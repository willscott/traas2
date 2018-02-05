package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/willscott/traas2"
)

type Server struct {
	sync.Mutex
	webServer http.Server
	config    Config
}

type Config struct {
	Port   int
	Path   string
	Device string
	Src    string
	Dst    string
}

func (s Server) Cleanup(remoteAddr string) {
	log.Printf("Closed connection from %s.", remoteAddr)
	if conn, ok := s.destinations[remoteAddr]; ok {
		conn.Close()
		delete(s.destinations, remoteAddr)
		if addrHost, _, err := net.SplitHostPort(remoteAddr); err == nil {
			if cc, ok := s.clientHosts[addrHost]; ok && cc == conn {
				delete(s.clientHosts, addrHost)

				// See if there's another connection from the same address to promote.
				for addr, otherConn := range s.destinations {
					if destAddr, _, err := net.SplitHostPort(addr); err == nil && destAddr == addrHost {
						s.clientHosts[destAddr] = otherConn
						break
					}
				}
			}
		}
	}
}

func SocketHandler(server *Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := server.upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		addrHost, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return
		}

		server.destinations[r.RemoteAddr] = c
		if _, ok := server.clientHosts[addrHost]; !ok {
			server.clientHosts[addrHost] = c
		}
		senderState := traas2.SENDERHELLO
		var sendStream chan<- []byte
		challenge := ""

		defer server.Cleanup(r.RemoteAddr)
		for {
			msgType, msg, err := c.ReadMessage()
			if err != nil {
				log.Println("read err:", err)
				break
			}
			if senderState == traas2.SENDERHELLO && msgType == websocket.TextMessage {
				hello := traas2.SenderHello{}
				err := json.Unmarshal(msg, &hello)
				if err != nil {
					log.Println("Hello err:", err)
					break
				}

				chal, err := server.Authorize(hello)
				if err != nil {
					log.Println("Authorize err:", err)
					resp := traas2.ServerMessage{
						Status: traas2.UNAUTHORIZED,
					}
					dat, _ := json.Marshal(resp)
					c.WriteMessage(websocket.TextMessage, dat)
					break
				}
				challenge = chal
				senderState = traas2.HELLORECEIVED
				continue
			} else if senderState == traas2.HELLORECEIVED && msgType == websocket.TextMessage {
				auth := sp3.SenderAuthorization{}
				err := json.Unmarshal(msg, &auth)
				if err != nil {
					log.Println("Auth err:", err)
					break
				}
				if challenge != "" && challenge == auth.Challenge {
					senderState = sp3.AUTHORIZED
					// Further messages should now be considered as binary packets.
					sendStream = CreateSpoofedStream(addrHost, auth.DestinationAddress)
					defer close(sendStream)

					resp := sp3.ServerMessage{
						Status: sp3.OKAY,
					}
					dat, _ := json.Marshal(resp)
					if err = c.WriteMessage(websocket.TextMessage, dat); err != nil {
						break
					}
					log.Printf("Authorized %v to send to %v.", r.RemoteAddr, auth.DestinationAddress)
				} else {
					log.Println("Bad Challenge from", r.RemoteAddr, " expected ", auth.Challenge, " but got ", challenge)
					resp := traas2.ServerMessage{
						Status: traas2.UNAUTHORIZED,
					}
					dat, _ := json.Marshal(resp)
					c.WriteMessage(websocket.TextMessage, dat)
					break
				}
				continue
			} else if senderState == traas2.AUTHORIZED && msgType == websocket.BinaryMessage {
				// Main forwarding loop.
				sendStream <- msg
				continue
			}
			// Else - unexpected message
			log.Println("Unexpected message", msg)
			break
		}
	})
}

func NewServer(conf Config) *Server {
	server := &Server{
		config:       conf,
		destinations: make(map[string]*websocket.Conn),
		clientHosts:  make(map[string]*websocket.Conn),
	}

	addr := fmt.Sprintf("0.0.0.0:%d", conf.Port)
	mux := http.NewServeMux()
	mux.Handle("/traas", SocketHandler(server))
	// By default serve a demo site.
	mux.Handle("/client/", http.StripPrefix("/client/", http.FileServer(http.Dir("../demo"))))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/client/", 301)
	}))

	webServer := &http.Server{Addr: addr, Handler: mux}

	server.webServer = *webServer
	return server
}

func (s *Server) Serve() error {
	return s.webServer.ListenAndServe()
}
