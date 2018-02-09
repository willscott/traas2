package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/willscott/traas2"
)

// Server contains the state of the active server
type Server struct {
	sync.Mutex
	webServer http.Server
	recorder  *Recorder
	config    Config
}

// Config stores longterm state of how the server behaves
type Config struct {
	Port   int    // What port to listen on
	Path   string // What path does traas live at
	Device string // What network interface is listened to
	Src    string // Ethernet address of the local network interface
	Dst    string // Ethernet address of the gateway network interface
}

// Cleanup ends traces
func (s Server) Cleanup(remoteAddr net.IP) {
	s.recorder.EndTrace(remoteAddr)
}

func StartHandler(path string, server *Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.recorder.BeginTrace(net.ParseIP(r.RemoteAddr))
		http.Redirect(w, r, "/"+path+"/probe", 302)
	})
}

func EndHandler(path string, server *Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if t := server.recorder.GetTrace(net.ParseIP(r.RemoteAddr)); t != nil {
			server.recorder.EndTrace(net.ParseIP(r.RemoteAddr))
			if b, err := json.Marshal(t); err == nil {
				w.Write(b)
				//todo: log
			} else {
				http.Redirect(w, r, "/"+path+"/error", 302)
			}
		}
	})
}

func ErrorHandler(server *Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Error."))
	})
}

func NewServer(conf Config) *Server {
	redirect := "HTTP/1.1 302 Found\r\n" +
		"Location: ./done\r\n" +
		"Connection: Keep-Alive\r\n" +
		"Content-Length: 0\r\n\r\n"
	probe := &traas2.Probe{
		Payload: []byte(redirect),
		MinHop:  4,
		MaxHop:  32,
	}
	recorder, err := MakeRecorder(conf.Device, uint16(conf.Port), probe)
	if err != nil {
		return nil
	}
	server := &Server{
		config:   conf,
		recorder: recorder,
	}

	addr := fmt.Sprintf("0.0.0.0:%d", conf.Port)
	mux := http.NewServeMux()
	mux.Handle("/"+conf.Path+"/start", StartHandler(conf.Path, server))
	mux.Handle("/"+conf.Path+"/done", EndHandler(conf.Path, server))
	mux.Handle("/"+conf.Path+"/error", ErrorHandler(server))
	// By default serve a demo site.
	mux.Handle("/"+conf.Path+"/client/", http.StripPrefix("/"+conf.Path+"/client/", http.FileServer(http.Dir("../demo"))))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/"+conf.Path+"/client/", 301)
	}))

	webServer := &http.Server{Addr: addr, Handler: mux}

	server.webServer = *webServer
	return server
}

func (s *Server) Serve() error {
	return s.webServer.ListenAndServe()
}
