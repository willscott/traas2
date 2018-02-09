package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

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

func (s *Server) StartHandler(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if err != nil || ip == nil {
		http.Redirect(w, r, "/"+s.config.Path+"/error", 302)
		return
	}
	s.recorder.BeginTrace(ip)
	http.Redirect(w, r, "/"+s.config.Path+"/probe", 302)
}

func (s *Server) EndHandler(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if err != nil || ip == nil {
		http.Redirect(w, r, "/"+s.config.Path+"/error", 302)
		return
	}

	if t := s.recorder.GetTrace(ip); t != nil {
		s.recorder.EndTrace(ip)
		if b, err := json.Marshal(t); err == nil {
			w.Write(b)
			log.Printf("End Handler from %v: %s\n", ip, b)
		} else {
			http.Redirect(w, r, "/"+s.config.Path+"/error", 302)
		}
	}
}

func (s *Server) ProbeHandler(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if err != nil || ip == nil {
		http.Redirect(w, r, "/"+s.config.Path+"/error", 302)
		return
	}

	closeNotifier, ok := w.(http.CloseNotifier)
	if !ok {
		http.Redirect(w, r, "/"+s.config.Path+"/error", 302)
	}
	select {
	case <-time.After(time.Second * 5):
		http.Redirect(w, r, "/"+s.config.Path+"/error", 302)
	case <-closeNotifier.CloseNotify():
		return
	}
}

func (s *Server) ErrorHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Error."))
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
	mux.HandleFunc("/"+conf.Path+"/start", server.StartHandler)
	mux.HandleFunc("/"+conf.Path+"/probe", server.ProbeHandler)
	mux.HandleFunc("/"+conf.Path+"/done", server.EndHandler)
	mux.HandleFunc("/"+conf.Path+"/error", server.ErrorHandler)
	// By default serve a demo site.
	mux.Handle("/"+conf.Path+"/client/", http.StripPrefix("/"+conf.Path+"/client/", http.FileServer(http.Dir("../demo"))))
	//	mux.Handle("/", http.RedirectHandler("/"+conf.Path+"/client", 302))

	webServer := &http.Server{Addr: addr, Handler: mux}

	server.webServer = *webServer
	return server
}

func (s *Server) Serve() error {
	return s.webServer.ListenAndServe()
}
