package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
)

type Server struct {
	sync.Mutex
	webServer http.Server
	recorder  *Recorder
	config    Config
}

type Config struct {
	Port   int
	Path   string
	Device string
	Src    string
	Dst    string
}

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

func NewServer(conf Config) *Server {
	server := &Server{
		config: conf,
	}

	addr := fmt.Sprintf("0.0.0.0:%d", conf.Port)
	mux := http.NewServeMux()
	mux.Handle("/"+conf.Path+"/start", StartHandler(conf.Path, server))
	mux.Handle("/"+conf.Path+"/done", EndHandler(conf.Path, server))
	// By default serve a demo site.
	mux.Handle("/"+conf.Path+"/client/", http.StripPrefix("/client/", http.FileServer(http.Dir("../demo"))))
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
