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
	ServePort  uint16 // What port for webServer
	ListenPort uint16 // What port for pcap
	Path       string // What path does traas live at
	Device     string // What network interface is listened to
	Src        string // Ethernet address of the local network interface
	Dst        string // Ethernet address of the gateway network interface
	IPHeader   string // If client ips should be checked from e.g. an x-forwarded-for header
}

func getIP(header string, r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil
	}

	if header != "" {
		if h := r.Header.Get(header); h != "" {
			host = h
		}
	}
	ip := net.ParseIP(host)
	return ip
}

func (s *Server) StartHandler(w http.ResponseWriter, r *http.Request) {
	ip := getIP(s.config.IPHeader, r)
	if ip == nil {
		http.Redirect(w, r, "/"+s.config.Path+"/error", 302)
		return
	}
	log.Printf("Beginning trace for %v\n", ip)
	s.recorder.BeginTrace(ip)
	http.Redirect(w, r, "/"+s.config.Path+"/probe", 302)
}

func (s *Server) EndHandler(w http.ResponseWriter, r *http.Request) {
	ip := getIP(s.config.IPHeader, r)
	if ip == nil {
		http.Redirect(w, r, "/"+s.config.Path+"/error", 302)
		return
	}
	closeNotifier, ok := w.(http.CloseNotifier)
	if !ok {
		http.Redirect(w, r, "/"+s.config.Path+"/error", 302)
	}

	if t := s.recorder.GetTrace(ip); t != nil {
		// Wait an extra second for the trace to get filled in.
		select {
		case <-time.After(time.Second * 1):
			t = s.recorder.GetTrace(ip)
			s.recorder.EndTrace(ip)
			if b, err := json.Marshal(t); err == nil {
				w.Write(b)
				log.Printf("End Handler from %v: %s\n", ip, b)
			}
		case <-closeNotifier.CloseNotify():
			return
		}
	}
}

func (s *Server) ProbeHandler(w http.ResponseWriter, r *http.Request) {
	ip := getIP(s.config.IPHeader, r)
	if ip == nil {
		http.Redirect(w, r, "/"+s.config.Path+"/error", 302)
		return
	}

	closeNotifier, ok := w.(http.CloseNotifier)
	if !ok {
		http.Redirect(w, r, "/"+s.config.Path+"/error", 302)
	}
	select {
	case <-time.After(time.Second * 5):
		s.recorder.EndTrace(ip)
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
		"Connection: Close\r\n" +
		"Content-Length: 0\r\n\r\n"
	probe := &traas2.Probe{
		Payload: []byte(redirect),
		MinHop:  4,
		MaxHop:  32,
	}
	recorder, err := MakeRecorder(conf.Device, conf.Path, conf.ListenPort, probe)
	if err != nil {
		return nil
	}
	server := &Server{
		config:   conf,
		recorder: recorder,
	}

	addr := fmt.Sprintf("0.0.0.0:%d", conf.ServePort)
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
