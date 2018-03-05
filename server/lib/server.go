package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/willscott/traas2"
)

// Server contains the state of the active server
type Server struct {
	sync.Mutex
	webServer http.Server
	recorder  *Recorder
	probe     *traas2.Probe
	config    Config
}

// Config stores longterm state of how the server behaves
type Config struct {
	ServePort  uint16      // What port for webServer
	ListenPort uint16      // What port for pcap
	Path       string      // What web path does traas live at
	Root       string      // where is the go code (and static files) for traas
	Device     string      // What network interface is listened to
	Dst        string      // Ethernet address of the gateway network interface
	IPHeader   string      // If client ips should be checked from e.g. an x-forwarded-for header
	TraceFile  string      // file to log traces.
	TraceLog   *log.Logger `json:"-"`
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

// StartHandler triggers the start of traces.
func (s *Server) StartHandler(w http.ResponseWriter, r *http.Request) {
	ip := getIP(s.config.IPHeader, r)
	if ip == nil {
		http.Redirect(w, r, "/"+s.config.Path+"/error", 302)
		return
	}
	log.Printf("Beginning trace for %v\n", ip)
	s.recorder.BeginTrace(ip)
	http.Redirect(w, r, s.config.Path+"/probe", 302)
}

// EndHandler finishes traces
func (s *Server) EndHandler(w http.ResponseWriter, r *http.Request) {
	ip := getIP(s.config.IPHeader, r)
	if ip == nil {
		http.Redirect(w, r, s.config.Path+"/error", 302)
		return
	}
	closeNotifier, ok := w.(http.CloseNotifier)
	if !ok {
		http.Redirect(w, r, s.config.Path+"/error", 302)
	}

	if t := s.recorder.GetTrace(ip); t != nil {
		// Wait an extra second for the trace to get filled in.
		delayTime := time.Millisecond * 100 * time.Duration(s.probe.MaxHop-s.probe.MinHop+1)
		select {
		case <-time.After(delayTime):
			t = s.recorder.GetTrace(ip)
			if t == nil {
				return
			}
			s.recorder.EndTrace(ip)
			//sort and create route from recorded hops.
			hops := make(traas2.Route, t.Recorded)
			for i := uint16(0); i < t.Recorded; i++ {
				hops[i] = t.Hops[i]
			}
			sort.Sort(hops)
			t.Route = hops

			if b, err := json.Marshal(t); err == nil {
				w.Write(b)
				s.config.TraceLog.Println(b)
			}
		case <-closeNotifier.CloseNotify():
			return
		}
	}
}

// ProbeHandler waits for probes to be received, then prints state.
func (s *Server) ProbeHandler(w http.ResponseWriter, r *http.Request) {
	ip := getIP(s.config.IPHeader, r)
	if ip == nil {
		http.Redirect(w, r, s.config.Path+"/error", 302)
		return
	}

	closeNotifier, ok := w.(http.CloseNotifier)
	if !ok {
		http.Redirect(w, r, s.config.Path+"/error", 302)
	}
	select {
	case <-time.After(time.Second * 10):
		s.recorder.EndTrace(ip)
		http.Redirect(w, r, s.config.Path+"/error", 302)
	case <-closeNotifier.CloseNotify():
		return
	}
}

// ErrorHandler prints a standard message when errors are encountered
func (s *Server) ErrorHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("\"Error.\""))
}

// NewServer creates an HTTP server with a given config.
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
		probe:    probe,
		recorder: recorder,
	}

	addr := fmt.Sprintf("0.0.0.0:%d", conf.ServePort)
	mux := http.NewServeMux()
	mux.HandleFunc(conf.Path+"/start", server.StartHandler)
	mux.HandleFunc(conf.Path+"/probe", server.ProbeHandler)
	mux.HandleFunc(conf.Path+"/done", server.EndHandler)
	mux.HandleFunc(conf.Path+"/error", server.ErrorHandler)
	// By default serve a demo site.
	mux.Handle(conf.Path+"/client/", http.StripPrefix(conf.Path+"/client/", http.FileServer(http.Dir(conf.Root+"/demo"))))

	server.webServer = http.Server{Addr: addr, Handler: mux}

	return server
}

// Serve begins listening for web connections on the port specified in config
func (s *Server) Serve() error {
	return s.webServer.ListenAndServe()
}
