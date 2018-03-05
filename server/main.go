package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/willscott/traas2/server/lib"
)

var (
	configFile   = flag.String("config", "", "File with server configuration")
	initFlag     = flag.Bool("init", false, "if true, setup new configuration")
	servePort    = flag.Int("port", 8080, "TCP port for web socket")
	listenPort   = flag.Int("lport", 8080, "TCP port for incoming connection listening")
	path         = flag.String("path", "", "prefix for web requests")
	root         = flag.String("root", "..", "FS directory of traas for serving static files")
	device       = flag.String("device", "eth0", "inet device for pcap to use")
	dstMAC       = flag.String("dstMAC", "000000000000", "Ethernet DST for sending")
	originHeader = flag.String("originHeader", "", "Client IPs are forwarded in a http header")
	logFile      = flag.String("log", "", "where to log completed traces. If not set, will log to stdout")
)

func main() {
	flag.Parse()

	if len(*configFile) == 0 {
		home := os.Getenv("HOME")
		if len(home) == 0 {
			fmt.Fprintf(os.Stderr, "$HOME not set. Please either export $HOME or use an explict --config location.\n")
			os.Exit(1)
		}
		configDir := filepath.Join(home, ".config")
		if *initFlag {
			os.Mkdir(configDir, 0700)
		}
		*configFile = filepath.Join(configDir, "traas.json")
	}
	if *initFlag {
		configHandle, err := os.OpenFile(*configFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Fatalf("Failed to create config file: %s", err)
			return
		}
		defaultConfig, _ := json.Marshal(server.Config{
			ServePort:  uint16(*servePort),
			ListenPort: uint16(*listenPort),
			Path:       *path,
			Root:       *root,
			Device:     *device,
			Dst:        *dstMAC,
			TraceFile:  *logFile,
		})
		if _, err := configHandle.Write(defaultConfig); err != nil {
			log.Fatalf("Failed to write default config: %s", err)
			return
		}
		configHandle.Close()
	}

	configString, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("Couldn't read config file: %s", err)
		return
	}

	var config server.Config
	if err = json.Unmarshal(configString, &config); err != nil {
		log.Fatalf("Couldn't parse config: %s", err)
		return
	}

	ll := log.New(os.Stderr, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	if config.TraceFile != "" {
		outfile, logerr := os.OpenFile(config.TraceFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if logerr != nil {
			panic("could not open log file: " + logerr.Error())
		}
		ll = log.New(outfile, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	}
	if *logFile != "" {
		outfile, logerr := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if logerr != nil {
			panic("could not open log file: " + logerr.Error())
		}
		ll = log.New(outfile, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	}
	config.TraceLog = ll

	if config.ServePort == 0 {
		config.ServePort = 8080
	}
	if config.ListenPort == 0 {
		config.ListenPort = 8080
	}
	if config.Device == "" {
		if iface, iferr := net.InterfaceByIndex(0); iferr == nil {
			config.Device = iface.Name
		} else {
			config.Device = "eth0"
		}
	}

	fmt.Printf("Using config %+v \n", config)
	if err = server.SetupSpoofingSockets(config); err != nil {
		log.Fatalf("Could not initialize sockets: %s", err)
		return
	}
	s := server.NewServer(config)
	s.Serve()
}
