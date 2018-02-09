package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/willscott/traas2/server/lib"
)

var (
	configFile = flag.String("config", "", "File with server configuration")
	initFlag   = flag.Bool("init", false, "if true, setup new configuration")
	port       = flag.Int("port", 8080, "TCP port for connections")
	path       = flag.String("path", "traas", "prefix for web requests")
	device     = flag.String("device", "eth0", "inet device for pcap to use")
	srcMAC     = flag.String("srcMAC", "000000000000", "Ethernet SRC for sending")
	dstMAC     = flag.String("dstMAC", "000000000000", "Ethernet DST for sending")
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
			Port:   *port,
			Path:   *path,
			Device: *device,
			Src:    *srcMAC,
			Dst:    *dstMAC,
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

	if config.Port == 0 {
		config.Port = 8080
	}
	if config.Device == "" {
		config.Device = "eth0"
	}
	if config.Path == "" {
		config.Path = "traas"
	}

	fmt.Printf("Using config %+v \n", config)
	if err = server.SetupSpoofingSockets(config); err != nil {
		log.Fatalf("Could not initialize sockets: %s", err)
		return
	}
	s := server.NewServer(config)
	s.Serve()
}
