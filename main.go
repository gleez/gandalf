// Copyright 2014 gandalf authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/gleez/gandalf/api"
	"github.com/gleez/gandalf/config"
	"github.com/gleez/gandalf/sshd"
)

const version = "0.5.1"

var (
	// Build info, populated during linking by goxc
	VERSION    = "0.5.1"
	BUILD_DATE = "undefined"

	// Command line flags
	help       = flag.Bool("help", false, "Displays this help")
	pidfile    = flag.String("pidfile", "none", "Write our PID into the specified file")
	logfile    = flag.String("logfile", "stderr", "Write out log into the specified file")
	configFile = flag.String("config", "/etc/gandalf.conf", "Path to the configuration file")
	gVersion   = flag.Bool("version", false, "Print version and exit")

	// startTime is used to calculate uptime of gandalf
	startTime = time.Now()

	// The file we send log output to, will be nil for stderr or stdout
	logf *os.File

	// Server instances
	sshServer *sshd.Server
)

func main() {
	flag.Parse()
	runtime.GOMAXPROCS(runtime.NumCPU())

	if *gVersion {
		fmt.Printf("gandalf version %s\n", version)
		return
	}

	err := config.ReadAndWatchConfigFile(*configFile)
	if err != nil {
		msg := `Could not find gandalf config file. Searched on %s.
For an example conf check gandalf/etc/gandalf.conf file.\n %s`
		log.Panicf(msg, *configFile, err)
	}

	sshbind, err := config.GetString("sshbind")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse sshbind: %v\n", err)
		os.Exit(1)
	}

	privateBytes, err := ioutil.ReadFile("etc/id_rsa")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load private key: %v\n", err)
		os.Exit(1)
	}

	uid, err := config.GetString("uid")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse uid: %v\n", err)
		os.Exit(1)
	}

	// Setup signal handler
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGTERM)
	go signalProcessor(sigChan)

	if *logfile != "stderr" {
		// stderr is the go logging default
		if *logfile == "stdout" {
			// set to stdout
			log.SetOutput(os.Stdout)
		} else {
			err := openLogFile()
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v", err)
				os.Exit(1)
			}
			defer closeLogFile()

			// close std* streams
			os.Stdout.Close()
			os.Stderr.Close() // Warning: this will hide panic() output
			os.Stdin.Close()
			os.Stdout = logf
			os.Stderr = logf
		}
	}

	log.Printf("SSH %v (%v) starting... with pid %v", VERSION, BUILD_DATE, os.Getpid())

	// Write pidfile if requested
	// TODO: Probably supposed to remove pidfile during shutdown
	if *pidfile != "none" {
		pidf, err := os.Create(*pidfile)
		if err != nil {
			log.Printf("Failed to create %v: %v", *pidfile, err)
			os.Exit(1)
		}
		defer pidf.Close()
		fmt.Fprintf(pidf, "%v\n", os.Getpid())
	}

	// Start HTTP API server
	api.Initialize()
	go api.Start()

	// Starts a SSH server listens on given port.
	sshServer = sshd.NewServer(sshbind, uid, sshd.PrivateKey(privateBytes))
	sshServer.Start()

	// Wait for active connections to finish
	sshServer.Drain()
}

// openLogFile creates or appends to the logfile passed on commandline
func openLogFile() error {
	// use specified log file
	var err error
	logf, err = os.OpenFile(*logfile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		return fmt.Errorf("Failed to create %v: %v\n", *logfile, err)
	}
	log.SetOutput(logf)
	log.Println("Opened new logfile")
	return nil
}

// closeLogFile closes the current logfile
func closeLogFile() error {
	log.Println("Closing logfile")
	return logf.Close()
}

// signalProcessor is a goroutine that handles OS signals
func signalProcessor(c <-chan os.Signal) {
	for {
		sig := <-c
		switch sig {
		case syscall.SIGHUP:
			// Rotate logs if configured
			if logf != nil {
				log.Println("Recieved SIGHUP, cycling logfile")
				closeLogFile()
				openLogFile()
			} else {
				log.Println("Ignoring SIGHUP, logfile not configured")
			}
		case syscall.SIGTERM:
			// Initiate shutdown
			log.Println("Received SIGTERM, shutting down")
			go timedExit()
			api.Stop()
			if sshServer != nil {
				sshServer.Stop()
			} else {
				log.Println("sshServer was nil during shutdown")
			}
		}
	}
}

// timedExit is called as a goroutine during shutdown, it will force an exit after 15 seconds
func timedExit() {
	time.Sleep(15 * time.Second)
	log.Println("Smtpd clean shutdown timed out, forcing exit")
	os.Exit(0)
}
