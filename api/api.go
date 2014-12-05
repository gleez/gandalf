// Copyright 2014 gandalf authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package api

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/pat"
	"github.com/gleez/gandalf/config"
)

var (
	Router    *pat.Router
	listener  net.Listener
	addr	  string
	shutdown  bool
)

// Initialize sets up things for unit tests or the Start() method
func Initialize() {
	var err error
	Router = SetupRouter()
	addr, err = config.GetString("bind")

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse config: %v\n", err)
		os.Exit(1)
	}
}

// Start() the web server
func Start() {
	server := &http.Server{
		Addr:         addr,
		Handler:      nil,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	// We don't use ListenAndServe because it lacks a way to close the listener
	var err error
	listener, err = net.Listen("tcp", addr)
	if err != nil {
		log.Printf("HTTP API failed to start listener: %v", err)
		// TODO More graceful early-shutdown procedure
		return
	}

	log.Printf("API server listening on %v", addr)
	err = server.Serve(listener)
	if shutdown {
		log.Println("HTTP server shutting down on request")
	} else if err != nil {
		log.Printf("HTTP server failed: %v", err)
	}
}

func Stop() {
	log.Println("HTTP API shutdown requested")
	shutdown = true
	if listener != nil {
		listener.Close()
	} else {
		log.Println("HTTP listener was nil during shutdown")
	}
}

func parseRemoteAddr(r *http.Request) string {
	if realip := r.Header.Get("X-Real-IP"); realip != "" {
		return realip
	}

	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// X-Forwarded-For is potentially a list of addresses separated with ","
		parts := strings.Split(forwarded, ",")
		for i, p := range parts {
			parts[i] = strings.TrimSpace(p)
		}

		// TODO: should return first non-local address
		return parts[0]
		//return forwarded
	}

	return r.RemoteAddr
}

