// Copyright 2014 gandalf authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sshd

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gleez/gandalf/config"
	"github.com/gleez/gandalf/db"
	"github.com/gleez/gandalf/repository"
	"github.com/gleez/gandalf/user"

	"golang.org/x/crypto/ssh"
	"gopkg.in/mgo.v2/bson"
)

// NewServer creates a new test SSH server that runs a shell
// command upon login (with the current directory set to user). It can
// be used to test remote SSH communication.
func NewServer(bind, uid string, opt ...func(*Server) error) *Server {
	// sem is an active clients channel used for counting clients
	maxClients := make(chan int, 100)

	s := &Server{Bind: bind, Uid: uid, waitgroup: new(sync.WaitGroup), sem: maxClients}

	for _, opt := range opt {
		if err := opt(s); err != nil {
			log.Printf("New SSH server failed to start: %v", err)
			return nil
		}
	}

	return s
}

// Server is an SSH server.
type Server struct {
	Bind string
	Uid  string

	SSH ssh.ServerConfig
	l   *net.TCPListener

	closedMu sync.Mutex
	closed   bool // whether l is closed

	waitgroup *sync.WaitGroup
	sem       chan int // currently active clients
}

// PrivateKey sets the server's private key and host key.
func PrivateKey(pemData []byte) func(*Server) error {
	return func(s *Server) error {
		privKey, err := ssh.ParseRawPrivateKey(pemData)
		if err != nil {
			return err
		}

		hostKey, err := ssh.NewSignerFromKey(privKey)
		if err != nil {
			return err
		}
		s.SSH.AddHostKey(hostKey)

		s.SSH.PublicKeyCallback = func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			log.Printf("Authenticating user %s from IP %s", c.User(), host)
			if c.User() == s.Uid {
				name, err := getUserFromKey(string(ssh.MarshalAuthorizedKey(key)))
				if err != nil {
					log.Printf("Auth failed from IP %s with error %v", host, err)
					return nil, errors.New("public key rejected")
				}
				return &ssh.Permissions{Extensions: map[string]string{"key-id": name, "ip": host}}, nil
			} else {
				return nil, errors.New("Invalid user")
			}
		}

		return nil
	}
}

// Start starts the server in a goroutine.
func (s *Server) Start() {
	addr, err := net.ResolveTCPAddr("tcp", s.Bind)
	if err != nil {
		log.Printf("SSH server failed to resolve addr: %v", err)
		return
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		log.Printf("SSH server failed to start listener: %v", err)
		return
	}
	s.l = l

	// Start listening for SMTP connections
	log.Printf("SSH server listening on %v", addr)

	// Handle incoming connections
	for {
		// SSH connections just house multiplexed connections
		conn, err := s.l.Accept()
		if err != nil {
			s.closedMu.Lock()
			if s.closed {
				s.closedMu.Unlock()
				return
			}
			s.closedMu.Unlock()
			log.Printf("SSH server failed to accept incoming connection: %v", err)
			continue
		}

		s.waitgroup.Add(1)
		log.Printf("There are now %s serving goroutines", strconv.Itoa(runtime.NumGoroutine()))
		s.sem <- 1 // Wait for active queue to drain.
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer func() {
		s.closeConn(conn)
		s.waitgroup.Done()
	}()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, &s.SSH)
	if err != nil {
		log.Println("SSH server failed to handshake:", err)
		return
	}

	// The incoming Request channel must be serviced.
	go ssh.DiscardRequests(reqs)
	log.Printf("SSH Connection from %v, starting session", sshConn.Permissions.Extensions["ip"])

	for ch := range chans {
		if ch.ChannelType() != "session" {
			ch.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		go s.handleChannel(sshConn, ch)
	}
}

func (s *Server) handleChannel(conn *ssh.ServerConn, newChan ssh.NewChannel) {
	ch, reqs, err := newChan.Accept()
	if err != nil {
		log.Println("SSH server newChan.Accept failed:", err)
		return
	}
	defer ch.Close()

	for req := range reqs {
		switch req.Type {
		case "exec":
			payload := string(req.Payload[4:])
			//log.Printf("Request: %s %t %s", req.Type, req.WantReply, payload)
			fail := func(at string, err error) {
				log.Printf("%s failed: %s", at, err)
				ch.Stderr().Write([]byte("Internal error.\n"))
			}

			if req.WantReply {
				req.Reply(true, nil)
			}

			c, err := canExecuteCmd(payload, conn.Permissions.Extensions["key-id"])
			if err != nil {
				fail("canExecuteCmd", err)
				return
			}

			log.Print("Executing " + strings.Join(c, " "))
			cmd := exec.Command(c[0], c[1:]...)
			done, err := attachCmd(cmd, ch, ch.Stderr(), ch)
			if err != nil {
				fail("attachCmd", err)
				return
			}
			if err := cmd.Start(); err != nil {
				fail("cmd.Start", err)
				return
			}
			done.Wait()
			status, err := exitStatus(cmd.Wait())
			if err != nil {
				fail("exitStatus", err)
				return
			}
			if _, err := ch.SendRequest("exit-status", false, ssh.Marshal(&status)); err != nil {
				fail("sendExit", err)
			}
			return
		case "shell":
			ch.Close() //shell is not allowed
		case "env":
			if req.WantReply {
				req.Reply(true, nil)
			}
		}
	}
}

func (s *Server) closeConn(conn net.Conn) {
	time.Sleep(200 * time.Millisecond)
	conn.Close()
	<-s.sem // Done; enable next client to run.
}

func (s *Server) Stop() error {
	s.closedMu.Lock()
	s.closed = true
	s.closedMu.Unlock()
	log.Print("SSH server shutdown requested, connections will be drained")
	return s.l.Close()
}

// Drain causes the caller to block until all active SSH connections have finished
func (s *Server) Drain() {
	s.waitgroup.Wait()
	log.Print("SSH server connections drained")
}

func getUserFromKey(key string) (string, error) {
	var k user.Key
	conn, err := db.Conn()
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if err := conn.Key().Find(bson.M{"body": key}).One(&k); err != nil {
		return "", errors.New("Error obtaining key. GitShell database is probably in an inconsistent state.")
	}

	return k.UserName, nil
}

func canExecuteCmd(sshcmd string, keyId string) ([]string, error) {
	a, r, err := parseGitCommand(sshcmd)
	if err != nil {
		return []string{}, err
	}

	var u user.User
	conn, err := db.Conn()
	if err != nil {
		return []string{}, err
	}
	defer conn.Close()
	if err := conn.User().Find(bson.M{"_id": keyId}).One(&u); err != nil {
		return []string{}, errors.New("Error obtaining user.")
	}

	repo, err := requestedRepository(r)
	if err != nil {
		return []string{}, err
	}

	ok := false
	//var errMsg string
	if a == "git-receive-pack" && hasWritePermission(&u, &repo) {
		ok = true
	} else if a == "git-upload-pack" && hasReadPermission(&u, &repo) {
		ok = true
	}

	if ok {
		// split into a function (maybe executeCmd)
		c, err := formatCommand(sshcmd)
		if err != nil {
			return []string{}, err
		}

		return c, nil
	}

	return []string{}, errors.New("Permission denied.")
}

func attachCmd(cmd *exec.Cmd, stdout, stderr io.Writer, stdin io.Reader) (*sync.WaitGroup, error) {
	var wg sync.WaitGroup
	wg.Add(2)

	stdinIn, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdoutOut, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderrOut, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	go func() {
		io.Copy(stdinIn, stdin)
		stdinIn.Close()
	}()
	go func() {
		io.Copy(stdout, stdoutOut)
		wg.Done()
	}()
	go func() {
		io.Copy(stderr, stderrOut)
		wg.Done()
	}()

	return &wg, nil
}

type exitStatusMsg struct {
	Status uint32
}

func exitStatus(err error) (exitStatusMsg, error) {
	if err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			// There is no platform independent way to retrieve
			// the exit code, but the following will work on Unix
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				return exitStatusMsg{uint32(status.ExitStatus())}, nil
			}
		}
		return exitStatusMsg{0}, err
	}
	return exitStatusMsg{0}, nil
}

// Get the repository name requested in SSH_ORIGINAL_COMMAND and retrieves
// the related document on the database and returns it.
// This function does two distinct things, parses the SSH_ORIGINAL_COMMAND and
// returns a "validation" error if it doesn't matches the expected format
// and gets the repository from the database based on the info
// obtained by the SSH_ORIGINAL_COMMAND parse.
func requestedRepository(repoName string) (repository.Repository, error) {
	/*	_, repoName, err := parseGitCommand(sshcmd)
		if err != nil {
			return repository.Repository{}, err
		}*/
	var repo repository.Repository
	conn, err := db.Conn()
	if err != nil {
		return repository.Repository{}, err
	}
	defer conn.Close()
	if err := conn.Repository().Find(bson.M{"_id": repoName}).One(&repo); err != nil {
		return repository.Repository{}, errors.New("Repository not found")
	}
	return repo, nil
}

func hasWritePermission(u *user.User, r *repository.Repository) (allowed bool) {
	for _, userName := range r.Users {
		if u.Name == userName {
			return true
		}
	}
	return false
}

func hasReadPermission(u *user.User, r *repository.Repository) (allowed bool) {
	if r.IsPublic {
		return true
	}
	for _, userName := range r.Users {
		if u.Name == userName {
			return true
		}
	}
	for _, userName := range r.ReadOnlyUsers {
		if u.Name == userName {
			return true
		}
	}
	return false
}

// Checks whether a command is a valid git command
// The following format is allowed:
// (git-[a-z-]+) '/?([\w-+@][\w-+.@]*/)?([\w-]+)\.git'
func parseGitCommand(sshcmd string) (command, name string, err error) {
	// The following regex validates the git command, which is in the form:
	//    <git-command> [<namespace>/]<name>
	// with namespace being optional. If a namespace is used, we validate it
	// according to the following:
	//  - a namespace is optional
	//  - a namespace contains only alphanumerics, underlines, @´s, -´s, +´s
	//    and periods but it does not start with a period (.)
	//  - one and exactly one slash (/) separates namespace and the actual name
	r, err := regexp.Compile(`(git-[a-z-]+) '/?([\w-+@][\w-+.@]*/)?([\w-]+)\.git'`)
	// r, err := regexp.Compile(`git-(upload|receive)-pack '/?([\w-+@][\w-+.@]*/)?([\w-]+)\.git'`)
	if err != nil {
		panic(err)
	}

	m := r.FindStringSubmatch(sshcmd)
	if len(m) != 4 {
		return "", "", errors.New("You've tried to execute some weird command, I'm deliberately denying you to do that, get over it.")
	}
	return m[1], m[2] + m[3], nil
}

func formatCommand(sshcmd string) ([]string, error) {
	p, err := config.GetString("git:bare:location")
	if err != nil {
		log.Print(err.Error())
		return []string{}, err
	}
	_, repoName, err := parseGitCommand(sshcmd)
	if err != nil {
		log.Print(err.Error())
		return []string{}, err
	}

	repoName += ".git"
	cmdList := strings.Split(sshcmd, " ")
	if len(cmdList) != 2 {
		log.Print("Malformed git command")
		return []string{}, fmt.Errorf("Malformed git command")
	}
	cmdList[1] = path.Join(p, repoName)
	return cmdList, nil
}
