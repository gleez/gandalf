// Copyright 2014 gandalf authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"log/syslog"
	"os"
	"path"
	"testing"

	"github.com/tsuru/commandmocker"
	"github.com/gleez/gandalf/config"
	"github.com/gleez/gandalf/db"
	"github.com/gleez/gandalf/repository"
	"github.com/gleez/gandalf/user"
	"gopkg.in/mgo.v2/bson"
	"launchpad.net/gocheck"
)

func Test(t *testing.T) { gocheck.TestingT(t) }

type S struct {
	user *user.User
	repo *repository.Repository
}

var _ = gocheck.Suite(&S{})

func (s *S) SetUpSuite(c *gocheck.C) {
	var err error
	log, err = syslog.New(syslog.LOG_INFO, "gandalf-listener")
	c.Check(err, gocheck.IsNil)
	err = config.ReadConfigFile("../etc/gandalf.conf")
	c.Check(err, gocheck.IsNil)
	config.Set("database:name", "gandalf_bin_tests")
	s.user, err = user.New("testuser", map[string]string{})
	c.Check(err, gocheck.IsNil)
	// does not uses repository.New to avoid creation of bare git repo
	s.repo = &repository.Repository{Name: "myapp", Users: []string{s.user.Name}}
	conn, err := db.Conn()
	c.Assert(err, gocheck.IsNil)
	defer conn.Close()
	err = conn.Repository().Insert(s.repo)
	c.Check(err, gocheck.IsNil)
}

func (s *S) TearDownSuite(c *gocheck.C) {
	conn, err := db.Conn()
	c.Assert(err, gocheck.IsNil)
	defer conn.Close()
	conn.User().Database.DropDatabase()
}

func (s *S) TestHasWritePermissionSholdReturnTrueWhenUserCanWriteInRepo(c *gocheck.C) {
	allowed := hasWritePermission(s.user, s.repo)
	c.Assert(allowed, gocheck.Equals, true)
}

func (s *S) TestHasWritePermissionShouldReturnFalseWhenUserCannotWriteinRepo(c *gocheck.C) {
	r := &repository.Repository{Name: "myotherapp"}
	conn, err := db.Conn()
	c.Assert(err, gocheck.IsNil)
	defer conn.Close()
	conn.Repository().Insert(&r)
	defer conn.Repository().Remove(bson.M{"_id": r.Name})
	allowed := hasWritePermission(s.user, r)
	c.Assert(allowed, gocheck.Equals, false)
}

func (s *S) TestHasReadPermissionShouldReturnTrueWhenRepositoryIsPublic(c *gocheck.C) {
	r := &repository.Repository{Name: "myotherapp", IsPublic: true}
	conn, err := db.Conn()
	c.Assert(err, gocheck.IsNil)
	defer conn.Close()
	conn.Repository().Insert(&r)
	defer conn.Repository().Remove(bson.M{"_id": r.Name})
	allowed := hasReadPermission(s.user, r)
	c.Assert(allowed, gocheck.Equals, true)
}

func (s *S) TestHasReadPermissionShouldReturnTrueWhenRepositoryIsNotPublicAndUserHasPermissionToRead(c *gocheck.C) {
	user, err := user.New("readonlyuser", map[string]string{})
	c.Check(err, gocheck.IsNil)
	repo := &repository.Repository{
		Name:          "otherapp",
		Users:         []string{s.user.Name},
		ReadOnlyUsers: []string{user.Name},
	}
	allowed := hasReadPermission(user, repo)
	c.Assert(allowed, gocheck.Equals, true)
}

func (s *S) TestHasReadPermissionShouldReturnTrueWhenRepositoryIsNotPublicAndUserHasPermissionToReadAndWrite(c *gocheck.C) {
	allowed := hasReadPermission(s.user, s.repo)
	c.Assert(allowed, gocheck.Equals, true)
}

func (s *S) TestHasReadPermissionShouldReturnFalseWhenUserDoesNotHavePermissionToReadWriteAndRepoIsNotPublic(c *gocheck.C) {
	r := &repository.Repository{Name: "myotherapp", IsPublic: false}
	conn, err := db.Conn()
	c.Assert(err, gocheck.IsNil)
	defer conn.Close()
	conn.Repository().Insert(&r)
	defer conn.Repository().Remove(bson.M{"_id": r.Name})
	allowed := hasReadPermission(s.user, r)
	c.Assert(allowed, gocheck.Equals, false)
}

func (s *S) TestActionShouldReturnTheCommandBeingExecutedBySSH_ORIGINAL_COMMANDEnvVar(c *gocheck.C) {
	os.Setenv("SSH_ORIGINAL_COMMAND", "test-cmd")
	defer os.Setenv("SSH_ORIGINAL_COMMAND", "")
	cmd := action()
	c.Assert(cmd, gocheck.Equals, "test-cmd")
}

func (s *S) TestActionShouldReturnEmptyWhenEnvVarIsNotSet(c *gocheck.C) {
	cmd := action()
	c.Assert(cmd, gocheck.Equals, "")
}

func (s *S) TestRequestedRepositoryShouldGetArgumentInSSH_ORIGINAL_COMMANDAndRetrieveTheEquivalentDatabaseRepository(c *gocheck.C) {
	r := repository.Repository{Name: "foo"}
	conn, err := db.Conn()
	c.Assert(err, gocheck.IsNil)
	defer conn.Close()
	err = conn.Repository().Insert(&r)
	c.Assert(err, gocheck.IsNil)
	defer conn.Repository().Remove(bson.M{"_id": r.Name})
	os.Setenv("SSH_ORIGINAL_COMMAND", "git-receive-pack 'foo.git'")
	defer os.Setenv("SSH_ORIGINAL_COMMAND", "")
	repo, err := requestedRepository()
	c.Assert(err, gocheck.IsNil)
	c.Assert(repo.Name, gocheck.Equals, r.Name)
}

func (s *S) TestRequestedRepositoryShouldDeduceCorrectlyRepositoryNameWithDash(c *gocheck.C) {
	r := repository.Repository{Name: "foo-bar"}
	conn, err := db.Conn()
	c.Assert(err, gocheck.IsNil)
	defer conn.Close()
	err = conn.Repository().Insert(&r)
	c.Assert(err, gocheck.IsNil)
	defer conn.Repository().Remove(bson.M{"_id": r.Name})
	os.Setenv("SSH_ORIGINAL_COMMAND", "git-receive-pack 'foo-bar.git'")
	defer os.Setenv("SSH_ORIGINAL_COMMAND", "")
	repo, err := requestedRepository()
	c.Assert(err, gocheck.IsNil)
	c.Assert(repo.Name, gocheck.Equals, r.Name)
}

func (s *S) TestRequestedRepositoryShouldReturnErrorWhenCommandDoesNotPassesWhatIsExpected(c *gocheck.C) {
	os.Setenv("SSH_ORIGINAL_COMMAND", "rm -rf /")
	defer os.Setenv("SSH_ORIGINAL_COMMAND", "")
	_, err := requestedRepository()
	c.Assert(err, gocheck.ErrorMatches, "^You've tried to execute some weird command, I'm deliberately denying you to do that, get over it.$")
}

func (s *S) TestRequestedRepositoryShouldReturnErrorWhenThereIsNoCommandPassedToSSH_ORIGINAL_COMMAND(c *gocheck.C) {
	_, err := requestedRepository()
	c.Assert(err, gocheck.ErrorMatches, "^You've tried to execute some weird command, I'm deliberately denying you to do that, get over it.$")
}

func (s *S) TestRequestedRepositoryShouldReturnFormatedErrorWhenRepositoryDoesNotExist(c *gocheck.C) {
	os.Setenv("SSH_ORIGINAL_COMMAND", "git-receive-pack 'inexistent-repo.git'")
	defer os.Setenv("SSH_ORIGINAL_COMMAND", "")
	_, err := requestedRepository()
	c.Assert(err, gocheck.ErrorMatches, "^Repository not found$")
}

func (s *S) TestRequestedRepositoryShouldReturnEmptyRepositoryStructOnError(c *gocheck.C) {
	repo, err := requestedRepository()
	c.Assert(err, gocheck.NotNil)
	c.Assert(repo.Name, gocheck.Equals, "")
}

func (s *S) TestParseGitCommand(c *gocheck.C) {
	os.Setenv("SSH_ORIGINAL_COMMAND", "git-receive-pack 'foobar.git'")
	defer os.Setenv("SSH_ORIGINAL_COMMAND", "")
	_, name, err := parseGitCommand()
	c.Assert(err, gocheck.IsNil)
	c.Assert(name, gocheck.Equals, "foobar")
}

func (s *S) TestParseGitCommandWithSlash(c *gocheck.C) {
	os.Setenv("SSH_ORIGINAL_COMMAND", "git-receive-pack '/foobar.git'")
	defer os.Setenv("SSH_ORIGINAL_COMMAND", "")
	_, name, err := parseGitCommand()
	c.Assert(err, gocheck.IsNil)
	c.Assert(name, gocheck.Equals, "foobar")
}

func (s *S) TestParseGitCommandShouldReturnErrorWhenTheresNoMatch(c *gocheck.C) {
	defer os.Setenv("SSH_ORIGINAL_COMMAND", "")
	os.Setenv("SSH_ORIGINAL_COMMAND", "git-receive-pack foobar")
	_, name, err := parseGitCommand()
	c.Assert(err, gocheck.ErrorMatches, "You've tried to execute some weird command, I'm deliberately denying you to do that, get over it.")
	c.Assert(name, gocheck.Equals, "")
	os.Setenv("SSH_ORIGINAL_COMMAND", "git-receive-pack ../foobar")
	_, name, err = parseGitCommand()
	c.Assert(err, gocheck.ErrorMatches, "You've tried to execute some weird command, I'm deliberately denying you to do that, get over it.")
	c.Assert(name, gocheck.Equals, "")
	os.Setenv("SSH_ORIGINAL_COMMAND", "git-receive-pack /etc")
	_, name, err = parseGitCommand()
	c.Assert(err, gocheck.ErrorMatches, "You've tried to execute some weird command, I'm deliberately denying you to do that, get over it.")
	c.Assert(name, gocheck.Equals, "")
}

func (s *S) TestParseGitCommandReturnsErrorWhenSSH_ORIGINAL_COMMANDIsNotAGitCommand(c *gocheck.C) {
	os.Setenv("SSH_ORIGINAL_COMMAND", "rm -rf /")
	defer os.Setenv("SSH_ORIGINAL_COMMAND", "")
	_, _, err := parseGitCommand()
	c.Assert(err, gocheck.ErrorMatches, "^You've tried to execute some weird command, I'm deliberately denying you to do that, get over it.$")
}

func (s *S) TestParseGitCommandDoNotReturnsErrorWhenSSH_ORIGINAL_COMMANDIsAValidGitCommand(c *gocheck.C) {
	os.Setenv("SSH_ORIGINAL_COMMAND", "git-receive-pack 'my-repo.git'")
	defer os.Setenv("SSH_ORIGINAL_COMMAND", "")
	_, _, err := parseGitCommand()
	c.Assert(err, gocheck.IsNil)
}

func (s *S) TestParseGitCommandDoNotReturnsErrorWhenSSH_ORIGINAL_COMMANDIsAValidGitCommandWithDashInName(c *gocheck.C) {
	os.Setenv("SSH_ORIGINAL_COMMAND", "git-receive-pack '/my-repo.git'")
	defer os.Setenv("SSH_ORIGINAL_COMMAND", "")
	_, _, err := parseGitCommand()
	c.Assert(err, gocheck.IsNil)
}

func (s *S) TestExecuteActionShouldExecuteGitReceivePackWhenUserHasWritePermission(c *gocheck.C) {
	dir, err := commandmocker.Add("git-receive-pack", "$*")
	c.Check(err, gocheck.IsNil)
	defer commandmocker.Remove(dir)
	os.Args = []string{"gandalf", s.user.Name}
	os.Setenv("SSH_ORIGINAL_COMMAND", "git-receive-pack 'myapp.git'")
	defer func() {
		os.Args = []string{}
		os.Setenv("SSH_ORIGINAL_COMMAND", "")
	}()
	stdout := &bytes.Buffer{}
	executeAction(hasWritePermission, "You don't have access to write in this repository.", stdout)
	c.Assert(commandmocker.Ran(dir), gocheck.Equals, true)
	p, err := config.GetString("git:bare:location")
	c.Assert(err, gocheck.IsNil)
	expected := path.Join(p, "myapp.git")
	c.Assert(stdout.String(), gocheck.Equals, expected)
}

func (s *S) TestExecuteActionShouldNotCallSSH_ORIGINAL_COMMANDWhenUserDoesNotExist(c *gocheck.C) {
	dir, err := commandmocker.Add("git-receive-pack", "$*")
	c.Check(err, gocheck.IsNil)
	defer commandmocker.Remove(dir)
	os.Args = []string{"gandalf", "god"}
	os.Setenv("SSH_ORIGINAL_COMMAND", "git-receive-pack 'myapp.git'")
	defer func() {
		os.Args = []string{}
		os.Setenv("SSH_ORIGINAL_COMMAND", "")
	}()
	stdout := new(bytes.Buffer)
	errorMsg := "You don't have access to write in this repository."
	executeAction(hasWritePermission, errorMsg, stdout)
	c.Assert(commandmocker.Ran(dir), gocheck.Equals, false)
}

func (s *S) TestExecuteActionShouldNotCallSSH_ORIGINAL_COMMANDWhenRepositoryDoesNotExist(c *gocheck.C) {
	dir, err := commandmocker.Add("git-receive-pack", "$*")
	c.Check(err, gocheck.IsNil)
	defer commandmocker.Remove(dir)
	os.Args = []string{"gandalf", s.user.Name}
	os.Setenv("SSH_ORIGINAL_COMMAND", "git-receive-pack 'ghostapp.git'")
	defer func() {
		os.Args = []string{}
		os.Setenv("SSH_ORIGINAL_COMMAND", "")
	}()
	stdout := &bytes.Buffer{}
	errorMsg := "You don't have access to write in this repository."
	executeAction(hasWritePermission, errorMsg, stdout)
	c.Assert(commandmocker.Ran(dir), gocheck.Equals, false)
}

func (s *S) TestFormatCommandShouldReceiveAGitCommandAndCanonizalizeTheRepositoryPath(c *gocheck.C) {
	os.Setenv("SSH_ORIGINAL_COMMAND", "git-receive-pack 'myproject.git'")
	defer os.Setenv("SSH_ORIGINAL_COMMAND", "")
	cmd, err := formatCommand()
	c.Assert(err, gocheck.IsNil)
	p, err := config.GetString("git:bare:location")
	c.Assert(err, gocheck.IsNil)
	expected := path.Join(p, "myproject.git")
	c.Assert(cmd, gocheck.DeepEquals, []string{"git-receive-pack", expected})
}

func (s *S) TestFormatCommandShouldReceiveAGitCommandAndCanonizalizeTheRepositoryPathWithNamespace(c *gocheck.C) {
	os.Setenv("SSH_ORIGINAL_COMMAND", "git-receive-pack 'me/myproject.git'")
	defer os.Setenv("SSH_ORIGINAL_COMMAND", "")
	cmd, err := formatCommand()
	c.Assert(err, gocheck.IsNil)
	p, err := config.GetString("git:bare:location")
	c.Assert(err, gocheck.IsNil)
	expected := path.Join(p, "me/myproject.git")
	c.Assert(cmd, gocheck.DeepEquals, []string{"git-receive-pack", expected})
}

func (s *S) TestFormatCommandShouldReceiveAGitCommandProjectWithDash(c *gocheck.C) {
	os.Setenv("SSH_ORIGINAL_COMMAND", "git-receive-pack '/myproject.git'")
	defer os.Setenv("SSH_ORIGINAL_COMMAND", "")
	cmd, err := formatCommand()
	c.Assert(err, gocheck.IsNil)
	p, err := config.GetString("git:bare:location")
	c.Assert(err, gocheck.IsNil)
	expected := path.Join(p, "myproject.git")
	c.Assert(cmd, gocheck.DeepEquals, []string{"git-receive-pack", expected})
}
