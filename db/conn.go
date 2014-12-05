// Copyright 2014 gandalf authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package db provides util functions to deal with Gandalf's database.
package db

import (
	"github.com/gleez/gandalf/config"
	"github.com/gleez/gandalf/db/storage"
	"gopkg.in/mgo.v2"
)

const (
	DefaultDatabaseURL  = "127.0.0.1:27017"
	DefaultDatabaseName = "gandalf"
)

type Storage struct {
	*storage.Storage
}

// conn reads the gandalf config and calls storage.Open to get a database connection.
//
// Most gandalf packages should probably use this function. storage.Open is intended for
// use when supporting more than one database.
func conn() (*storage.Storage, error) {
	url, _ := config.GetString("database:url")
	if url == "" {
		url = DefaultDatabaseURL
	}
	dbname, _ := config.GetString("database:name")
	if dbname == "" {
		dbname = DefaultDatabaseName
	}
	return storage.Open(url, dbname)
}

func Conn() (*Storage, error) {
	var (
		strg Storage
		err  error
	)
	strg.Storage, err = conn()
	return &strg, err
}

// Repository returns a reference to the "repository" collection in MongoDB.
func (s *Storage) Repository() *storage.Collection {
	return s.Collection("repository")
}

// User returns a reference to the "user" collection in MongoDB.
func (s *Storage) User() *storage.Collection {
	return s.Collection("user")
}

func (s *Storage) Key() *storage.Collection {
	index := mgo.Index{Key: []string{"body"}, Unique: true}
	c := s.Collection("key")
	c.EnsureIndex(index)
	return c
}
