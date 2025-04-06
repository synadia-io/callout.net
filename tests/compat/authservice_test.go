// Copyright (c) Synadia Communications, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0.

// Adapted from https://github.com/synadia-io/callout.go

package compat

import (
	"github.com/aricart/nst.go"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/suite"
	"os"
	"testing"
)

type CalloutSuite struct {
	suite.Suite
	dir *nst.TestDir
	env CalloutEnv
	ns  nst.NatsServer
	// setup second server to talk to auth service process
	dir2 *nst.TestDir
	ns2  nst.NatsServer
}

type CalloutEnv interface {
	GetServerConf() []byte
	ServiceUserOpts() []nats.Option
	ServiceAudience() string
	EncryptionKey() nkeys.KeyPair
	Audience() string
	EncodeUser(account string, claim jwt.Claims) (string, error)
	UserOpts() []nats.Option
	GetAccounts() map[string]nkeys.KeyPair
	ServiceCreds() string
}

func NewCalloutSuite(t *testing.T) *CalloutSuite {
	return &CalloutSuite{
		dir:  nst.NewTestDir(t, os.TempDir(), "callout_test"),
		dir2: nst.NewTestDir(t, os.TempDir(), "callout2_test"),
	}
}

func (s *CalloutSuite) SetupServer(conf []byte) nst.NatsServer {
	return nst.NewNatsServer(s.dir, &nst.Options{
		ConfigFile: s.dir.WriteFile("server.conf", conf),
		Port:       -1,
	})
}

func (s *CalloutSuite) SetupSuite() {
	s.ns = s.SetupServer(s.env.GetServerConf())
	s.ns2 = nst.NewNatsServer(s.dir2, nil)
}

func (s *CalloutSuite) TearDownSuite() {
	s.ns.Shutdown()
	s.dir.Cleanup()
}

func (s *CalloutSuite) getServiceConn() *nats.Conn {
	nc, err := s.ns.MaybeConnect(s.env.ServiceUserOpts()...)
	s.NoError(err)
	return nc
}

func (s *CalloutSuite) userConn(opts ...nats.Option) (*nats.Conn, error) {
	buf := append(opts, s.env.UserOpts()...)
	return s.ns.MaybeConnect(buf...)
}

func TestBasicEnv(t *testing.T) {
	cs := NewCalloutSuite(t)
	cs.env = NewBasicEnv(t, cs.dir)
	suite.Run(t, cs)
}

func TestBasicAccountEnv(t *testing.T) {
	cs := NewCalloutSuite(t)
	cs.env = NewBasicAccountEnv(t, cs.dir)
	suite.Run(t, cs)
}

func TestBasicEncryptedEnv(t *testing.T) {
	cs := NewCalloutSuite(t)
	cs.env = NewBasicEncryptedEnv(t, cs.dir)
	suite.Run(t, cs)
}

func TestDelegatedEnv(t *testing.T) {
	cs := NewCalloutSuite(t)
	cs.env = NewDelegatedEnv(t, cs.dir)
	suite.Run(t, cs)
}

func TestDelegatedKeysEnv(t *testing.T) {
	cs := NewCalloutSuite(t)
	cs.env = NewDelegatedKeysEnv(t, cs.dir)
	suite.Run(t, cs)
}

func (s *CalloutSuite) TestEncryptionMismatch() {
	es := StartExternalAuthService(s)
	defer es.Stop()

	// this should timeout, but shown as Authorization Violation because the service is NOT running due to the mismatch
	_, err := s.userConn(nats.MaxReconnects(1))
	s.Error(err)
	lastErr := es.GetLastError()
	s.Contains(lastErr, "encryption mismatch")
}
func (s *CalloutSuite) TestSetupOK() {
	es := StartExternalAuthService(s)
	defer es.Stop()

	c, err := s.userConn(nats.UserInfo("hello", "world"))
	s.NoError(err)
	s.NotNil(c)
	info := nst.ClientInfo(s.T(), c)
	s.Contains(info.Data.Permissions.Pub.Allow, nst.UserInfoSubj)
	s.Contains(info.Data.Permissions.Sub.Allow, "_INBOX.>")
}

func (s *CalloutSuite) TestAbortRequest() {
	es := StartExternalAuthService(s)
	defer es.Stop()

	nc, err := s.userConn(nats.UserInfo("hello", "world"))
	s.NoError(err)
	s.NotNil(nc)
	defer nc.Close()

	_, err = s.userConn(
		nats.UserInfo("errorme", ""),
		nats.MaxReconnects(1),
	)
	s.Error(err)

	_, err = s.userConn(
		nats.UserInfo("blacklisted", ""),
		nats.MaxReconnects(1),
	)
	s.Error(err)

	_, err = s.userConn(
		nats.UserInfo("blank", ""),
		nats.MaxReconnects(1),
	)
	s.Error(err)
}
