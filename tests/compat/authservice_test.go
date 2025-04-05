// Copyright (c) Synadia Communications, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package compat

import (
    "bytes"
    "encoding/base64"
    "encoding/json"
    "errors"
    "github.com/aricart/nst.go"
    "github.com/nats-io/jwt/v2"
    "github.com/nats-io/nats.go"
    "github.com/nats-io/nkeys"
    "github.com/stretchr/testify/suite"
    "os"
    "os/exec"
    "testing"
    "time"
)

type CalloutSuite struct {
    suite.Suite
    dir *nst.TestDir
    env CalloutEnv
    ns  nst.NatsServer
}

type CalloutEnv interface {
    // GetConf returns the server configuration
    GetServerConf() []byte
    // ServiceConnOpts returns additional service connection options
    ServiceUserOpts() []nats.Option
    ServiceAudience() string
    EncryptionKey() nkeys.KeyPair
    Audience() string
    EncodeUser(account string, claim jwt.Claims) (string, error)
    ServiceOpts() []Option
    UserOpts() []nats.Option
    AccountKey() nkeys.KeyPair
}

type NATSOptions struct {
    Servers          []string      `json:"servers"`
    NoRandomize      bool          `json:"no_randomize"`
    Name             string        `json:"name"`
    Verbose          bool          `json:"verbose"`
    Pedantic         bool          `json:"pedantic"`
    Secure           bool          `json:"secure"`
    AllowReconnect   bool          `json:"allow_reconnect"`
    MaxReconnect     int           `json:"max_reconnect"`
    ReconnectWait    time.Duration `json:"reconnect_wait"`
    Timeout          time.Duration `json:"timeout"`
    PingInterval     time.Duration `json:"ping_interval"`
    MaxPingsOut      int           `json:"max_pings_out"`
    ReconnectBufSize int           `json:"reconnect_buf_size"`
    SubChanLen       int           `json:"sub_chan_len"`
    User             string        `json:"user"`
    Password         string        `json:"password"`
    Token            string        `json:"token"`
}

type callbackFn string

// Option is a function type used to configure the AuthorizationService options
type Option func(*Options) error

type Options struct {
    // Name for the AuthorizationService cannot have spaces, etc, as this is
    // the name that the actual micro.Service will use.
    Name string
    // Authorizer function that processes authorization request and issues user
    // JWT
    Authorizer callbackFn
    // ResponseSigner is a function that performs the signing of the
    // jwt.AuthorizationResponseClaim
    ResponseSigner callbackFn
    // ResponseSigner is the key that will be used to sign the
    // jwt.AuthorizationResponseClaim
    ResponseSignerKey nkeys.KeyPair
    // ResponseSigner is the key that ID of the account issuing the
    // jwt.AuthorizationResponseClaim if not set, ResponseSigner is the account
    ResponseSignerIssuer string
    // EncryptionKey is an optional configuration that must be provided if the
    // callout is configured to use encryption.
    EncryptionKey nkeys.KeyPair
    // InvalidUser when set user JWTs are validated if error notified via the
    // callback
    InvalidUser callbackFn
    // ErrCallback is an optional callback invoked whenever AuthorizerFn
    // returns an error, useful for handling test errors.
    ErrCallback callbackFn
    // ServiceEndpoints sets the number of endpoints available for the service
    // to handle requests.
    ServiceEndpoints int
    // AsyncWorkers specifies the number of workers used for asynchronous task
    // processing.
    AsyncWorkers int
}

type CompatKey struct {
    Seed string `json:"seed"`
    Pk   string `json:"pk"`
}

type CompatVars struct {
    NatsUrls     []string    `json:"nats_urls"`
    NatsOpts     NATSOptions `json:"nats_opts"`
    Audience     string      `json:"audience"`
    UserInfoSubj string      `json:"user_info_subj"`
    AccountKey   CompatKey   `json:"account_key"`
}

func NewCalloutSuite(t *testing.T) *CalloutSuite {
    return &CalloutSuite{dir: nst.NewTestDir(t, os.TempDir(), "callout_test")}
}

// ResponseSignerKey sets the response signer key to be used for signing
// authorization responses in the authorization service. The key pair must be an
// account private key, otherwise an error is returned.
func ResponseSignerKey(kp nkeys.KeyPair) Option {
    return func(o *Options) error {
        seed, err := kp.Seed()
        if err != nil {
            return errors.New("response signer key must be an account private key")
        }
        if !bytes.HasPrefix(seed, []byte("SA")) {
            return errors.New("response signer key must be an account private key")
        }
        o.ResponseSignerKey = kp
        return nil
    }
}

func (s *CalloutSuite) SetupServer(conf []byte) nst.NatsServer {
    return nst.NewNatsServer(s.dir, &nst.Options{
        ConfigFile: s.dir.WriteFile("server.conf", conf),
        Port:       -1,
    })
}

func (s *CalloutSuite) SetupSuite() {
    //println(">>> SETUP SUITE", string(s.env.GetServerConf()))
    s.ns = s.SetupServer(s.env.GetServerConf())
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

func (s *CalloutSuite) TestSetupOK() {
    println("test setup starting...")

    compatExe := os.Getenv("X_COMPAT_EXE")
    if compatExe == "" {
        s.T().Fatal("environment variable X_COMPAT_EXE is not set")
    }
    println("X_COMPAT_EXE:", compatExe)

    opts := s.env.ServiceUserOpts()
    opts1 := &nats.Options{}

    for _, opt := range opts {
        err := opt(opts1)
        if err != nil {
            s.T().Fatalf("can't set opts: %v", err)
        }
    }

    opts2 := NATSOptions{
        Secure:           opts1.Secure,
        AllowReconnect:   opts1.AllowReconnect,
        MaxReconnect:     opts1.MaxReconnect,
        ReconnectWait:    opts1.ReconnectWait,
        Timeout:          opts1.Timeout,
        PingInterval:     opts1.PingInterval,
        MaxPingsOut:      opts1.MaxPingsOut,
        ReconnectBufSize: opts1.ReconnectBufSize,
        SubChanLen:       opts1.SubChanLen,
        User:             opts1.User,
        Password:         opts1.Password,
        Token:            opts1.Token,
    }

    seed, err := s.env.AccountKey().Seed()
    if err != nil {
        s.T().Fatalf("failed to get account seed: %v", err)
    }

    pk, err := s.env.AccountKey().PublicKey()
    if err != nil {
        s.T().Fatalf("failed to get account pk: %v", err)
    }

    cv := CompatVars{
        NatsUrls:     s.ns.NatsURLs(),
        NatsOpts:     opts2,
        Audience:     s.env.Audience(),
        UserInfoSubj: nst.UserInfoSubj,
        AccountKey: CompatKey{
            Seed: string(seed),
            Pk:   pk,
        },
    }

    var buf bytes.Buffer
    if err := json.NewEncoder(&buf).Encode(cv); err != nil {
        s.T().Fatalf("failed to encode CompatVars to JSON: %v", err)
    }

    encoded := base64.StdEncoding.EncodeToString(buf.Bytes())

    println("Encoded CompatVars:", encoded)

    cmd := exec.Command(compatExe, "-r", "-") // Replace with your process

    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr

    cmd.Stdin = bytes.NewReader([]byte(encoded))

    if err := cmd.Start(); err != nil {
        s.T().Fatalf("failed to start process: %v", err)
    }

    println("process started, PID:", cmd.Process.Pid)

    time.Sleep(3 * time.Second)

    //serviceConn := s.getServiceConn()
    //defer serviceConn.Close()
    //info := nst.ClientInfo(s.T(), serviceConn)
    //s.Equal(s.env.ServiceAudience(), info.Data.Account)

    //opts := append(s.env.ServiceOpts(), Authorizer(authorizer), Logger(nst.NewNilLogger()))
    //svc, err := NewAuthorizationService(serviceConn, opts...)
    //s.NoError(err)
    //s.NotNil(svc)
    //defer func() {
    //    _ = svc.Stop()
    //}()

    println(">>> connecting as user...")
    c, err := s.userConn(nats.UserInfo("hxxello", "woxxrld"))
    s.NoError(err)
    s.NotNil(c)
    info := nst.ClientInfo(s.T(), c)
    s.Contains(info.Data.Permissions.Pub.Allow, nst.UserInfoSubj)
    s.Contains(info.Data.Permissions.Sub.Allow, "_INBOX.>")

    // Create a channel to signal when the process exits
    done := make(chan error, 1)

    // Start a goroutine to wait for the process to finish
    go func() {
        done <- cmd.Wait()
    }()

    // Use a select statement to wait for either the process to exit or a timeout
    select {
    case err := <-done:
        if err != nil {
            s.T().Fatalf("process exited with error: %v", err)
        } else {
            println("process exited successfully, code:", cmd.ProcessState.ExitCode())
        }
    case <-time.After(5 * time.Second):
        println("process timed out, killing process...")
        if killErr := cmd.Process.Kill(); killErr != nil {
            s.T().Fatalf("failed to kill process: %v", killErr)
        } else {
            println("process killed successfully")
        }
    }

    println("Size of encoded in KB:", len(encoded)/1024)
    println("test setup ok", len(encoded))
}
