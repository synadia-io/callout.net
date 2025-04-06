package compat

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/aricart/nst.go"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const subjectDriverAll = ".test.driver.>"
const subjectServiceStop = ".test.service.stop"
const subjectServiceSync = ".test.service.sync"
const subjectDriverConnected = ".test.driver.connected"
const subjectDriverSync = ".test.driver.sync"
const subjectDriverError = ".test.driver.error"
const subjectDriverVars = ".test.driver.vars"

type ExtService struct {
	name   string
	t      *testing.T
	s      *CalloutSuite
	cv     *CompatVars
	cmd    *exec.Cmd
	nc2    *nats.Conn
	mu     sync.Mutex
	errors []string
}

type callbackFn string

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
	SuitName        string               `json:"suit_name"`
	NatsUrls        []string             `json:"nats_urls"`
	NatsOpts        NATSOptions          `json:"nats_opts"`
	Audience        string               `json:"audience"`
	ServiceAudience string               `json:"service_audience"`
	UserInfoSubj    string               `json:"user_info_subj"`
	EncryptionKey   CompatKey            `json:"encryption_key"`
	NatsTestUrls    []string             `json:"nats_test_urls"`
	AccountKeys     map[string]CompatKey `json:"account_keys"`
	Dir             string               `json:"dir"`
	NscDir          string               `json:"nsc_dir"`
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

func StartExternalAuthService(s *CalloutSuite) *ExtService {
	suitName := s.T().Name()
	logMessage(1, "Starting external auth service for "+suitName+" ...")
	cv := createVars(suitName, s)

	nc2, err := s.ns2.MaybeConnect()
	if err != nil {
		s.T().Fatalf("can't connect to nats2: %v", err)
	}

	es := &ExtService{
		name:   suitName,
		t:      s.T(),
		s:      s,
		cv:     cv,
		nc2:    nc2,
		errors: []string{},
	}

	waitConnected := make(chan struct{})
	timeout := time.NewTimer(5 * time.Second) // Set timeout duration as appropriate
	defer timeout.Stop()

	subscribe, err := nc2.Subscribe(suitName+subjectDriverAll, func(m *nats.Msg) {
		logMessage(2, "received message: "+string(m.Data))

		if m.Subject == suitName+subjectDriverSync {
			err := m.Respond([]byte("ok"))
			if err != nil {
				logMessage(0, fmt.Sprintf("error in sync response: %v", err))
			}
		} else if m.Subject == suitName+subjectDriverConnected {
			logMessage(1, "Connected")
			close(waitConnected) // Signal completion
			err := m.Respond([]byte("ok"))
			if err != nil {
				logMessage(0, fmt.Sprintf("error in connected response: %v", err))
			}
		} else if m.Subject == suitName+subjectDriverVars {
			var buf bytes.Buffer
			if err := json.NewEncoder(&buf).Encode(cv); err != nil {
				s.T().Fatalf("failed to encode CompatVars to JSON: %v", err)
			}
			//encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
			err := m.Respond(buf.Bytes())
			if err != nil {
				logMessage(0, fmt.Sprintf("error in vars response: %v", err))
			}
		} else if m.Subject == suitName+subjectDriverError {
			errorMessage := string(m.Data)
			logMessage(1, fmt.Sprintf("error from service: %s", errorMessage))

			es.mu.Lock()
			defer es.mu.Unlock()
			es.errors = append(es.errors, errorMessage)
		} else {
			logMessage(0, fmt.Sprintf("unknown subject: %s", m.Subject))
		}
	})
	if err != nil {
		s.T().Fatalf("error in test coordination sub: %v", err)
	}
	logMessage(1, "subscribed to test: "+subscribe.Subject)

	compatExe := os.Getenv("X_COMPAT_EXE")
	if compatExe == "" {
		s.T().Fatal("environment variable X_COMPAT_EXE is not set")
	}
	logMessage(3, "X_COMPAT_EXE: "+compatExe)

	natsTestUrl := s.ns2.NatsURLs()[0]
	logMessage(2, "natsTestUrl: "+natsTestUrl)

	cmd := exec.Command(compatExe, "-r", suitName, natsTestUrl) // Replace with your process
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		s.T().Fatalf("failed to start process: %v", err)
	}

	es.cmd = cmd

	logMessage(1, "process started")

	select {
	case <-waitConnected:
		logMessage(1, "service connected successfully.")
	case <-timeout.C:
		s.T().Fatalf("process failed to connect: %v", err)
	}

	return es
}

func (es *ExtService) GetLastError() string {
	_, _ = es.nc2.Request(es.name+subjectServiceSync, []byte("sync"), 5*time.Second)
	es.mu.Lock()
	defer es.mu.Unlock()
	if len(es.errors) == 0 {
		logMessage(3, "Get last error: N/A")
		return ""
	}
	lastError := es.errors[len(es.errors)-1]
	logMessage(2, fmt.Sprintf("Get last error: '%s'", lastError))
	return lastError
}

func (es *ExtService) GetErrors() []string {
	_, _ = es.nc2.Request(es.name+subjectServiceSync, []byte("sync"), 5*time.Second)
	es.mu.Lock()
	defer es.mu.Unlock()

	// Return a copy of the errors slice to ensure immutability
	errorsCopy := make([]string, len(es.errors))
	copy(errorsCopy, es.errors)
	return errorsCopy
}

func (es *ExtService) Stop() {
	_, _ = es.nc2.Request(es.name+subjectServiceStop, []byte("stop"), 5*time.Second)

	// Create a channel to signal when the process exits
	done := make(chan error, 1)

	// Start a goroutine to wait for the process to finish
	go func() {
		done <- es.cmd.Wait()
	}()

	// Use a select statement to wait for either the process to exit or a timeout
	select {
	case err := <-done:
		if err != nil {
			es.t.Fatalf("process exited with error: %v", err)
		} else {
			logMessage(1, fmt.Sprintf("process exited successfully, code: %d", es.cmd.ProcessState.ExitCode()))
		}
	case <-time.After(5 * time.Second):
		println("process timed out, killing process...")
		if killErr := es.cmd.Process.Kill(); killErr != nil {
			es.t.Fatalf("failed to kill process: %v", killErr)
		} else {
			logMessage(1, "process killed successfully")
		}
	}
}

func createVars(suitName string, s *CalloutSuite) *CompatVars {
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

	accountKeys := s.env.GetAccounts()
	compatKeyMap := make(map[string]CompatKey, len(accountKeys))
	for key, keyPair := range accountKeys {
		compatKeyMap[key] = getCompatKey(keyPair)
	}

	return &CompatVars{
		SuitName:        suitName,
		NatsTestUrls:    s.ns2.NatsURLs(),
		NatsUrls:        s.ns.NatsURLs(),
		NatsOpts:        opts2,
		Audience:        s.env.Audience(),
		ServiceAudience: s.env.ServiceAudience(),
		UserInfoSubj:    nst.UserInfoSubj,
		EncryptionKey:   getCompatKey(s.env.EncryptionKey()),
		AccountKeys:     compatKeyMap,
		Dir:             s.dir.Dir,
		NscDir:          filepath.Join(s.dir.Dir, "nsc"),
	}
}

func getCompatKey(kp nkeys.KeyPair) CompatKey {
	return CompatKey{
		Seed: getSeed(kp),
		Pk:   getPK(kp),
	}
}

func getPK(kp nkeys.KeyPair) string {
	if kp == nil {
		return ""
	}
	pk, err := kp.PublicKey()
	if err != nil {
		return ""
	}
	return pk
}

func getSeed(kp nkeys.KeyPair) string {
	if kp == nil {
		return ""
	}
	seed, err := kp.Seed()
	if err != nil {
		return ""
	}
	return string(seed)
}

var globalDebugLevel int

func init() {
	globalDebugLevel = getDebugLevel()
}

func getDebugLevel() int {
	if debugEnv, exists := os.LookupEnv("X_COMPAT_DEBUG"); exists {
		switch strings.ToLower(debugEnv) {
		case "no", "off", "false":
			return 0
		default:
			if num, err := strconv.Atoi(debugEnv); err == nil {
				return num
			} else {
				return 1
			}
		}
	}
	return 0
}

func logMessage(level int, message string) {
	if level <= globalDebugLevel {
		fmt.Printf("[TEST] [%d] %s\n", level, message)
	}
}
