package yayagent

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tomis007/yay-agent/internal/yubikey"
	"github.com/tomis007/yay-agent/internal/yubikeyreader"
	"github.com/tomis007/yay-agent/third_party/ssh/agent"

	"github.com/awnumar/memguard"
	"github.com/go-piv/piv-go/v2/piv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

type YAYAgent struct {
	mu           sync.Mutex
	pins         map[uint32]*memguard.Enclave
	locks        map[uint32]*atomic.Bool
	normalAgent  agent.Agent
	unlockEvents chan (bool)
}

func (a *YAYAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	log.Info().Msg(fmt.Sprintf("Extension request: %s", extensionType))
	switch extensionType {
	case "yay-agent-status@openssh.com":
		return a.yayAgentStatusExtension()
	default:
		log.Warn().Msg(fmt.Sprintf("unsupported extension request: %s", extensionType))
		return nil, agent.ErrExtensionUnsupported
	}
}

func (a *YAYAgent) yayAgentStatusExtension() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	y := yubikeyreader.YubikeyReader{}
	defer y.Close()
	var msg string
	for serial, lock := range a.locks {
		if lock.Load() {
			msg += fmt.Sprintf("PIN (serial:%d) Unlocked\n", serial)
		} else {
			msg += fmt.Sprintf("PIN (serial:%d) Locked\n", serial)
		}
	}
	if version, tries, serial, err := y.PIVInfo(0); err == nil {
		msg += fmt.Sprintf("Serial: %d\nVersion: %s\nPIN Tries Remaining: %d\n", serial, version, tries)
	} else {
		log.Warn().Msg(err.Error())
	}
	if len(a.locks) == 0 {
		msg += "No Yubikey connected\nNo PINS cached\n"
	}
	return []byte(msg), nil
}

func (a *YAYAgent) signWithSSHFlags(signer ssh.Signer, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if flags == 0 {
		return signer.Sign(rand.Reader, data)
	} else {
		if algorithmSigner, ok := signer.(ssh.AlgorithmSigner); !ok {
			return nil, fmt.Errorf("agent: signature does not support non-default signature algorithm: %T", signer.PublicKey().Type())
		} else {
			switch flags {
			case agent.SignatureFlagRsaSha256:
				return algorithmSigner.SignWithAlgorithm(rand.Reader, data, ssh.KeyAlgoRSASHA256)
			case agent.SignatureFlagRsaSha512:
				return algorithmSigner.SignWithAlgorithm(rand.Reader, data, ssh.KeyAlgoRSASHA512)
			default:
				return nil, fmt.Errorf("agent: unsupported signature flags: %d", flags)
			}
		}
	}
}

func (a *YAYAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	log.Info().Msg("signing with flags!, should be called!")
	// First see if any of the normal keys saved in the keyring are being requested
	wanted := key.Marshal()
	if signers, err := a.normalAgent.Signers(); err != nil {
		log.Error().Err(err).Msg("unable to get signers!")
	} else {
		for _, k := range signers {
			if bytes.Equal(k.PublicKey().Marshal(), wanted) {
				if flags == 0 {
					return k.Sign(rand.Reader, data)
				} else {
					return a.signWithSSHFlags(k, data, flags)
				}
			}
		}
	}

	// Try to sign with Yubikey
	if len(a.pins) == 0 {
		return nil, fmt.Errorf("attempting to sign without any Yubikey PINs set!")
	}

	// see if the requested yubikey is connected and try to sign with it
	log.Info().Msg(fmt.Sprintf("signing operation requested for key %s", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))))
	y := yubikeyreader.YubikeyReader{}
	defer y.Close()

	keyInfo, err := y.GetKeyInfo(30 * time.Second)
	if errors.Is(err, piv.ErrNotFound) {
		log.Info().Msg("No Data in Yubikey PIV Authentication Slot (9C)")
		log.Info().Msg("Run: 'yay-agent keys create'")
		return nil, err
	} else if err != nil {
		return nil, err
	}
	if x, err := ssh.NewPublicKey(keyInfo.PublicKey); err != nil {
		return nil, err
	} else if !bytes.Equal(x.Marshal(), wanted) {
		log.Error().Msg("Unable to identify key for signing, please attach correct Yubikey!")
		return nil, fmt.Errorf("can not find key")
	}

	serial, err := y.GetSerial(0)
	if err != nil {
		return nil, err
	}
	if pin, ok := a.pins[serial]; ok {
		enc, err := pin.Open()
		if err != nil {
			return nil, err
		}
		privKey, err := y.PrivateKey(0*time.Second, piv.SlotAuthentication, keyInfo.PublicKey, piv.KeyAuth{PIN: enc.String()})
		defer enc.Destroy()
		if err != nil {
			return nil, err
		}

		signer, err := ssh.NewSignerFromKey(privKey)
		if err != nil {
			return nil, err
		}
		a.unlockEvents <- true
		if flags == 0 {
			return signer.Sign(rand.Reader, data)
		} else {
			return a.signWithSSHFlags(signer, data, flags)
		}
	} else {
		log.Warn().Msg("requested signing for yubikey pin that is not specified")
		return nil, fmt.Errorf("requested yubikey pin not set")
	}
}

// Start a goroutine that will automatically remove the pin after
// timeout, unless a signing or unlock operation occurs
func (a *YAYAgent) ConfigureLockout(timeout time.Duration) {
	go func() {
		for {
			select {
			case <-a.unlockEvents:
				log.Debug().Msg("Unlock event! Restarting timeout")
			case <-time.After(timeout):
				for serial := range a.locks {
					log.Info().Msg("Timeout! Locking yubikey")
					a.locks[serial].Store(false)
				}
			}
		}
	}()
}

func (a *YAYAgent) List() ([]*agent.Key, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	log.Info().Msg("list request")
	keys, err := a.normalAgent.List()
	if err != nil {
		return nil, err
	}

	// check for connected yubikey
	if pubKey, err := yubikey.GetPublicKey(0 * time.Second); err == nil {
		keys = append(keys, &agent.Key{
			Format:  pubKey.Type(),
			Blob:    pubKey.Marshal(),
			Comment: "yubikey PIV SLOT 9A",
		})
	}
	return keys, nil
}

// Sign has the agent sign the data using a protocol 2 key as defined
// in [PROTOCOL.agent] section 2.6.2.
func (a *YAYAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	log.Info().Msg(fmt.Sprintf("sign request %s", key.Type()))
	return a.SignWithFlags(key, data, 0)
}

// Add adds a private key to the agent.
// Does nothing with Yubikeys, works for regular keys
func (a *YAYAgent) Add(key agent.AddedKey) error {
	log.Info().Msg("add request")
	return a.normalAgent.Add(key)
}

// Remove removes all identities with the given public key.
// Does nothing with Yubikeys, works for regualr keys
func (a *YAYAgent) Remove(key ssh.PublicKey) error {
	log.Info().Msg("remove request")
	return a.normalAgent.Remove(key)
}

// RemoveAll removes all identities.
// Does nothing with Yubikeys, works for regualr keys
func (a *YAYAgent) RemoveAll() error {
	log.Info().Msg("remove all request")
	return a.normalAgent.RemoveAll()
}

// Lock drops the yubikey pin and will require another pin unlock for use
func (a *YAYAgent) Lock(passphrase []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	log.Info().Msg("lock request! Clearing pins...")
	clear(a.pins)
	for serial := range a.locks {
		a.locks[serial].Store(false)
	}
	return nil
}

// Save the yubikey pin (for use in operations)
func (a *YAYAgent) Unlock(pin []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	log.Info().Msg("PIN verification unlock request")
	y := yubikeyreader.YubikeyReader{}
	defer y.Close()
	serial, err := y.GetSerial(30 * time.Second)

	savedPin := memguard.NewEnclave(pin)
	lockedBuf, err := savedPin.Open()
	if err != nil {
		return err
	}
	defer lockedBuf.Destroy()

	err = y.VerifyPIN(0, lockedBuf.String())
	if err == nil {
		log.Info().Msg("PIN Verification success")
		a.unlockEvents <- true
		if _, exists := a.locks[serial]; !exists {
			a.locks[serial] = &atomic.Bool{}
		}
		a.locks[serial].Store(true)
		a.pins[serial] = savedPin
	}
	return err
}

// Not supported
func (a *YAYAgent) Signers() ([]ssh.Signer, error) {
	log.Error().Msg("signers request, not supported")
	return nil, agent.ErrExtensionUnsupported
}

func (a *YAYAgent) HandleConn(c net.Conn) {
	if err := agent.ServeAgent(a, c); err != io.EOF {
		log.Err(err).Msg("error handling connection")
	}
}

func Bind(socketFile string, fork bool, launchd bool) error {
	if os.Getenv("YAY_AGENTD") != "1" && fork {
		return ForkAndExec(socketFile)
	} else {
		var yayAgentPath string
		if fork {
			yayAgentPath = os.Getenv("SSH_AUTH_SOCK")
		} else {
			if socketFile == "" {
				var err error
				if yayAgentPath, err = os.MkdirTemp(os.TempDir(), "yay-*"); err != nil {
					return err
				}
			} else {
				yayAgentPath = path.Dir(socketFile)
				if err := os.MkdirAll(yayAgentPath, 0700); err != nil {
					return err
				}
			}
		}

		yaySocket := fmt.Sprintf("%s/agent.%d", yayAgentPath, os.Getpid())
		if socketFile != "" {
			yaySocket = socketFile
		}
		// starting from yay-agent's plist with launchd
		// delete the provided socket and reuse the same file
		if launchd {
			yaySocket = os.Getenv("SSH_YAYAUTH_SOCK")
			if err := os.Remove(yaySocket); err != nil {
				return err
			}
		}

		// save logs to a file if we forked
		var runLogFile os.File
		var logFile = fmt.Sprintf("%s/yay-agent.log", yayAgentPath)
		if fork {
			runLogFile, _ := os.OpenFile(
				logFile,
				os.O_APPEND|os.O_CREATE|os.O_WRONLY,
				0600,
			)
			defer runLogFile.Close()
			os.Stdin.Close()
			os.Stdin.Close()
			os.Stderr.Close()
			log.Logger = log.Output(zerolog.ConsoleWriter{Out: runLogFile})
		}

		log.Info().Msg(fmt.Sprintf("Agent socket: %s", yaySocket))
		l, err := net.Listen("unix", yaySocket)
		if err != nil {
			return err
		}
		defer l.Close()
		if err := os.Chmod(yaySocket, 0600); err != nil {
			return err
		}

		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			msg := <-sigs
			log.Warn().Msg(fmt.Sprintf("Received signal: %s", msg.String()))
			l.Close()
			if fork {
				runLogFile.Close()
				err = os.Remove(logFile)
			}
			if socketFile == "" && !launchd {
				// clean up our temp directory
				err = os.Remove(yayAgentPath)
				if err != nil {
					log.Info().Msg(err.Error())
				}
			}
			os.Exit(1)
		}()

		yayAgent := NewYAYAgent(60 * time.Minute)
		log.Info().Msg("Listening for connections!")
		for {
			c, err := l.Accept()
			if err != nil && !errors.Is(err, net.ErrClosed) {
				log.Err(err).Msg("error handling connection")
			}
			if err == nil {
				go yayAgent.HandleConn(c)
			}
		}
	}
}

func NewYAYAgent(timeout time.Duration) *YAYAgent {
	yayAgent := YAYAgent{
		unlockEvents: make(chan bool),
		normalAgent:  agent.NewKeyring(),
		pins:         make(map[uint32]*memguard.Enclave),
		locks:        make(map[uint32]*atomic.Bool),
	}
	yayAgent.ConfigureLockout(timeout)
	return &yayAgent
}

func ForkAndExec(socketFile string) error {
	os.Unsetenv("SSH_AUTH_SOCK")
	os.Unsetenv("SSH_AGENT_ID")
	if socketFile != "" {
		if err := os.MkdirAll(filepath.Dir(socketFile), 0600); err != nil {
			return err
		}
	} else {
		var err error
		socketFile, err = os.MkdirTemp(os.TempDir(), "yay-*")
		if err != nil {
			return err
		}
	}
	pwd, _ := os.Getwd()
	// to Daemonize in go, need to use ForkExec to just run again
	pid, err := syscall.ForkExec(os.Args[0], os.Args, &syscall.ProcAttr{
		Env: append(os.Environ(), "YAY_AGENTD=1", fmt.Sprintf("SSH_AUTH_SOCK=%s", socketFile)),
		Dir: pwd,
		Sys: &syscall.SysProcAttr{
			Setsid: true,
		},
	})

	if err != nil {
		return err
	}

	fmt.Printf("%s\n", fmt.Sprintf("SSH_AUTH_SOCK=%s/agent.%d; export SSH_AUTH_SOCK;", socketFile, pid))
	fmt.Printf("%s\n", fmt.Sprintf("SSH_AGENT_ID=%d; export SSH_AGENT_PID;", pid))
	fmt.Printf("%s\n", fmt.Sprintf("echo Agent pid %d", pid))

	return nil
}
