package client

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

// Submits the Yubikey PIN to the running yay-agent
func EnterPin() error {
	agentClient, err := NewAgentClient()
	if err != nil {
		return err
	}

	fmt.Print("Enter Yubikey PIN: ")
	pin, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return err
	}
	fmt.Printf("\n")

	if err = agentClient.Unlock(pin); err != nil {
		CheckYubikeyStatus()
		log.Fatal().Msg(fmt.Sprintf("Setting PIN Failed: %v", err))
	} else {
		log.Info().Msg("Yubikey PIN Set and Verified!")
	}
	return nil
}

// Removes the Yubikey PIN from the running yay-agent
func Lock() error {
	if agentClient, err := NewAgentClient(); err != nil {
		return err
	} else if err := agentClient.Lock(nil); err != nil {
		return err
	}
	log.Info().Msg("Yubikey PIN Removed!")
	return nil
}

// Checks the pin status from the running yay-agent
func CheckYubikeyStatus() error {
	agentClient, err := NewAgentClient()
	if err != nil {
		return err
	}
	if resp, err := agentClient.Extension("yay-agent-status@openssh.com", nil); err != nil {
		return err
	} else {
		fmt.Print(string(resp))
		return nil
	}
}

func NewAgentClient() (agent.ExtendedAgent, error) {
	if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" {
		if conn, err := net.Dial("unix", socket); err == nil {
			return agent.NewClient(conn), nil
		} else {
			log.Fatal().Err(err).Msg("failed to connect to agent")
		}
	}
	log.Fatal().Msg("SSH_AUTH_SOCK not defined!")
	return nil, fmt.Errorf("unable to connect")
}
