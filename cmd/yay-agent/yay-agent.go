package main

import (
	"context"
	"os"
	"time"

	"github.com/tomis007/yay-agent/internal/client"
	"github.com/tomis007/yay-agent/internal/yayagent"
	"github.com/tomis007/yay-agent/internal/yubikey"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	cmd := &cli.Command{
		Name:    "yay-agent",
		Usage:   "Yet Another Yubikey ssh agent",
		Version: "0.4.0",
		Commands: []*cli.Command{
			{
				Name:  "bind",
				Usage: "start the agent listening on a UNIX-domain socket",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "bind_address",
						Aliases: []string{"a"},
						Usage:   "path for the UNIX-domain socket bind address",
					},
					&cli.BoolFlag{
						Name:    "fork",
						Aliases: []string{"f"},
						Usage:   "fork into background",
					},
					&cli.BoolFlag{
						Name:    "launchd",
						Aliases: []string{"l"},
						Usage:   "launchd service",
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return yayagent.Bind(cmd.String("bind_address"), cmd.Bool("fork"), cmd.Bool("launchd"))
				},
			},
			{
				Name:  "status",
				Usage: "check the status of the yubikeys, required to be unlocked for Yubikey operations to work",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return client.CheckYubikeyStatus()
				},
			},
			{
				Name:    "pin",
				Aliases: []string{"unlock", "X"},
				Usage:   "submit the pin to the running agent",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return client.EnterPin()
				},
			},
			{
				Name:    "lock",
				Usage:   "remove the pin from the running agent",
				Aliases: []string{"x"},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return client.Lock()
				},
			},
			{
				Name:  "show",
				Usage: "prints attached Yubikey's public key to stdout",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return yubikey.Show(30 * time.Second)
				},
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal().Err(err).Msg("yay-agent errored")
	}
}
