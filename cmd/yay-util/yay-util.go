package main

import (
	"context"
	"os"
	"time"

	"github.com/tomis007/yay-agent/internal/yubikey"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	cmd := &cli.Command{
		Name:    "yay-util",
		Usage:   "A yubikey helper to configure, manage, and create keys",
		Version: "0.4.0",
		Commands: []*cli.Command{
			{
				Name:  "config",
				Usage: "checks status of yubikey PIN and Management Key. Will help configure and change PIN, PUK, and Management Key",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return yubikey.Status(30 * time.Second)
				},
			},
			{
				Name:  "piv",
				Usage: "get yubikey piv information",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return yubikey.PIVInfo(30 * time.Second)
				},
			},
			{
				Name:  "keys",
				Usage: "Manage yubikey Authentication Key (Slot 9A)",
				Commands: []*cli.Command{
					{
						Name:  "create",
						Usage: "create new key",
						Flags: []cli.Flag{
							&cli.BoolFlag{Name: "overwrite"},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							return yubikey.Create(cmd.Bool("overwrite"), 30*time.Second)
						},
					},
					{
						Name:  "keyinfo",
						Usage: "get current key information and status",
						Action: func(ctx context.Context, cmd *cli.Command) error {
							return yubikey.Info("info cli", 30*time.Second)
						},
					},
					{
						Name:  "show",
						Usage: "prints attached Yubikey's public key to stdout",
						Action: func(ctx context.Context, cmd *cli.Command) error {
							return yubikey.Show(30 * time.Second)
						},
					},
					{
						Name:  "save",
						Usage: "saves public key to file",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:    "file",
								Aliases: []string{"f"},
								Value:   "yubikey.pub",
								Usage:   "output file",
							},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							return yubikey.Save(cmd.String("file"), 30*time.Second)
						},
					},
				},
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal().Err(err).Msg("yay-agent errored!")
	}
}
