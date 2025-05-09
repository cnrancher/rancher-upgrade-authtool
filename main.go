//go:generate go run pkg/codegen/cleanup/main.go
//go:generate go run pkg/codegen/main.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/cnrancher/rancher-upgrade-authtool/tool"
	"github.com/urfave/cli"
)

var (
	Version   = "dev"
	GitCommit = "HEAD"
)

func getVersion() string {
	return fmt.Sprintf("%s (%s)", Version, GitCommit)
}

func main() {
	var config tool.Config
	app := cli.NewApp()
	app.Name = "Sync AD/LDAP auth config for rancher users"
	app.Version = getVersion()
	app.Commands = []cli.Command{
		{
			Name:    "upgrade",
			Aliases: []string{"u"},
			Usage:   "upgrade rancher user to new version",
			Action: func(c *cli.Context) error {
				if config.AuthType == "0" {
					config.AuthConfigType = tool.ActiveDirectoryAuth
				} else if config.AuthType == "1" {
					config.AuthConfigType = tool.OpenLDAPAuth
				}
				ctx := context.Background()
				return tool.Upgrade(ctx, &config)
			},
		},
	}
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:        "dry-run",
			Usage:       "Enable dry run",
			Required:    false,
			Destination: &config.IsDryRun,
		},
		cli.StringFlag{
			Name:        "kubeconfig",
			Usage:       "kube config for accessing local k8s cluster of rancher",
			Destination: &config.KubeConfig,
			EnvVar:      "KUBECONFIG",
		},
		cli.StringFlag{
			Name:        "auth-type",
			Usage:       "auth type: 0 - AD auth, 1 - openldap auth",
			Required:    true,
			Destination: &config.AuthType,
		},
		cli.StringFlag{
			Name:        "log-file",
			Usage:       "log file path for upgrade",
			Required:    false,
			Destination: &config.LogFilePath,
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
