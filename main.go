//go:generate go run pkg/codegen/cleanup/main.go
//go:generate go run pkg/codegen/main.go
package main

import (
	"log"
	"os"

	"github.com/JacieChao/rancher-upgrade-authtool/tool"
	"github.com/urfave/cli"
)

func main() {
	var config tool.Config
	app := cli.NewApp()
	app.Name = "rancher user rbac checker"
	app.Version = "v1.0.0"
	app.Commands = []cli.Command{
		//{
		//	Name:    "upgrade",
		//	Aliases: []string{"u"},
		//	Usage:   "upgrade rancher user to new version",
		//	Action: func(c *cli.Context) error {
		//		if config.AuthType == "0" {
		//			config.AuthConfigType = tool.ActiveDirectoryAuth
		//		} else if config.AuthType == "1" {
		//			config.AuthConfigType = tool.OpenLDAPAuth
		//		}
		//		return tool.Upgrade(&config)
		//	},
		//},
		{
			Name:  "checker",
			Usage: "check rancher user rbac",
			Action: func(c *cli.Context) error {
				return tool.Checker(&config)
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
			Name:        "targetClusterConfig",
			Usage:       "kubeconfig for accessing target downstream cluster",
			Destination: &config.TargetClusterConfig,
			EnvVar:      "TARGET_CLUSTER_CONFIG",
		},
		cli.StringFlag{
			Name:        "cluster",
			Usage:       "target downstream cluster id(get from Rancher)",
			Destination: &config.Cluster,
			EnvVar:      "CLUSTER",
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
