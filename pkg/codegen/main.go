package main

import (
	"os"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	controllergen "github.com/rancher/wrangler/pkg/controller-gen"
	"github.com/rancher/wrangler/pkg/controller-gen/args"
)

func main() {
	os.Unsetenv("GOPATH")
	controllergen.Run(args.Options{
		OutputPackage: "github.com/cnrancher/rancher-upgrade-authtool/pkg/generated",
		Boilerplate:   "scripts/boilerplate.go.txt",
		Groups: map[string]args.Group{
			"management.cattle.io": {
				PackageName: "management.cattle.io",
				Types: []interface{}{
					v3.Cluster{},
					v3.AuthConfig{},
					v3.User{},
					v3.UserAttribute{},
					v3.GlobalRoleBinding{},
					v3.ClusterRoleTemplateBinding{},
					v3.ProjectRoleTemplateBinding{},
				},
			},
		},
	})
}
