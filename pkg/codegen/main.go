// Turn off creation of Alias types, which break code generation.
// This can be removed after migrating to k8s 1.32 code generators that are aware of the new type.
// For more details see https://github.com/rancher/rancher/issues/47207
//
//go:debug gotypesalias=0
package main

import (
	"os"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	controllergen "github.com/rancher/wrangler/v3/pkg/controller-gen"
	"github.com/rancher/wrangler/v3/pkg/controller-gen/args"
)

func main() {
	os.Unsetenv("GOPATH")
	controllergen.Run(args.Options{
		OutputPackage: "github.com/cnrancher/rancher-upgrade-authtool/pkg/generated",
		Boilerplate:   "scripts/boilerplate.go.txt",
		Groups: map[string]args.Group{
			"management.cattle.io": {
				PackageName: "management.cattle.io",
				Types: []any{
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
