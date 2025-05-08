package client

import (
	"context"

	"github.com/rancher/lasso/pkg/client"
	"github.com/rancher/lasso/pkg/controller"
	"github.com/rancher/lasso/pkg/dynamic"
	v3 "github.com/rancher/rancher/pkg/apis/cluster.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/clients"
	v1 "github.com/rancher/wrangler/pkg/generated/controllers/core/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
)

type Clients struct {
	Clusters                    *client.Client
	ProjectRoleTemplateBindings *client.Client
	ClusterRoleTemplateBindings *client.Client
	AuthConfigs                 *client.Client
	Users                       *client.Client
	UserAttributes              *client.Client
	GlobalRoleBindings          *client.Client
	Secrets                     v1.SecretClient
	Dynamic                     *dynamic.Controller
}

func New(ctx context.Context, rest *rest.Config) (*Clients, error) {
	c, err := clients.NewFromConfig(rest, nil)
	if err != nil {
		return nil, err
	}

	if err := c.Start(ctx); err != nil {
		return nil, err
	}

	localSchemeBuilder := runtime.SchemeBuilder{
		v3.AddToScheme,
	}
	scheme := runtime.NewScheme()
	err = localSchemeBuilder.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}
	factory, err := controller.NewSharedControllerFactoryFromConfig(rest, scheme)
	if err != nil {
		return nil, err
	}

	return &Clients{
		Dynamic:                     c.Dynamic,
		Secrets:                     c.Core.Secret(),
		Users:                       NewClient(factory, "management.cattle.io", "v3", "users", "User", false),
		Clusters:                    NewClient(factory, "management.cattle.io", "v3", "clusters", "Cluster", false),
		ProjectRoleTemplateBindings: NewClient(factory, "management.cattle.io", "v3", "projectRoleTemplateBindings", "ProjectRoleTemplateBinding", true),
		ClusterRoleTemplateBindings: NewClient(factory, "management.cattle.io", "v3", "clusterRoleTemplateBindings", "ClusterRoleTemplateBinding", true),
		GlobalRoleBindings:          NewClient(factory, "management.cattle.io", "v3", "globalRoleBindings", "GlobalRoleBinding", false),
		AuthConfigs:                 NewClient(factory, "management.cattle.io", "v3", "authconfigs", "AuthConfig", false),
		UserAttributes:              NewClient(factory, "management.cattle.io", "v3", "userattributes", "UserAttribute", false),
	}, nil
}

func NewClient(factory controller.SharedControllerFactory, group, version, resource, kind string, namespaced bool) *client.Client {
	gvr := schema.GroupVersionResource{Group: group, Resource: resource, Version: version}
	sharedController := factory.ForResourceKind(gvr, kind, namespaced)
	return sharedController.Client()
}
