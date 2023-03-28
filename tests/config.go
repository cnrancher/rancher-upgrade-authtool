package tests

//
//import (
//	"github.com/JacieChao/rancher-upgrade-authtool/pkg/generated/controllers/management.cattle.io"
//	managementv3 "github.com/JacieChao/rancher-upgrade-authtool/pkg/generated/controllers/management.cattle.io/v3"
//	"k8s.io/client-go/dynamic"
//	"k8s.io/client-go/kubernetes"
//	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
//	"k8s.io/client-go/rest"
//	"os"
//)
//
//type Config struct {
//	Host  string
//	Token string
//}
//
//type Client struct {
//	RestConfig    *rest.Config
//	Management    managementv3.Interface
//	CoreClient    v1.CoreV1Interface
//	DynamicClient dynamic.Interface
//	Config
//}
//
//func NewRancherClient() (*Client, error) {
//	rancherHost := os.Getenv("TEST_RANCHER_HOST")
//	rancherToken := os.Getenv("TEST_RANCHER_TOKEN")
//	c := &Client{}
//	c.Host = rancherHost
//	c.Token = rancherToken
//
//	restConfig := &rest.Config{
//		Host:        rancherHost,
//		BearerToken: rancherToken,
//		TLSClientConfig: rest.TLSClientConfig{
//			Insecure: true,
//		},
//	}
//	c.RestConfig = restConfig
//	mgmt, err := management.NewFactoryFromConfig(restConfig)
//	if err != nil {
//		return nil, err
//	}
//	c.Management = mgmt.Management().V3()
//	k8sClient, err := kubernetes.NewForConfig(restConfig)
//	if err != nil {
//		return nil, err
//	}
//	c.CoreClient = k8sClient.CoreV1()
//	client, err := dynamic.NewForConfig(restConfig)
//	if err != nil {
//		return nil, err
//	}
//	c.DynamicClient = client
//
//	return c, nil
//}
