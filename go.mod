module github.com/JacieChao/rancher-upgrade-authtool

go 1.14

replace (
	github.com/prometheus/prometheus => github.com/prometheus/prometheus v0.0.0-20200626085723-c448ada63d83
	github.com/rancher/norman => github.com/cnrancher/pandaria-norman v0.0.0-20210308033239-d88db3d2258c
	github.com/rancher/prometheus-auth/pkg/data => github.com/cnrancher/prometheus-auth/pkg/data v0.0.0-20201013075525-c015fa82fdd7
	github.com/rancher/prometheus-auth/pkg/prom => github.com/cnrancher/prometheus-auth/pkg/prom v0.0.0-20201013075525-c015fa82fdd7
	github.com/rancher/rancher => github.com/cnrancher/pandaria v0.0.0-20210329084518-dc6472ca7ad3
	github.com/rancher/rancher/pkg/apis => github.com/cnrancher/pandaria/pkg/apis v0.0.0-20210329084518-dc6472ca7ad3
	github.com/rancher/rancher/pkg/client => github.com/cnrancher/pandaria/pkg/client v0.0.0-20210329084518-dc6472ca7ad3
	k8s.io/api => k8s.io/api v0.20.0
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.20.0
	k8s.io/apimachinery => k8s.io/apimachinery v0.20.0
	k8s.io/apiserver => k8s.io/apiserver v0.20.0
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.20.0
	k8s.io/client-go => github.com/rancher/client-go v1.20.0-rancher.1
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.20.0
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.20.0
	k8s.io/code-generator => k8s.io/code-generator v0.20.0
	k8s.io/component-base => k8s.io/component-base v0.20.0
	k8s.io/component-helpers => k8s.io/component-helpers v0.20.0
	k8s.io/controller-manager => k8s.io/controller-manager v0.20.0
	k8s.io/cri-api => k8s.io/cri-api v0.20.0
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.20.0
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.20.0
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.20.0
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.20.0
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.20.0
	k8s.io/kubectl => k8s.io/kubectl v0.20.0
	k8s.io/kubelet => k8s.io/kubelet v0.20.0
	k8s.io/kubernetes => k8s.io/kubernetes v1.20.0
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.20.0
	k8s.io/metrics => k8s.io/metrics v0.20.0
	k8s.io/mount-utils => k8s.io/mount-utils v0.20.0
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.20.0
)

require (
	github.com/mitchellh/mapstructure v1.2.2
	github.com/pkg/errors v0.9.1
	github.com/rancher/rancher v0.0.0-20210329195251-b2a34d7cef44
	github.com/rancher/rancher/pkg/apis v0.0.0
	github.com/rancher/rancher/pkg/client v0.0.0
	github.com/sirupsen/logrus v1.6.0
	github.com/urfave/cli v1.22.3
	gopkg.in/ldap.v2 v2.5.1
	k8s.io/apimachinery v0.20.0
	k8s.io/client-go v12.0.0+incompatible
)
