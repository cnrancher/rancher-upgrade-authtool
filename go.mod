module github.com/JacieChao/rancher-upgrade-authtool

go 1.19

replace (
	github.com/rancher/rancher/pkg/apis => github.com/cnrancher/pandaria/pkg/apis v0.0.0-20230711004506-41ff3705d76e
	github.com/rancher/rancher/pkg/client => github.com/cnrancher/pandaria/pkg/client v0.0.0-20230711004506-41ff3705d76e
	k8s.io/api => k8s.io/api v0.25.11
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.25.11
	k8s.io/apimachinery => k8s.io/apimachinery v0.25.11
	k8s.io/apiserver => k8s.io/apiserver v0.25.11
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.25.11
	k8s.io/client-go => github.com/rancher/client-go v1.25.4-rancher1
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.25.11
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.25.11
	k8s.io/code-generator => k8s.io/code-generator v0.25.11
	k8s.io/component-base => k8s.io/component-base v0.25.11
	k8s.io/component-helpers => k8s.io/component-helpers v0.25.11
	k8s.io/controller-manager => k8s.io/controller-manager v0.25.11
	k8s.io/cri-api => k8s.io/cri-api v0.25.11
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.25.11
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.25.11
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.25.11
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.25.11
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.25.11
	k8s.io/kubectl => k8s.io/kubectl v0.25.11
	k8s.io/kubelet => k8s.io/kubelet v0.25.11
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.25.11
	k8s.io/metrics => k8s.io/metrics v0.25.11
	k8s.io/mount-utils => k8s.io/mount-utils v0.25.11
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.25.11
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.25.11
)

require (
	github.com/go-ldap/ldap/v3 v3.4.1
	github.com/mitchellh/mapstructure v1.5.0
	github.com/pkg/errors v0.9.1
	github.com/rancher/lasso v0.0.0-20221227210133-6ea88ca2fbcc
	github.com/rancher/rancher/pkg/apis v0.0.0
	github.com/rancher/rancher/pkg/client v0.0.0
	github.com/rancher/wrangler v1.1.1
	github.com/sirupsen/logrus v1.9.3
	github.com/urfave/cli v1.22.9
	gomodules.xyz/jsonpatch/v2 v2.2.0
	k8s.io/apimachinery v0.25.11
	k8s.io/client-go v12.0.0+incompatible
)

require (
	github.com/Azure/go-ntlmssp v0.0.0-20200615164410-66371956d46c // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/cnrancher/ack-operator v0.0.5-0.20230310081604-5534e781bb33 // indirect
	github.com/cnrancher/tke-operator v0.0.0-20230324031424-c87fae4e1716 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/emicklei/go-restful/v3 v3.10.1 // indirect
	github.com/evanphx/json-patch v4.12.0+incompatible // indirect
	github.com/ghodss/yaml v1.0.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.3 // indirect
	github.com/go-logr/logr v1.2.4 // indirect
	github.com/go-openapi/jsonpointer v0.19.6 // indirect
	github.com/go-openapi/jsonreference v0.20.1 // indirect
	github.com/go-openapi/swag v0.22.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/gnostic v0.5.7-v3refs // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/gorilla/websocket v1.4.2 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_golang v1.14.0 // indirect
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/common v0.37.0 // indirect
	github.com/prometheus/procfs v0.8.0 // indirect
	github.com/rancher/aks-operator v1.1.2 // indirect
	github.com/rancher/eks-operator v1.2.1 // indirect
	github.com/rancher/fleet/pkg/apis v0.0.0-20230605094423-ddbb43505e80 // indirect
	github.com/rancher/gke-operator v1.1.5 // indirect
	github.com/rancher/norman v0.0.0-20230426211126-d3552b018687 // indirect
	github.com/rancher/rke v1.4.6 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/crypto v0.10.0 // indirect
	golang.org/x/mod v0.10.0 // indirect
	golang.org/x/net v0.11.0 // indirect
	golang.org/x/oauth2 v0.0.0-20220628200809-02e64fa58f26 // indirect
	golang.org/x/sync v0.2.0 // indirect
	golang.org/x/sys v0.9.0 // indirect
	golang.org/x/term v0.9.0 // indirect
	golang.org/x/text v0.10.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/tools v0.9.3 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/api v0.25.11 // indirect
	k8s.io/apiserver v0.25.11 // indirect
	k8s.io/code-generator v0.27.1 // indirect
	k8s.io/gengo v0.0.0-20220902162205-c0856e24416d // indirect
	k8s.io/klog/v2 v2.90.1 // indirect
	k8s.io/kube-openapi v0.0.0-20230308215209-15aac26d736a // indirect
	k8s.io/kubernetes v1.25.11 // indirect
	k8s.io/utils v0.0.0-20230209194617-a36077c30491 // indirect
	sigs.k8s.io/cli-utils v0.27.0 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)
