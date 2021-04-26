package v3

import (
	"bytes"
	"encoding/gob"

	"github.com/rancher/norman/types"
	"github.com/sirupsen/logrus"

	v1 "k8s.io/api/core/v1"
	extv1beta1 "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type RelatedSourceInterface map[string]interface{}

func (m *RelatedSourceInterface) DeepCopy() *RelatedSourceInterface {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)
	err := enc.Encode(m)
	if err != nil {
		logrus.Errorf("error while deep copying RelatedSourceInterface %v", err)
		return nil
	}

	var copy RelatedSourceInterface
	err = dec.Decode(&copy)
	if err != nil {
		logrus.Errorf("error while deep copying RelatedSourceInterface %v", err)
		return nil
	}

	return &copy
}

type CloneApp struct {
	types.Namespaced
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Target                    CloneTarget               `json:"target" norman:"required"`
	Workload                  Workload                  `json:"workload" norman:"required"`
	SecretList                []*RelatedSourceInterface `json:"secretList,omitempty"`
	DockerCredentialList      []*RelatedSourceInterface `json:"credentialList,omitempty"`
	CertificateList           []*RelatedSourceInterface `json:"certificateList,omitempty"`
	ConfigMapList             []v1.ConfigMap            `json:"configMapList,omitempty"`
	PersistentVolumeClaimList []*RelatedSourceInterface `json:"pvcList,omitempty"`
	IngressList               []extv1beta1.Ingress      `json:"ingressList,omitempty"`
	ServiceList               []*RelatedSourceInterface `json:"serviceList,omitempty"`
}

type CloneTarget struct {
	Project   string `json:"project,omitempty" norman:"type=reference[project],required"`
	Namespace string `json:"namespace,omitempty" norman:"type=reference[namespace],required"`
}
