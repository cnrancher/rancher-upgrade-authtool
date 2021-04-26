package client

const (
	AliyunSMSConfigType                 = "aliyunSMSConfig"
	AliyunSMSConfigFieldAccessKeyID     = "accessKeyID"
	AliyunSMSConfigFieldAccessKeySecret = "accessKeySecret"
	AliyunSMSConfigFieldSignName        = "signName"
	AliyunSMSConfigFieldTemplateCode    = "templateCode"
	AliyunSMSConfigFieldTo              = "to"
)

type AliyunSMSConfig struct {
	AccessKeyID     string   `json:"accessKeyID,omitempty" yaml:"accessKeyID,omitempty"`
	AccessKeySecret string   `json:"accessKeySecret,omitempty" yaml:"accessKeySecret,omitempty"`
	SignName        string   `json:"signName,omitempty" yaml:"signName,omitempty"`
	TemplateCode    string   `json:"templateCode,omitempty" yaml:"templateCode,omitempty"`
	To              []string `json:"to,omitempty" yaml:"to,omitempty"`
}
