package client

const (
	RDNSProviderConfigType          = "rdnsProviderConfig"
	RDNSProviderConfigFieldETCDUrls = "etcdUrls"
	RDNSProviderConfigFieldSecret   = "secret"
)

type RDNSProviderConfig struct {
	ETCDUrls string `json:"etcdUrls,omitempty" yaml:"etcdUrls,omitempty"`
	Secret   string `json:"secret,omitempty" yaml:"secret,omitempty"`
}
