package client

const (
	PagerdutyConfigType             = "pagerdutyConfig"
	PagerdutyConfigFieldBasicAuth   = "basic_auth"
	PagerdutyConfigFieldBearerToken = "bearer_token"
	PagerdutyConfigFieldProxyURL    = "proxyUrl"
	PagerdutyConfigFieldServiceKey  = "serviceKey"
)

type PagerdutyConfig struct {
	BasicAuth   *BasicAuth `json:"basic_auth,omitempty" yaml:"basic_auth,omitempty"`
	BearerToken string     `json:"bearer_token,omitempty" yaml:"bearer_token,omitempty"`
	ProxyURL    string     `json:"proxyUrl,omitempty" yaml:"proxyUrl,omitempty"`
	ServiceKey  string     `json:"serviceKey,omitempty" yaml:"serviceKey,omitempty"`
}
