package client

const (
	ServiceNowConfigType             = "serviceNowConfig"
	ServiceNowConfigFieldBasicAuth   = "basic_auth"
	ServiceNowConfigFieldBearerToken = "bearer_token"
	ServiceNowConfigFieldProxyURL    = "proxyUrl"
	ServiceNowConfigFieldURL         = "url"
)

type ServiceNowConfig struct {
	BasicAuth   *BasicAuth `json:"basic_auth,omitempty" yaml:"basic_auth,omitempty"`
	BearerToken string     `json:"bearer_token,omitempty" yaml:"bearer_token,omitempty"`
	ProxyURL    string     `json:"proxyUrl,omitempty" yaml:"proxyUrl,omitempty"`
	URL         string     `json:"url,omitempty" yaml:"url,omitempty"`
}
