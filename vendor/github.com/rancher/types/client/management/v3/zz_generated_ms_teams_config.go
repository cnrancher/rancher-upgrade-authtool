package client

const (
	MSTeamsConfigType             = "msTeamsConfig"
	MSTeamsConfigFieldBasicAuth   = "basic_auth"
	MSTeamsConfigFieldBearerToken = "bearer_token"
	MSTeamsConfigFieldProxyURL    = "proxyUrl"
	MSTeamsConfigFieldURL         = "url"
)

type MSTeamsConfig struct {
	BasicAuth   *BasicAuth `json:"basic_auth,omitempty" yaml:"basic_auth,omitempty"`
	BearerToken string     `json:"bearer_token,omitempty" yaml:"bearer_token,omitempty"`
	ProxyURL    string     `json:"proxyUrl,omitempty" yaml:"proxyUrl,omitempty"`
	URL         string     `json:"url,omitempty" yaml:"url,omitempty"`
}
