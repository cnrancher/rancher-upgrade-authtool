package client

const (
	WebhookConfigType             = "webhookConfig"
	WebhookConfigFieldBasicAuth   = "basic_auth"
	WebhookConfigFieldBearerToken = "bearer_token"
	WebhookConfigFieldProxyURL    = "proxyUrl"
	WebhookConfigFieldURL         = "url"
)

type WebhookConfig struct {
	BasicAuth   *BasicAuth `json:"basic_auth,omitempty" yaml:"basic_auth,omitempty"`
	BearerToken string     `json:"bearer_token,omitempty" yaml:"bearer_token,omitempty"`
	ProxyURL    string     `json:"proxyUrl,omitempty" yaml:"proxyUrl,omitempty"`
	URL         string     `json:"url,omitempty" yaml:"url,omitempty"`
}
