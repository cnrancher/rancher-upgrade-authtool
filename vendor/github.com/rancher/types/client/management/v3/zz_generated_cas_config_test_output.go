package client

const (
	CASConfigTestOutputType             = "casConfigTestOutput"
	CASConfigTestOutputFieldRedirectURL = "redirectUrl"
)

type CASConfigTestOutput struct {
	RedirectURL string `json:"redirectUrl,omitempty" yaml:"redirectUrl,omitempty"`
}
