package client

const (
	BasicAuthType          = "basicAuth"
	BasicAuthFieldPassword = "password"
	BasicAuthFieldUsername = "username"
)

type BasicAuth struct {
	Password string `json:"password,omitempty" yaml:"password,omitempty"`
	Username string `json:"username,omitempty" yaml:"username,omitempty"`
}
