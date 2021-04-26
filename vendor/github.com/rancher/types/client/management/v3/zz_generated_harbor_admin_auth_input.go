package client

const (
	HarborAdminAuthInputType           = "harborAdminAuthInput"
	HarborAdminAuthInputFieldPassword  = "password"
	HarborAdminAuthInputFieldServerURL = "serverURL"
	HarborAdminAuthInputFieldUsername  = "username"
	HarborAdminAuthInputFieldVersion   = "version"
)

type HarborAdminAuthInput struct {
	Password  string `json:"password,omitempty" yaml:"password,omitempty"`
	ServerURL string `json:"serverURL,omitempty" yaml:"serverURL,omitempty"`
	Username  string `json:"username,omitempty" yaml:"username,omitempty"`
	Version   string `json:"version,omitempty" yaml:"version,omitempty"`
}
