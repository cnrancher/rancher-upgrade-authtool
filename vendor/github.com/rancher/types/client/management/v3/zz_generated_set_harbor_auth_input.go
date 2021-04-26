package client

const (
	SetHarborAuthInputType          = "setHarborAuthInput"
	SetHarborAuthInputFieldEmail    = "email"
	SetHarborAuthInputFieldPassword = "password"
	SetHarborAuthInputFieldUsername = "username"
)

type SetHarborAuthInput struct {
	Email    string `json:"email,omitempty" yaml:"email,omitempty"`
	Password string `json:"password,omitempty" yaml:"password,omitempty"`
	Username string `json:"username,omitempty" yaml:"username,omitempty"`
}
