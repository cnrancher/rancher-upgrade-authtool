package client

const (
	SetHarborAuthInputType          = "setHarborAuthInput"
	SetHarborAuthInputFieldEmail    = "email"
	SetHarborAuthInputFieldPassword = "password"
)

type SetHarborAuthInput struct {
	Email    string `json:"email,omitempty" yaml:"email,omitempty"`
	Password string `json:"password,omitempty" yaml:"password,omitempty"`
}
