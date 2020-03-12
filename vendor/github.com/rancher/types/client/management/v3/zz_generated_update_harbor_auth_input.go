package client

const (
	UpdateHarborAuthInputType             = "updateHarborAuthInput"
	UpdateHarborAuthInputFieldEmail       = "email"
	UpdateHarborAuthInputFieldNewPassword = "newPassword"
	UpdateHarborAuthInputFieldOldPassword = "oldPassword"
)

type UpdateHarborAuthInput struct {
	Email       string `json:"email,omitempty" yaml:"email,omitempty"`
	NewPassword string `json:"newPassword,omitempty" yaml:"newPassword,omitempty"`
	OldPassword string `json:"oldPassword,omitempty" yaml:"oldPassword,omitempty"`
}
