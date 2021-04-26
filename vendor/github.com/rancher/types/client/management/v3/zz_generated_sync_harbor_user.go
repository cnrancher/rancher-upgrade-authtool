package client

const (
	SyncHarborUserType              = "syncHarborUser"
	SyncHarborUserFieldAuthProvider = "provider"
	SyncHarborUserFieldPassword     = "password"
	SyncHarborUserFieldUsername     = "username"
)

type SyncHarborUser struct {
	AuthProvider string `json:"provider,omitempty" yaml:"provider,omitempty"`
	Password     string `json:"password,omitempty" yaml:"password,omitempty"`
	Username     string `json:"username,omitempty" yaml:"username,omitempty"`
}
