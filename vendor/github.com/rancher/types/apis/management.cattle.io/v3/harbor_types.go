package v3

type SyncHarborUser struct {
	Username     string `json:"username" norman:"type=string,required"`
	Password     string `json:"password" norman:"type=string,required"`
	AuthProvider string `json:"provider" norman:"type=string,required"`
}

type SetHarborAuthInput struct {
	Password string `json:"password" norman:"type=string,required"`
	Email    string `json:"email" norman:"type=string,required"`
	Username string `json:"username" norman:"type=string,required"`
}

type UpdateHarborAuthInput struct {
	OldPassword string `json:"oldPassword" norman:"type=string"`
	NewPassword string `json:"newPassword" norman:"type=string"`
	Email       string `json:"email" norman:"type=string"`
}

type HarborAdminAuthInput struct {
	ServerURL string `json:"serverURL" norman:"type=string,required"`
	Password  string `json:"password" norman:"type=password,required"`
	Username  string `json:"username" norman:"type=string,required"`
	Version   string `json:"version" norman:"type=string"`
}
