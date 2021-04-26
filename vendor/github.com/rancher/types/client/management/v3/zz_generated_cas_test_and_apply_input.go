package client

const (
	CASTestAndApplyInputType           = "casTestAndApplyInput"
	CASTestAndApplyInputFieldCASConfig = "casConfig"
	CASTestAndApplyInputFieldEnabled   = "enabled"
	CASTestAndApplyInputFieldTicket    = "ticket"
)

type CASTestAndApplyInput struct {
	CASConfig *CASConfig `json:"casConfig,omitempty" yaml:"casConfig,omitempty"`
	Enabled   bool       `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Ticket    string     `json:"ticket,omitempty" yaml:"ticket,omitempty"`
}
