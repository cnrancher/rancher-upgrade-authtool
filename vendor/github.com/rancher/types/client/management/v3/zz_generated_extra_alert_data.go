package client

const (
	ExtraAlertDataType             = "extraAlertData"
	ExtraAlertDataFieldSourceType  = "sourceType"
	ExtraAlertDataFieldSourceValue = "sourceValue"
	ExtraAlertDataFieldTargetKey   = "targetKey"
	ExtraAlertDataFieldTargetType  = "targetType"
)

type ExtraAlertData struct {
	SourceType  string `json:"sourceType,omitempty" yaml:"sourceType,omitempty"`
	SourceValue string `json:"sourceValue,omitempty" yaml:"sourceValue,omitempty"`
	TargetKey   string `json:"targetKey,omitempty" yaml:"targetKey,omitempty"`
	TargetType  string `json:"targetType,omitempty" yaml:"targetType,omitempty"`
}
