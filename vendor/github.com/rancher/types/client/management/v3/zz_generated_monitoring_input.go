package client

const (
	MonitoringInputType              = "monitoringInput"
	MonitoringInputFieldAnswers      = "answers"
	MonitoringInputFieldExtraAnswers = "extraAnswers"
	MonitoringInputFieldValuesYaml   = "valuesYaml"
	MonitoringInputFieldVersion      = "version"
)

type MonitoringInput struct {
	Answers      map[string]string `json:"answers,omitempty" yaml:"answers,omitempty"`
	ExtraAnswers map[string]string `json:"extraAnswers,omitempty" yaml:"extraAnswers,omitempty"`
	ValuesYaml   string            `json:"valuesYaml,omitempty" yaml:"valuesYaml,omitempty"`
	Version      string            `json:"version,omitempty" yaml:"version,omitempty"`
}
