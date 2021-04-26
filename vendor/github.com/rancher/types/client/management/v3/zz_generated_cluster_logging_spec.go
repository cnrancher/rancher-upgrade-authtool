package client

const (
	ClusterLoggingSpecType                           = "clusterLoggingSpec"
	ClusterLoggingSpecFieldClusterID                 = "clusterId"
	ClusterLoggingSpecFieldCustomTargetConfig        = "customTargetConfig"
	ClusterLoggingSpecFieldDisplayName               = "displayName"
	ClusterLoggingSpecFieldElasticsearchConfig       = "elasticsearchConfig"
	ClusterLoggingSpecFieldEnableExceptionStackMatch = "enableExceptionStackMatch"
	ClusterLoggingSpecFieldEnableJSONParsing         = "enableJSONParsing"
	ClusterLoggingSpecFieldEnableMultiLineFilter     = "enableMultiLineFilter"
	ClusterLoggingSpecFieldFluentForwarderConfig     = "fluentForwarderConfig"
	ClusterLoggingSpecFieldIncludeSystemComponent    = "includeSystemComponent"
	ClusterLoggingSpecFieldKafkaConfig               = "kafkaConfig"
	ClusterLoggingSpecFieldMultiLineEndRegexp        = "multiLineEndRegexp"
	ClusterLoggingSpecFieldMultiLineStartRegexp      = "multiLineStartRegexp"
	ClusterLoggingSpecFieldOutputFlushInterval       = "outputFlushInterval"
	ClusterLoggingSpecFieldOutputTags                = "outputTags"
	ClusterLoggingSpecFieldSplunkConfig              = "splunkConfig"
	ClusterLoggingSpecFieldSyslogConfig              = "syslogConfig"
)

type ClusterLoggingSpec struct {
	ClusterID                 string                 `json:"clusterId,omitempty" yaml:"clusterId,omitempty"`
	CustomTargetConfig        *CustomTargetConfig    `json:"customTargetConfig,omitempty" yaml:"customTargetConfig,omitempty"`
	DisplayName               string                 `json:"displayName,omitempty" yaml:"displayName,omitempty"`
	ElasticsearchConfig       *ElasticsearchConfig   `json:"elasticsearchConfig,omitempty" yaml:"elasticsearchConfig,omitempty"`
	EnableExceptionStackMatch bool                   `json:"enableExceptionStackMatch,omitempty" yaml:"enableExceptionStackMatch,omitempty"`
	EnableJSONParsing         bool                   `json:"enableJSONParsing,omitempty" yaml:"enableJSONParsing,omitempty"`
	EnableMultiLineFilter     bool                   `json:"enableMultiLineFilter,omitempty" yaml:"enableMultiLineFilter,omitempty"`
	FluentForwarderConfig     *FluentForwarderConfig `json:"fluentForwarderConfig,omitempty" yaml:"fluentForwarderConfig,omitempty"`
	IncludeSystemComponent    *bool                  `json:"includeSystemComponent,omitempty" yaml:"includeSystemComponent,omitempty"`
	KafkaConfig               *KafkaConfig           `json:"kafkaConfig,omitempty" yaml:"kafkaConfig,omitempty"`
	MultiLineEndRegexp        string                 `json:"multiLineEndRegexp,omitempty" yaml:"multiLineEndRegexp,omitempty"`
	MultiLineStartRegexp      string                 `json:"multiLineStartRegexp,omitempty" yaml:"multiLineStartRegexp,omitempty"`
	OutputFlushInterval       int64                  `json:"outputFlushInterval,omitempty" yaml:"outputFlushInterval,omitempty"`
	OutputTags                map[string]string      `json:"outputTags,omitempty" yaml:"outputTags,omitempty"`
	SplunkConfig              *SplunkConfig          `json:"splunkConfig,omitempty" yaml:"splunkConfig,omitempty"`
	SyslogConfig              *SyslogConfig          `json:"syslogConfig,omitempty" yaml:"syslogConfig,omitempty"`
}
