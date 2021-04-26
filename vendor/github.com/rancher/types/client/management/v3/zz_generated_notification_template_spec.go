package client

const (
	NotificationTemplateSpecType           = "notificationTemplateSpec"
	NotificationTemplateSpecFieldClusterID = "clusterId"
	NotificationTemplateSpecFieldContent   = "content"
	NotificationTemplateSpecFieldEnabled   = "enabled"
)

type NotificationTemplateSpec struct {
	ClusterID string `json:"clusterId,omitempty" yaml:"clusterId,omitempty"`
	Content   string `json:"content,omitempty" yaml:"content,omitempty"`
	Enabled   bool   `json:"enabled,omitempty" yaml:"enabled,omitempty"`
}
