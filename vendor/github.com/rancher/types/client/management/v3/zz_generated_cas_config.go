package client

const (
	CASConfigType                     = "casConfig"
	CASConfigFieldAccessMode          = "accessMode"
	CASConfigFieldAllowedPrincipalIDs = "allowedPrincipalIds"
	CASConfigFieldAnnotations         = "annotations"
	CASConfigFieldConnectionTimeout   = "connectionTimeout"
	CASConfigFieldCreated             = "created"
	CASConfigFieldCreatorID           = "creatorId"
	CASConfigFieldEnabled             = "enabled"
	CASConfigFieldHostname            = "hostname"
	CASConfigFieldLabels              = "labels"
	CASConfigFieldLoginEndpoint       = "loginEndpoint"
	CASConfigFieldLogoutEndpoint      = "logoutEndpoint"
	CASConfigFieldName                = "name"
	CASConfigFieldOwnerReferences     = "ownerReferences"
	CASConfigFieldPort                = "port"
	CASConfigFieldRemoved             = "removed"
	CASConfigFieldService             = "service"
	CASConfigFieldServiceValidate     = "serviceValidate"
	CASConfigFieldTLS                 = "tls"
	CASConfigFieldType                = "type"
	CASConfigFieldUUID                = "uuid"
)

type CASConfig struct {
	AccessMode          string            `json:"accessMode,omitempty" yaml:"accessMode,omitempty"`
	AllowedPrincipalIDs []string          `json:"allowedPrincipalIds,omitempty" yaml:"allowedPrincipalIds,omitempty"`
	Annotations         map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	ConnectionTimeout   int64             `json:"connectionTimeout,omitempty" yaml:"connectionTimeout,omitempty"`
	Created             string            `json:"created,omitempty" yaml:"created,omitempty"`
	CreatorID           string            `json:"creatorId,omitempty" yaml:"creatorId,omitempty"`
	Enabled             bool              `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Hostname            string            `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	Labels              map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	LoginEndpoint       string            `json:"loginEndpoint,omitempty" yaml:"loginEndpoint,omitempty"`
	LogoutEndpoint      string            `json:"logoutEndpoint,omitempty" yaml:"logoutEndpoint,omitempty"`
	Name                string            `json:"name,omitempty" yaml:"name,omitempty"`
	OwnerReferences     []OwnerReference  `json:"ownerReferences,omitempty" yaml:"ownerReferences,omitempty"`
	Port                string            `json:"port,omitempty" yaml:"port,omitempty"`
	Removed             string            `json:"removed,omitempty" yaml:"removed,omitempty"`
	Service             string            `json:"service,omitempty" yaml:"service,omitempty"`
	ServiceValidate     string            `json:"serviceValidate,omitempty" yaml:"serviceValidate,omitempty"`
	TLS                 bool              `json:"tls,omitempty" yaml:"tls,omitempty"`
	Type                string            `json:"type,omitempty" yaml:"type,omitempty"`
	UUID                string            `json:"uuid,omitempty" yaml:"uuid,omitempty"`
}
