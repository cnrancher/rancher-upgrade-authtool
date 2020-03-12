package client

const (
	ClusterSpecBaseType                                     = "clusterSpecBase"
	ClusterSpecBaseFieldAgentImageOverride                  = "agentImageOverride"
	ClusterSpecBaseFieldDefaultClusterRoleForProjectMembers = "defaultClusterRoleForProjectMembers"
	ClusterSpecBaseFieldDefaultPodSecurityPolicyTemplateID  = "defaultPodSecurityPolicyTemplateId"
	ClusterSpecBaseFieldDesiredAgentImage                   = "desiredAgentImage"
	ClusterSpecBaseFieldDesiredAuthImage                    = "desiredAuthImage"
	ClusterSpecBaseFieldDockerRootDir                       = "dockerRootDir"
	ClusterSpecBaseFieldEnableClusterAlerting               = "enableClusterAlerting"
	ClusterSpecBaseFieldEnableClusterMonitoring             = "enableClusterMonitoring"
	ClusterSpecBaseFieldEnableGPUManagement                 = "enableGPUManagement"
	ClusterSpecBaseFieldEnableNetworkPolicy                 = "enableNetworkPolicy"
	ClusterSpecBaseFieldGPUSchedulerNodePort                = "gpuSchedulerNodePort"
	ClusterSpecBaseFieldLocalClusterAuthEndpoint            = "localClusterAuthEndpoint"
	ClusterSpecBaseFieldRancherKubernetesEngineConfig       = "rancherKubernetesEngineConfig"
	ClusterSpecBaseFieldWindowsPreferedCluster              = "windowsPreferedCluster"
)

type ClusterSpecBase struct {
	AgentImageOverride                  string                         `json:"agentImageOverride,omitempty" yaml:"agentImageOverride,omitempty"`
	DefaultClusterRoleForProjectMembers string                         `json:"defaultClusterRoleForProjectMembers,omitempty" yaml:"defaultClusterRoleForProjectMembers,omitempty"`
	DefaultPodSecurityPolicyTemplateID  string                         `json:"defaultPodSecurityPolicyTemplateId,omitempty" yaml:"defaultPodSecurityPolicyTemplateId,omitempty"`
	DesiredAgentImage                   string                         `json:"desiredAgentImage,omitempty" yaml:"desiredAgentImage,omitempty"`
	DesiredAuthImage                    string                         `json:"desiredAuthImage,omitempty" yaml:"desiredAuthImage,omitempty"`
	DockerRootDir                       string                         `json:"dockerRootDir,omitempty" yaml:"dockerRootDir,omitempty"`
	EnableClusterAlerting               bool                           `json:"enableClusterAlerting,omitempty" yaml:"enableClusterAlerting,omitempty"`
	EnableClusterMonitoring             bool                           `json:"enableClusterMonitoring,omitempty" yaml:"enableClusterMonitoring,omitempty"`
	EnableGPUManagement                 bool                           `json:"enableGPUManagement,omitempty" yaml:"enableGPUManagement,omitempty"`
	EnableNetworkPolicy                 *bool                          `json:"enableNetworkPolicy,omitempty" yaml:"enableNetworkPolicy,omitempty"`
	GPUSchedulerNodePort                string                         `json:"gpuSchedulerNodePort,omitempty" yaml:"gpuSchedulerNodePort,omitempty"`
	LocalClusterAuthEndpoint            *LocalClusterAuthEndpoint      `json:"localClusterAuthEndpoint,omitempty" yaml:"localClusterAuthEndpoint,omitempty"`
	RancherKubernetesEngineConfig       *RancherKubernetesEngineConfig `json:"rancherKubernetesEngineConfig,omitempty" yaml:"rancherKubernetesEngineConfig,omitempty"`
	WindowsPreferedCluster              bool                           `json:"windowsPreferedCluster,omitempty" yaml:"windowsPreferedCluster,omitempty"`
}
