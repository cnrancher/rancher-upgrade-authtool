package tool

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	v32 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v3client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	corev1 "github.com/rancher/rancher/pkg/generated/norman/core/v1"
	v3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	ldapv2 "gopkg.in/ldap.v2"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	ActiveDirectoryAuth     = "activedirectory"
	OpenLDAPAuth            = "openldap"
	UserScope               = "_user"
	GroupScope              = "_group"
	DefaultTimeout          = 5000
	NoResultFoundError      = "No identities can be retrieved"
	MutipleResultFoundError = "Get more than one results"
	SecretsNamespace        = "cattle-global-data"
	UserUIDScope            = "_user_uid"
	GroupUIDScope           = "_group_uid"
)

type Config struct {
	Server         string
	Port           int64
	UserName       string
	Password       string
	BaseDN         string
	KubeConfig     string
	AuthType       string
	AuthConfigType string
	IsDryRun       bool
	LogFilePath    string
}

func GetConfig(c *Config) (*rest.Config, error) {
	if c.KubeConfig != "" {
		return clientcmd.BuildConfigFromFlags("", c.KubeConfig)
	}

	if config, err := rest.InClusterConfig(); err == nil {
		if config.BearerToken == "" {
			tokenBytes, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
			if err == nil {
				config.BearerToken = string(tokenBytes)
			}
		}
		return config, nil
	}
	return nil, fmt.Errorf("failed to get kube config")
}

func GetDNAndScopeFromPrincipalID(principalID string) (string, string, error) {
	parts := strings.SplitN(principalID, ":", 2)
	if len(parts) != 2 {
		return "", "", errors.Errorf("invalid id %v", principalID)
	}
	scope := parts[0]
	externalID := strings.TrimPrefix(parts[1], "//")
	return externalID, scope, nil
}

func NewLDAPConn(servers []string, TLS, startTLS bool, port int64, connectionTimeout int64, caPool *x509.CertPool) (*ldapv2.Conn, error) {
	var lConn *ldapv2.Conn
	var err error
	var tlsConfig *tls.Config
	ldapv2.DefaultTimeout = time.Duration(connectionTimeout) * time.Millisecond
	// TODO implment multi-server support
	if len(servers) != 1 {
		return nil, errors.New("invalid server config. only exactly 1 server is currently supported")
	}
	server := servers[0]
	tlsConfig = &tls.Config{RootCAs: caPool, InsecureSkipVerify: false, ServerName: server}
	if TLS {
		lConn, err = ldapv2.DialTLS("tcp", fmt.Sprintf("%s:%d", server, port), tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("Error creating ssl connection: %v", err)
		}
	} else if startTLS {
		lConn, err = ldapv2.Dial("tcp", fmt.Sprintf("%s:%d", server, port))
		if err != nil {
			return nil, fmt.Errorf("Error creating connection for startTLS: %v", err)
		}
		if err := lConn.StartTLS(tlsConfig); err != nil {
			return nil, fmt.Errorf("Error upgrading startTLS connection: %v", err)
		}
	} else {
		lConn, err = ldapv2.Dial("tcp", fmt.Sprintf("%s:%d", server, port))
		if err != nil {
			return nil, fmt.Errorf("Error creating connection: %v", err)
		}
	}

	lConn.SetTimeout(time.Duration(connectionTimeout) * time.Millisecond)

	return lConn, nil
}

func GetActiveDirectoryConfig(management v3.Interface, coreClient corev1.SecretInterface) (*v32.ActiveDirectoryConfig, *x509.CertPool, error) {
	authConfigObj, err := management.AuthConfigs("").ObjectClient().UnstructuredClient().Get("activedirectory", metav1.GetOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve ActiveDirectoryConfig, error: %v", err)
	}

	u, ok := authConfigObj.(runtime.Unstructured)
	if !ok {
		return nil, nil, fmt.Errorf("failed to retrieve ActiveDirectoryConfig, cannot read k8s Unstructured data")
	}
	storedADConfigMap := u.UnstructuredContent()

	storedADConfig := &v32.ActiveDirectoryConfig{}
	mapstructure.Decode(storedADConfigMap, storedADConfig)

	metadataMap, ok := storedADConfigMap["metadata"].(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("failed to retrieve ActiveDirectoryConfig metadata, cannot read k8s Unstructured data")
	}

	typemeta := &metav1.ObjectMeta{}
	mapstructure.Decode(metadataMap, typemeta)
	storedADConfig.ObjectMeta = *typemeta

	if storedADConfig.ServiceAccountPassword != "" {
		value, err := ReadFromSecret(coreClient, storedADConfig.ServiceAccountPassword,
			strings.ToLower(v3client.ActiveDirectoryConfigFieldServiceAccountPassword))
		if err != nil {
			return nil, nil, err
		}
		storedADConfig.ServiceAccountPassword = value
	}

	pool, err := newCAPool(storedADConfig.Certificate)
	if err != nil {
		return nil, nil, err
	}

	return storedADConfig, pool, nil
}

func GetLDAPConfig(management v3.Interface, coreClient corev1.SecretInterface) (*v32.LdapConfig, *x509.CertPool, error) {
	authConfigObj, err := management.AuthConfigs("").ObjectClient().UnstructuredClient().Get("openldap", metav1.GetOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve openldap config, error: %v", err)
	}

	u, ok := authConfigObj.(runtime.Unstructured)
	if !ok {
		return nil, nil, fmt.Errorf("failed to retrieve openldap config, cannot read k8s Unstructured data")
	}
	storedLdapConfigMap := u.UnstructuredContent()
	storedLdapConfig := &v3.LdapConfig{}

	mapstructure.Decode(storedLdapConfigMap, storedLdapConfig)
	metadataMap, ok := storedLdapConfigMap["metadata"].(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("failed to retrieve openldap metadata, cannot read k8s Unstructured data")
	}
	objectMeta := &metav1.ObjectMeta{}
	mapstructure.Decode(metadataMap, objectMeta)
	storedLdapConfig.ObjectMeta = *objectMeta

	pool, err := newCAPool(storedLdapConfig.Certificate)
	if err != nil {
		return nil, nil, err
	}

	if storedLdapConfig.ServiceAccountPassword != "" {
		value, err := ReadFromSecret(coreClient, storedLdapConfig.ServiceAccountPassword,
			strings.ToLower(v3client.LdapConfigFieldServiceAccountPassword))
		if err != nil {
			return nil, nil, err
		}
		storedLdapConfig.ServiceAccountPassword = value
	}

	return storedLdapConfig, pool, nil
}

func GetUserExternalID(username string, loginDomain string) string {
	if strings.Contains(username, "\\") {
		return username
	} else if loginDomain != "" {
		return loginDomain + "\\" + username
	}
	return username
}

func GetUserSearchAttributes(config *v32.ActiveDirectoryConfig, uidAttribute string) []string {
	userSearchAttributes := []string{
		"memberOf",
		config.UserLoginAttribute,
		config.UserNameAttribute,
		uidAttribute}
	return userSearchAttributes
}

func GetGroupSearchAttributes(config *v32.ActiveDirectoryConfig, uidAttribute string) []string {
	groupSeachAttributes := []string{"memberOf",
		"objectClass",
		config.GroupObjectClass,
		config.UserLoginAttribute,
		config.GroupNameAttribute,
		config.GroupSearchAttribute,
		uidAttribute}
	return groupSeachAttributes
}

func GetUserSearchAttributesForLDAP(config *v32.LdapConfig, uidAttribute string) []string {
	userSearchAttributes := []string{"dn", config.UserMemberAttribute,
		"objectClass",
		config.UserObjectClass,
		config.UserLoginAttribute,
		config.UserNameAttribute,
		config.UserEnabledAttribute,
		uidAttribute}
	return userSearchAttributes
}

func GetGroupSearchAttributesForLDAP(config *v32.LdapConfig, uidAttribute string) []string {
	groupSeachAttributes := []string{config.GroupMemberUserAttribute,
		config.GroupMemberMappingAttribute,
		"objectClass",
		config.GroupObjectClass,
		config.UserLoginAttribute,
		config.GroupNameAttribute,
		config.GroupSearchAttribute,
		uidAttribute}
	return groupSeachAttributes
}

func GetUsersForUpdate(management v3.Interface, authType string) (map[string]v32.User, error) {
	userList, err := management.Users("").List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	beforeUpdate := map[string]v3.User{}
	for _, user := range userList.Items {
		principalIDs := user.PrincipalIDs
		for _, principalID := range principalIDs {
			if strings.HasPrefix(principalID, authType) {
				beforeUpdate[user.Name] = user
				break
			}
		}
	}

	return beforeUpdate, nil
}

func newCAPool(cert string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	pool.AppendCertsFromPEM([]byte(cert))
	return pool, nil
}

func ReadFromSecret(secrets corev1.SecretInterface, secretInfo string, field string) (string, error) {
	if strings.HasPrefix(secretInfo, SecretsNamespace) {
		split := strings.SplitN(secretInfo, ":", 2)
		if len(split) == 2 {
			secret, err := secrets.GetNamespaced(split[0], split[1], metav1.GetOptions{})
			if err != nil {
				return "", fmt.Errorf("error getting secret %s %v", secretInfo, err)
			}
			for key, val := range secret.Data {
				if key == field {
					return string(val), nil
				}
			}
		}
	}
	return secretInfo, nil
}
