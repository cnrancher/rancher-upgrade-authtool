package tool

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"

	managementv3 "github.com/JacieChao/rancher-upgrade-authtool/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/mitchellh/mapstructure"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v32 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v3client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	"github.com/sirupsen/logrus"
	"gomodules.xyz/jsonpatch/v2"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

type LDAPAuthTool struct {
	*AuthUtil `json:",inline"`
	config    *v32.LdapConfig
}

func init() {
	RegisterAuthTool(OpenLDAPAuth, func() AuthTool {
		return &LDAPAuthTool{
			AuthUtil: NewAuthUtil(),
		}
	})
}

func (l *LDAPAuthTool) NewAuthTool(management managementv3.Interface, coreClient v1.CoreV1Interface, client dynamic.Interface) error {
	l.management = management
	l.coreClient = coreClient
	l.client = client
	ldapConfig, caPool, err := GetLDAPConfig(l.client, l.coreClient)
	if err != nil {
		return err
	}
	l.config = ldapConfig
	logrus.Infof("Get OpenLDAP Auth config: %++v", *ldapConfig)
	lConn, err := NewLDAPConn(ldapConfig.Servers, ldapConfig.TLS, ldapConfig.StartTLS, ldapConfig.Port, ldapConfig.ConnectionTimeout, caPool)
	if err != nil {
		return err
	}
	l.conn = lConn
	username := GetUserExternalID(ldapConfig.ServiceAccountDistinguishedName, "")
	err = lConn.Bind(username, ldapConfig.ServiceAccountPassword)
	if err != nil {
		return err
	}
	l.userObjectFilter = fmt.Sprintf("(objectClass=%v)", ldapConfig.UserObjectClass)
	l.groupObjectFilter = fmt.Sprintf("(objectClass=%v)", ldapConfig.GroupObjectClass)
	l.userUniqueAttribute = ldapConfig.UserUniqueIDAttribute
	if l.userUniqueAttribute == "" {
		l.userUniqueAttribute = "entryUUID"
	}
	l.groupUniqueAttribute = ldapConfig.GroupUniqueIDAttribute
	if l.groupUniqueAttribute == "" {
		l.groupUniqueAttribute = "entryUUID"
	}
	l.baseDN = ldapConfig.UserSearchBase
	l.groupSearchDN = ldapConfig.GroupSearchBase
	if l.groupSearchDN == "" {
		l.groupSearchDN = ldapConfig.UserSearchBase
	}
	l.userSearchAttribute = GetUserSearchAttributesForLDAP(ldapConfig, l.userUniqueAttribute)
	l.groupSearchAttribute = GetGroupSearchAttributesForLDAP(ldapConfig, l.groupUniqueAttribute)
	return nil
}

func (l *LDAPAuthTool) DestroyAuthTool() {
	l.conn.Close()
}

func (l *LDAPAuthTool) GetAllowedPrincipals() []string {
	return l.config.AllowedPrincipalIDs
}

func (l *LDAPAuthTool) UpdateAllowedPrincipals(isDryRun bool) error {
	newConfig := l.config.DeepCopy()
	userScopeType := fmt.Sprintf("%s%s", OpenLDAPAuth, UserScope)
	groupScopeType := fmt.Sprintf("%s%s", OpenLDAPAuth, GroupScope)

	newAllowedPrincipals, err := l.prepareAllowedPrincipals(userScopeType, groupScopeType, newConfig.AllowedPrincipalIDs)
	if err != nil {
		return err
	}
	newConfig.AllowedPrincipalIDs = newAllowedPrincipals
	if !isDryRun {
		original, _ := json.Marshal(l.config)
		current, _ := json.Marshal(newConfig)
		patches, err := jsonpatch.CreatePatch(original, current)
		if err != nil {
			return err
		}
		logrus.Infof("Will update new openldap auth config with patches %v", patches)
		patchBytes, _ := json.Marshal(patches)
		_, err = l.management.AuthConfig().Patch(OpenLDAPAuth, types.JSONPatchType, patchBytes)
		if err != nil {
			return err
		}
	} else {
		logrus.Infof("FOR DRY_RUN:: Will update new openldap auth config with: %++v", newConfig)
	}

	return nil
}

func (l *LDAPAuthTool) UpdateUserPrincipals(list map[string]v3.User, isDryRun bool) {
	preparedUsers := l.prepareUsers(list, OpenLDAPAuth)
	l.UpdateUser(preparedUsers, isDryRun)
}

func (l *LDAPAuthTool) UpdatePermissionPrincipals(isDryRun bool, grbList []v3.GlobalRoleBinding, crtbList []v3.ClusterRoleTemplateBinding, prtbList []v3.ProjectRoleTemplateBinding) {
	groupScopeType := fmt.Sprintf("%s%s://", OpenLDAPAuth, GroupScope)
	userScopeType := fmt.Sprintf("%s%s://", OpenLDAPAuth, UserScope)
	preparedGRB := l.prepareGRB(grbList, groupScopeType)
	l.UpdateGRB(preparedGRB, isDryRun)

	preparedCRTB := l.prepareCRTB(crtbList, userScopeType, groupScopeType)
	l.UpdateCRTB(preparedCRTB, isDryRun)

	preparedPRTB := l.preparePRTB(prtbList, userScopeType, groupScopeType)
	l.UpdatePRTB(preparedPRTB, isDryRun)
}

func (l *LDAPAuthTool) PrintManualCheckData() {
	l.print()
}

func GetLDAPConfig(client dynamic.Interface, coreClient v1.CoreV1Interface) (*v32.LdapConfig, *x509.CertPool, error) {
	var gvr = schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "authconfigs",
	}
	authConfigObj, err := client.Resource(gvr).Get(context.TODO(), OpenLDAPAuth, metav1.GetOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve openldap config, error: %v", err)
	}
	storedLdapConfigMap := authConfigObj.UnstructuredContent()
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
