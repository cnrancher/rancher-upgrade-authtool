package tool

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mitchellh/mapstructure"
	v32 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v3client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	corev1 "github.com/rancher/rancher/pkg/generated/norman/core/v1"
	managementv3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
	"gomodules.xyz/jsonpatch/v2"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

type ADAuthTool struct {
	*AuthUtil `json:",inline"`
	config    *v32.ActiveDirectoryConfig
}

func init() {
	RegisterAuthTool(ActiveDirectoryAuth, func() AuthTool {
		return &ADAuthTool{
			AuthUtil: NewAuthUtil(),
		}
	})
}

func (au *ADAuthTool) NewAuthTool(management managementv3.Interface, coreClient corev1.SecretInterface) error {
	au.management = management
	au.secretClient = coreClient
	adConfig, caPool, err := GetActiveDirectoryConfig(management, coreClient)
	if err != nil {
		return err
	}
	au.config = adConfig
	logrus.Infof("Get ActiveDirectory Auth config: %++v", *adConfig)
	lConn, err := NewLDAPConn(adConfig.Servers, adConfig.TLS, adConfig.StartTLS, adConfig.Port, adConfig.ConnectionTimeout, caPool)
	if err != nil {
		return err
	}
	au.conn = lConn
	au.userObjectFilter = fmt.Sprintf("(objectClass=%v)", adConfig.UserObjectClass)
	au.groupObjectFilter = fmt.Sprintf("(objectClass=%v)", adConfig.GroupObjectClass)
	au.userUniqueAttribute = adConfig.UserUniqueIDAttribute
	if au.userUniqueAttribute == "" {
		au.userUniqueAttribute = "objectGUID"
	}
	au.groupUniqueAttribute = adConfig.GroupUniqueIDAttribute
	if au.groupUniqueAttribute == "" {
		au.groupUniqueAttribute = "objectGUID"
	}
	au.baseDN = adConfig.UserSearchBase
	au.groupSearchDN = adConfig.GroupSearchBase
	if au.groupSearchDN == "" {
		au.groupSearchDN = adConfig.UserSearchBase
	}
	au.userSearchAttribute = GetUserSearchAttributes(adConfig, au.userUniqueAttribute)
	au.groupSearchAttribute = GetGroupSearchAttributes(adConfig, au.groupUniqueAttribute)
	username := GetUserExternalID(adConfig.ServiceAccountUsername, adConfig.DefaultLoginDomain)
	err = lConn.Bind(username, adConfig.ServiceAccountPassword)
	if err != nil {
		return err
	}
	return nil
}

func (au *ADAuthTool) DestroyAuthTool() {
	au.conn.Close()
}

func (au *ADAuthTool) GetAllowedPrincipals() []string {
	return au.config.AllowedPrincipalIDs
}

func (au *ADAuthTool) UpdateAllowedPrincipals(isDryRun bool) error {
	newConfig := au.config.DeepCopy()
	userScopeType := fmt.Sprintf("%s%s", ActiveDirectoryAuth, UserScope)
	groupScopeType := fmt.Sprintf("%s%s", ActiveDirectoryAuth, GroupScope)

	newAllowedPrincipals, err := au.prepareAllowedPrincipals(userScopeType, groupScopeType, newConfig.AllowedPrincipalIDs)
	if err != nil {
		return err
	}
	newConfig.AllowedPrincipalIDs = newAllowedPrincipals
	if !isDryRun {
		original, _ := json.Marshal(au.config)
		current, _ := json.Marshal(newConfig)
		patches, err := jsonpatch.CreatePatch(original, current)
		if err != nil {
			return err
		}
		logrus.Infof("Will update new activedirectory auth config with patches %v", patches)
		patchBytes, _ := json.Marshal(patches)
		_, err = au.management.AuthConfigs("").ObjectClient().Patch(ActiveDirectoryAuth, au.config, types.JSONPatchType, patchBytes)
		if err != nil {
			return err
		}
	} else {
		logrus.Infof("FOR DRY_RUN:: Will update new openldap auth config with: %++v", newConfig)
	}

	return nil
}

func (au *ADAuthTool) UpdateUserPrincipals(list map[string]v32.User, isDryRun bool) {
	preparedUsers := au.prepareUsers(list, ActiveDirectoryAuth)
	au.UpdateUser(preparedUsers, isDryRun)
}

func (au *ADAuthTool) UpdatePermissionPrincipals(isDryRun bool, grbList []v32.GlobalRoleBinding, crtbList []v32.ClusterRoleTemplateBinding, prtbList []v32.ProjectRoleTemplateBinding) {
	groupScopeType := fmt.Sprintf("%s%s://", ActiveDirectoryAuth, GroupScope)
	userScopeType := fmt.Sprintf("%s%s://", ActiveDirectoryAuth, UserScope)
	preparedGRB := au.prepareGRB(grbList, groupScopeType)
	au.UpdateGRB(preparedGRB, isDryRun)

	preparedCRTB := au.prepareCRTB(crtbList, userScopeType, groupScopeType)
	au.UpdateCRTB(preparedCRTB, isDryRun)

	preparedPRTB := au.preparePRTB(prtbList, userScopeType, groupScopeType)
	au.UpdatePRTB(preparedPRTB, isDryRun)
}

func (au *ADAuthTool) PrintManualCheckData() {
	au.print()
}

func GetActiveDirectoryConfig(management managementv3.Interface, coreClient corev1.SecretInterface) (*v32.ActiveDirectoryConfig, *x509.CertPool, error) {
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
