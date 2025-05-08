package tool

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cnrancher/rancher-upgrade-authtool/client"
	v32 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v3client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	"github.com/rancher/wrangler/v3/pkg/unstructured"
	"github.com/sirupsen/logrus"
	"gomodules.xyz/jsonpatch/v2"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
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

func (au *ADAuthTool) NewAuthTool(cli *client.Clients) error {
	au.cli = cli
	adConfig, caPool, err := GetActiveDirectoryConfig(au.cli)
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
	err = au.conn.Bind(username, adConfig.ServiceAccountPassword)
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

func (au *ADAuthTool) UpdateAllowedPrincipals(ctx context.Context, isDryRun bool) error {
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
		err = au.cli.AuthConfigs.Patch(ctx, "", ActiveDirectoryAuth, types.JSONPatchType, patchBytes, nil, metav1.PatchOptions{})
		if err != nil {
			return err
		}
	} else {
		logrus.Infof("FOR DRY_RUN:: Will update new openldap auth config with: %++v", newConfig)
	}

	return nil
}

func (au *ADAuthTool) UpdateUserPrincipals(ctx context.Context, list map[string]v32.User, isDryRun bool) {
	preparedUsers := au.prepareUsers(ctx, list, ActiveDirectoryAuth)
	au.UpdateUser(ctx, preparedUsers, isDryRun)
}

func (au *ADAuthTool) UpdatePermissionPrincipals(ctx context.Context, isDryRun bool, grbList []v32.GlobalRoleBinding, crtbList []v32.ClusterRoleTemplateBinding, prtbList []v32.ProjectRoleTemplateBinding) {
	groupScopeType := fmt.Sprintf("%s%s://", ActiveDirectoryAuth, GroupScope)
	userScopeType := fmt.Sprintf("%s%s://", ActiveDirectoryAuth, UserScope)
	preparedGRB := au.prepareGRB(grbList, groupScopeType)
	au.UpdateGRB(ctx, preparedGRB, isDryRun)

	preparedCRTB := au.prepareCRTB(crtbList, userScopeType, groupScopeType)
	au.UpdateCRTB(ctx, preparedCRTB, isDryRun)

	preparedPRTB := au.preparePRTB(prtbList, userScopeType, groupScopeType)
	au.UpdatePRTB(ctx, preparedPRTB, isDryRun)
}

func (au *ADAuthTool) PrintManualCheckData() {
	au.print()
}

func GetActiveDirectoryConfig(cli *client.Clients) (*v32.ActiveDirectoryConfig, *x509.CertPool, error) {
	var gvr = schema.GroupVersionKind{
		Group:   "management.cattle.io",
		Version: "v3",
		Kind:    "AuthConfig",
	}
	authConfigObj, err := cli.Dynamic.Get(gvr, "", ActiveDirectoryAuth)
	if err != nil {
		return nil, nil, err
	}

	logrus.Infof("----- get ad config %++v", authConfigObj)
	u, err := unstructured.ToUnstructured(authConfigObj)
	if err != nil {
		return nil, nil, err
	}
	storedADConfigMap := u.UnstructuredContent()
	storedADConfig := &v32.ActiveDirectoryConfig{}
	err = Decode(storedADConfigMap, storedADConfig)
	if err != nil {
		return nil, nil, err
	}

	if storedADConfig.ServiceAccountPassword != "" {
		value, err := ReadFromSecret(cli, storedADConfig.ServiceAccountPassword,
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
