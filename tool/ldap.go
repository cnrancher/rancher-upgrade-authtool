package tool

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cnrancher/rancher-upgrade-authtool/client"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v32 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v3client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	"github.com/rancher/wrangler/v3/pkg/unstructured"
	"github.com/sirupsen/logrus"
	"gomodules.xyz/jsonpatch/v2"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
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

func (l *LDAPAuthTool) NewAuthTool(cli *client.Clients) error {
	l.cli = cli
	ldapConfig, caPool, err := GetLDAPConfig(cli)
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

func (l *LDAPAuthTool) UpdateAllowedPrincipals(ctx context.Context, isDryRun bool) error {
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
		err = l.cli.AuthConfigs.Patch(ctx, "", OpenLDAPAuth, types.JSONPatchType, patchBytes, nil, metav1.PatchOptions{})
		if err != nil {
			return err
		}
	} else {
		logrus.Infof("FOR DRY_RUN:: Will update new openldap auth config with: %++v", newConfig)
	}

	return nil
}

func (l *LDAPAuthTool) UpdateUserPrincipals(ctx context.Context, list map[string]v3.User, isDryRun bool) {
	preparedUsers := l.prepareUsers(ctx, list, OpenLDAPAuth)
	l.UpdateUser(ctx, preparedUsers, isDryRun)
}

func (l *LDAPAuthTool) UpdatePermissionPrincipals(ctx context.Context, isDryRun bool, grbList []v3.GlobalRoleBinding, crtbList []v3.ClusterRoleTemplateBinding, prtbList []v3.ProjectRoleTemplateBinding) {
	groupScopeType := fmt.Sprintf("%s%s://", OpenLDAPAuth, GroupScope)
	userScopeType := fmt.Sprintf("%s%s://", OpenLDAPAuth, UserScope)
	preparedGRB := l.prepareGRB(grbList, groupScopeType)
	l.UpdateGRB(ctx, preparedGRB, isDryRun)

	preparedCRTB := l.prepareCRTB(crtbList, userScopeType, groupScopeType)
	l.UpdateCRTB(ctx, preparedCRTB, isDryRun)

	preparedPRTB := l.preparePRTB(prtbList, userScopeType, groupScopeType)
	l.UpdatePRTB(ctx, preparedPRTB, isDryRun)
}

func (l *LDAPAuthTool) PrintManualCheckData() {
	l.print()
}

func GetLDAPConfig(cli *client.Clients) (*v32.LdapConfig, *x509.CertPool, error) {
	var gvr = schema.GroupVersionKind{
		Group:   "management.cattle.io",
		Version: "v3",
		Kind:    "AuthConfig",
	}
	authConfigObj, err := cli.Dynamic.Get(gvr, "", OpenLDAPAuth)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve openldap config, error: %v", err)
	}

	logrus.Infof("----- get config %++v", authConfigObj)
	u, err := unstructured.ToUnstructured(authConfigObj)
	if err != nil {
		return nil, nil, err
	}
	storedLdapConfigMap := u.UnstructuredContent()

	storedLdapConfig := &v3.LdapConfig{}
	err = Decode(storedLdapConfigMap, storedLdapConfig)

	pool, err := newCAPool(storedLdapConfig.Certificate)
	if err != nil {
		return nil, nil, err
	}

	if storedLdapConfig.ServiceAccountPassword != "" {
		value, err := ReadFromSecret(cli, storedLdapConfig.ServiceAccountPassword,
			strings.ToLower(v3client.LdapConfigFieldServiceAccountPassword))
		if err != nil {
			return nil, nil, err
		}
		storedLdapConfig.ServiceAccountPassword = value
	}

	return storedLdapConfig, pool, nil
}
