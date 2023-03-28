package tests

//
//import (
//	"context"
//	"fmt"
//	"github.com/JacieChao/rancher-upgrade-authtool/tool"
//	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
//	client "github.com/rancher/rancher/pkg/client/generated/management/v3"
//	"github.com/rancher/wrangler/pkg/unstructured"
//	"github.com/stretchr/testify/require"
//	"github.com/stretchr/testify/suite"
//	"reflect"
//	"strings"
//	"testing"
//
//	corev1 "k8s.io/api/core/v1"
//	apierrors "k8s.io/apimachinery/pkg/api/errors"
//	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
//	"k8s.io/apimachinery/pkg/runtime/schema"
//	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
//)
//
//type LDAPAuthUpgradeTestSuite struct {
//	suite.Suite
//
//	context context.Context
//	client  *Client
//}
//
//func (l *LDAPAuthUpgradeTestSuite) SetupSuite() {
//	l.context = context.TODO()
//	client, err := NewRancherClient()
//	require.NoError(l.T(), err)
//	l.client = client
//
//	fakeServer := NewMockLDAPServer()
//	go fakeServer.ListenAndServe("127.0.0.1:9999")
//	err = l.initAuthConfig()
//	require.NoError(l.T(), err)
//}
//
//func (l *LDAPAuthUpgradeTestSuite) TearDownSuite() {
//	// remove authconfig
//	storedConfig, _, err := tool.GetLDAPConfig(l.client.DynamicClient, l.client.CoreClient)
//	require.NoError(l.T(), err)
//	storedConfig.Enabled = false
//	var gvr = schema.GroupVersionResource{
//		Group:    "management.cattle.io",
//		Version:  "v3",
//		Resource: "authconfigs",
//	}
//	storedConfig.Kind = "AuthConfig"
//	storedConfig.APIVersion = "management.cattle.io/v3"
//	storedConfig.Type = client.OpenLdapConfigType
//	unstructuredConfig, err := unstructured.ToUnstructured(storedConfig)
//	require.NoError(l.T(), err)
//	_, err = l.client.DynamicClient.Resource(gvr).Update(l.context, unstructuredConfig, metav1.UpdateOptions{})
//
//	require.NoError(l.T(), err)
//}
//
//func (l *LDAPAuthUpgradeTestSuite) initAuthConfig() error {
//	storedConfig, _, err := tool.GetLDAPConfig(l.client.DynamicClient, l.client.CoreClient)
//	if err != nil {
//		return err
//	}
//	conf := &v3.LdapConfig{}
//	conf.APIVersion = "management.cattle.io/v3"
//	conf.Kind = "AuthConfig"
//	conf.Type = client.OpenLdapConfigType
//	conf.ObjectMeta = storedConfig.ObjectMeta
//	conf.AccessMode = "restricted"
//	conf.Enabled = true
//	conf.Servers = []string{"127.0.0.1"}
//	conf.Port = 9999
//	conf.ServiceAccountDistinguishedName = MockAdminDN
//	conf.UserSearchBase = MockBaseDN
//	conf.ServiceAccountPassword = MockAdminPwd
//	conf.UserLoginAttribute = "uid"
//	conf.UserMemberAttribute = "memberOf"
//	conf.UserNameAttribute = "cn"
//	conf.UserObjectClass = "inetOrgPerson"
//	conf.GroupObjectClass = "groupOfNames"
//	conf.GroupMemberMappingAttribute = "member"
//	conf.GroupNameAttribute = "cn"
//	conf.UserSearchAttribute = "uid|cn"
//	conf.GroupUniqueIDAttribute = ""
//	conf.UserUniqueIDAttribute = ""
//	conf.AllowedPrincipalIDs = []string{"openldap_user://uid=admin,ou=test,dc=example,dc=com", "openldap_user://cn=group1,ou=test,dc=example,dc=com"}
//
//	field := strings.ToLower(client.LdapConfigFieldServiceAccountPassword)
//	if err := l.createOrUpdateSecrets(l.client.CoreClient, conf.ServiceAccountPassword,
//		field, strings.ToLower(conf.Type)); err != nil {
//		return err
//	}
//
//	conf.ServiceAccountPassword = fmt.Sprintf("%s:%s-%s", tool.SecretsNamespace, strings.ToLower(conf.Type), field)
//
//	l.T().Log(conf.ServiceAccountPassword)
//	var gvr = schema.GroupVersionResource{
//		Group:    "management.cattle.io",
//		Version:  "v3",
//		Resource: "authconfigs",
//	}
//	unstructuredConfig, err := unstructured.ToUnstructured(conf)
//	if err != nil {
//		return err
//	}
//	_, err = l.client.DynamicClient.Resource(gvr).Update(l.context, unstructuredConfig, metav1.UpdateOptions{})
//
//	return err
//}
//
//func (l *LDAPAuthUpgradeTestSuite) createOrUpdateSecrets(coreClient v1.CoreV1Interface, secretInfo string, field string, authType string) error {
//	if secretInfo == "" {
//		return nil
//	}
//
//	name := fmt.Sprintf("%s-%s", authType, field)
//	secret := &corev1.Secret{
//		ObjectMeta: metav1.ObjectMeta{
//			Name:      name,
//			Namespace: tool.SecretsNamespace,
//		},
//		StringData: map[string]string{field: secretInfo},
//		Type:       corev1.SecretTypeOpaque,
//	}
//
//	curr, err := coreClient.Secrets(tool.SecretsNamespace).Get(l.context, name, metav1.GetOptions{})
//	if err != nil && !apierrors.IsNotFound(err) {
//		return fmt.Errorf("error getting secret for %s : %v", name, err)
//	}
//	if err == nil && !reflect.DeepEqual(curr.Data, secret.Data) {
//		_, err = coreClient.Secrets(tool.SecretsNamespace).Update(l.context, secret, metav1.UpdateOptions{})
//		if err != nil {
//			return fmt.Errorf("error updating secret %s: %v", name, err)
//		}
//	} else if apierrors.IsNotFound(err) {
//		_, err = coreClient.Secrets(tool.SecretsNamespace).Create(l.context, secret, metav1.CreateOptions{})
//		if err != nil && !apierrors.IsAlreadyExists(err) {
//			return fmt.Errorf("error creating secret %s %v", name, err)
//		}
//	}
//	return nil
//}
//
//func (l *LDAPAuthUpgradeTestSuite) prepareBeforeUpgrade() error {
//	// prepare user
//	user := &v3.User{
//		ObjectMeta: metav1.ObjectMeta{
//			GenerateName: "user-",
//		},
//	}
//	user, err := l.client.Management.User().Create(user)
//	if err != nil {
//		return err
//	}
//
//	l.T().Logf("===== get user %++v", user)
//
//	user.PrincipalIDs = append(user.PrincipalIDs, "openldap_user://uid=user1,ou=test,dc=example,dc=com")
//	user, err = l.client.Management.User().Update(user)
//	if err != nil {
//		return err
//	}
//	l.T().Logf("===== new user %++v", user)
//	// prepare global/cluster/project role
//	return nil
//}
//
//func (l *LDAPAuthUpgradeTestSuite) TestUpgrade() {
//	err := l.prepareBeforeUpgrade()
//	//c := &tool.Config{
//	//	RestConfig:     l.client.RestConfig,
//	//	AuthConfigType: tool.OpenLDAPAuth,
//	//	AuthType:       "1",
//	//}
//	//err := tool.Upgrade(c)
//	require.NoError(l.T(), err)
//}
//
//func TestLDAPUpgradeTestSuite(t *testing.T) {
//	suite.Run(t, new(LDAPAuthUpgradeTestSuite))
//}
