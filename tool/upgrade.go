package tool

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/JacieChao/rancher-upgrade-authtool/pkg/generated/controllers/management.cattle.io"
	managementv3 "github.com/JacieChao/rancher-upgrade-authtool/pkg/generated/controllers/management.cattle.io/v3"
	ldapv3 "github.com/go-ldap/ldap/v3"
	"github.com/pkg/errors"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

type Tool func() AuthTool

var (
	mutex sync.Mutex
	tools = make(map[string]Tool)
)

func RegisterAuthTool(name string, p Tool) {
	mutex.Lock()
	defer mutex.Unlock()
	if _, found := tools[name]; !found {
		tools[name] = p
	}
}

func GetAuthTool(name string) AuthTool {
	mutex.Lock()
	defer mutex.Unlock()
	f, found := tools[name]
	if !found {
		logrus.Panicf("tool %s is not registed", name)
	}
	return f()
}

type AuthTool interface {
	NewAuthTool(management managementv3.Interface, coreClient v1.CoreV1Interface, client dynamic.Interface) error
	GetAllowedPrincipals() []string
	UpdateAllowedPrincipals(isDryRun bool) error
	UpdateUserPrincipals(list map[string]v3.User, isDryRun bool)
	UpdatePermissionPrincipals(isDryRun bool, grbList []v3.GlobalRoleBinding, crtbList []v3.ClusterRoleTemplateBinding, prtbList []v3.ProjectRoleTemplateBinding)
	PrintManualCheckData()
	DestroyAuthTool()
}

func Upgrade(c *Config) error {
	cfg, err := GetConfig(c)
	if err != nil {
		return err
	}
	mgmt, err := management.NewFactoryFromConfig(cfg)
	if err != nil {
		return err
	}
	k8sClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return err
	}

	if c.LogFilePath != "" {
		logFile, err := os.OpenFile(c.LogFilePath, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logrus.Errorf("Open log file %s error: %v", c.LogFilePath, err)
		}
		mw := io.MultiWriter(os.Stdout, logFile)
		logrus.SetOutput(mw)
	}
	tool := GetAuthTool(c.AuthConfigType)
	mgmtInterface := mgmt.Management().V3()
	if err := tool.NewAuthTool(mgmtInterface, k8sClient.CoreV1(), client); err != nil {
		return err
	}
	defer tool.DestroyAuthTool()

	logrus.Println("Prepare data for Upgrade...")
	logrus.Printf("Step 1. Get auth config for %s", c.AuthConfigType)
	allowedPrincipals := tool.GetAllowedPrincipals()
	// prepare for auth config allowed principal id update
	if len(allowedPrincipals) > 0 {
		logrus.Println("Step 1.1 Prepare for new allowed principals...")
		if err := tool.UpdateAllowedPrincipals(c.IsDryRun); err != nil {
			return err
		}
	}
	logrus.Println("Step 2. Get User list")
	userScopeType := fmt.Sprintf("%s%s://", c.AuthConfigType, UserScope)
	beforeUpdate, err := GetUsersForUpdate(mgmtInterface, userScopeType)
	if err != nil {
		return fmt.Errorf("failed to get user list: %v", err)
	}

	if c.IsDryRun {
		for userID, user := range beforeUpdate {
			logrus.Infof("FOR DRY_RUN:: User %s need to update with principal id %v", userID, user.PrincipalIDs)
		}
	}
	logrus.Infof("Find %d users for update", len(beforeUpdate))

	logrus.Println("Step 3. Prepare user/groups for new principalID")
	groupScopeType := fmt.Sprintf("%s%s://", c.AuthConfigType, GroupScope)
	grbList, err := mgmtInterface.GlobalRoleBinding().List(metav1.ListOptions{})
	if err != nil {
		return err
	}
	beforeUpdateGRB := []v3.GlobalRoleBinding{}
	for _, grb := range grbList.Items {
		if grb.GroupPrincipalName != "" && strings.HasPrefix(grb.GroupPrincipalName, groupScopeType) {
			beforeUpdateGRB = append(beforeUpdateGRB, grb)
		}
	}
	logrus.Infof("find %d global role bindings to update for group principal", len(beforeUpdateGRB))

	crtbList, err := mgmtInterface.ClusterRoleTemplateBinding().List("", metav1.ListOptions{})
	if err != nil {
		return err
	}
	beforeUpdateCRTB := []v3.ClusterRoleTemplateBinding{}
	for _, crtb := range crtbList.Items {
		if crtb.UserPrincipalName != "" && strings.HasPrefix(crtb.UserPrincipalName, userScopeType) {
			beforeUpdateCRTB = append(beforeUpdateCRTB, crtb)
		} else if crtb.GroupPrincipalName != "" && strings.HasPrefix(crtb.GroupPrincipalName, groupScopeType) {
			beforeUpdateCRTB = append(beforeUpdateCRTB, crtb)
		}
	}
	logrus.Infof("find %d crtb need to update", len(beforeUpdateCRTB))

	prtbList, err := mgmtInterface.ProjectRoleTemplateBinding().List("", metav1.ListOptions{})
	if err != nil {
		return err
	}
	beforeUpdatePRTB := []v3.ProjectRoleTemplateBinding{}
	for _, prtb := range prtbList.Items {
		if prtb.UserPrincipalName != "" && strings.HasPrefix(prtb.UserPrincipalName, userScopeType) {
			beforeUpdatePRTB = append(beforeUpdatePRTB, prtb)
		} else if prtb.GroupPrincipalName != "" && strings.HasPrefix(prtb.GroupPrincipalName, groupScopeType) {
			beforeUpdatePRTB = append(beforeUpdatePRTB, prtb)
		}
	}
	logrus.Infof("find %d prtb need to update", len(beforeUpdatePRTB))

	logrus.Println("Step 4. Sync cluster permission with unique attribute id")
	tool.UpdatePermissionPrincipals(c.IsDryRun, beforeUpdateGRB, beforeUpdateCRTB, beforeUpdatePRTB)

	logrus.Println("Step 5. Sync user with unique attribute id")
	tool.UpdateUserPrincipals(beforeUpdate, c.IsDryRun)

	logrus.Println("Step 6. Manual check data")
	tool.PrintManualCheckData()
	return nil
}

func getLdapUserForUpdate(lConn *ldapv3.Conn, distinguishedName, filter string, scopeBaseObject int, searchAttributes []string) (*ldapv3.SearchResult, error) {
	fmt.Printf("Query for distinguishedName %s, filter %s \n", distinguishedName, filter)
	search := ldapv3.NewSearchRequest(distinguishedName,
		scopeBaseObject, ldapv3.NeverDerefAliases, 0, 0, false,
		filter,
		searchAttributes, nil)
	result, err := lConn.Search(search)
	if err != nil {
		ldapErr, ok := reflect.ValueOf(err).Interface().(*ldapv3.Error)
		if ok && ldapErr.ResultCode != ldapv3.LDAPResultNoSuchObject {
			return nil, err
		}
		return nil, errors.New(NoResultFoundError)
	}

	if len(result.Entries) < 1 {
		return nil, errors.New(NoResultFoundError)
	}

	return result, nil
}

func getUniqueAttribute(entry *ldapv3.Entry, scopeType, scope, uniqueAttribute string) (string, string, string) {
	var uniqueID string
	if uniqueAttribute == "objectGUID" {
		var b [16]byte
		copy(b[:], entry.GetRawAttributeValue("objectGUID"))
		uniqueID = FromWindowsArray(b).String()
	} else {
		uniqueID = entry.GetAttributeValue(uniqueAttribute)
	}

	principalIDOfDN := fmt.Sprintf("%s%s", scopeType, entry.DN)
	principalOfUID := fmt.Sprintf("%s_uid://%s", scope, uniqueID)
	return principalIDOfDN, principalOfUID, uniqueID
}
