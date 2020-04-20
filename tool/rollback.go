package tool

import (
	"fmt"
	"io"
	"os"
	"strings"

	corev1 "github.com/rancher/types/apis/core/v1"
	"github.com/rancher/types/apis/management.cattle.io/v3"
	managementv3 "github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
	ldapv2 "gopkg.in/ldap.v2"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Rollback(c *Config) error {
	cfg, err := GetConfig(c)
	if err != nil {
		return err
	}
	management, err := managementv3.NewForConfig(*cfg)
	if err != nil {
		return err
	}
	coreClient, err := corev1.NewForConfig(*cfg)
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

	logrus.Println("Begin to Rollback")
	logrus.Println("Step 1. Get User list")

	userUIDScopeType := fmt.Sprintf("%s%s://", c.AuthConfigType, UserUIDScope)
	groupUIDScopeType := fmt.Sprintf("%s%s://", c.AuthConfigType, GroupUIDScope)
	beforeUpdate, err := GetUsersForUpdate(management, userUIDScopeType)
	if err != nil {
		return fmt.Errorf("failed to get user list: %v", err)
	}

	if c.IsDryRun {
		for userID, user := range beforeUpdate {
			logrus.Infof("FOR DRY_RUN:: User %s need to rollback with principal id %v", userID, user.PrincipalIDs)
		}
	}
	logrus.Infof("Find %d users for update", len(beforeUpdate))

	// get auth config
	var lConn *ldapv2.Conn
	var uidAttribute, gidAttribute, baseDN, groupSearchDN string
	var searchAttribute, groupSearchAttribute []string
	if c.AuthConfigType == ActiveDirectoryAuth {
		authConfig, caPool, err := GetActiveDirectoryConfig(management, coreClient.Secrets(""))
		if err != nil {
			return err
		}
		logrus.Infof("Get Active Directory Auth config: %++v", *authConfig)
		lConn, err = NewLDAPConn(authConfig.Servers, authConfig.TLS, authConfig.Port, authConfig.ConnectionTimeout, caPool)
		if err != nil {
			return err
		}
		uidAttribute = authConfig.UserUniqueIDAttribute
		gidAttribute = authConfig.GroupUniqueIDAttribute
		baseDN = authConfig.UserSearchBase
		groupSearchDN = authConfig.GroupSearchBase
		searchAttribute = GetUserSearchAttributes(authConfig, uidAttribute)
		groupSearchAttribute = GetGroupSearchAttributes(authConfig, gidAttribute)
		username := GetUserExternalID(authConfig.ServiceAccountUsername, authConfig.DefaultLoginDomain)
		err = lConn.Bind(username, authConfig.ServiceAccountPassword)
		if err != nil {
			return err
		}
	} else if c.AuthConfigType == OpenLDAPAuth {
		ldapConfig, caPool, err := GetLDAPConfig(management, coreClient.Secrets(""))
		if err != nil {
			return err
		}
		logrus.Infof("Get OpenLDAP Auth config: %++v", *ldapConfig)
		lConn, err = NewLDAPConn(ldapConfig.Servers, ldapConfig.TLS, ldapConfig.Port, ldapConfig.ConnectionTimeout, caPool)
		if err != nil {
			return err
		}
		uidAttribute = ldapConfig.UserUniqueIDAttribute
		gidAttribute = ldapConfig.GroupUniqueIDAttribute
		baseDN = ldapConfig.UserSearchBase
		groupSearchDN = ldapConfig.GroupSearchBase
		searchAttribute = GetUserSearchAttributesForLDAP(ldapConfig, uidAttribute)
		groupSearchAttribute = GetGroupSearchAttributesForLDAP(ldapConfig, gidAttribute)
		username := GetUserExternalID(ldapConfig.ServiceAccountDistinguishedName, "")
		err = lConn.Bind(username, ldapConfig.ServiceAccountPassword)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("invalid auth config type %v", c.AuthType)
	}

	if groupSearchDN == "" {
		groupSearchDN = baseDN
	}
	crtbList, err := management.ClusterRoleTemplateBindings("").List(metav1.ListOptions{})
	if err != nil {
		return err
	}
	beforeUpdateCRTB := []v3.ClusterRoleTemplateBinding{}
	for _, crtb := range crtbList.Items {
		if crtb.UserPrincipalName != "" && strings.HasPrefix(crtb.UserPrincipalName, userUIDScopeType) {
			beforeUpdateCRTB = append(beforeUpdateCRTB, crtb)
		} else if crtb.GroupPrincipalName != "" && strings.HasPrefix(crtb.GroupPrincipalName, groupUIDScopeType) {
			beforeUpdateCRTB = append(beforeUpdateCRTB, crtb)
		}
	}
	logrus.Infof("find %d crtb need to update", len(beforeUpdateCRTB))

	prtbList, err := management.ProjectRoleTemplateBindings("").List(metav1.ListOptions{})
	if err != nil {
		return err
	}
	beforeUpdatePRTB := []v3.ProjectRoleTemplateBinding{}
	for _, prtb := range prtbList.Items {
		if prtb.UserPrincipalName != "" && strings.HasPrefix(prtb.UserPrincipalName, userUIDScopeType) {
			beforeUpdatePRTB = append(beforeUpdatePRTB, prtb)
		} else if prtb.GroupPrincipalName != "" && strings.HasPrefix(prtb.GroupPrincipalName, groupUIDScopeType) {
			beforeUpdatePRTB = append(beforeUpdatePRTB, prtb)
		}
	}
	logrus.Infof("find %d prtb need to update", len(beforeUpdatePRTB))

	logrus.Println("Step 2. Rollback user principalID")
	preparedUsers, failedUsers := rollbackUser(beforeUpdate, lConn, c.AuthConfigType, baseDN, uidAttribute, searchAttribute)

	logrus.Infof("RESULT:: Will rollback %d users", len(preparedUsers))

	for _, user := range preparedUsers {
		if !c.IsDryRun {
			_, err := management.Users("").Update(&user)
			if err != nil {
				logrus.Errorf("failed to update user %s with error: %v", user.Name, err)
				logrus.Infof("failed user is: %++v", user)
				continue
			}
		} else {
			logrus.Infof("DRY_RUN:: User %s need to rollback with principalIDs: %v", user.Name, user.PrincipalIDs)
		}
	}

	logrus.Println("Step 3. Rollback permissions")
	preparedCRTB, failedCRTB := rollbackClusterPermission(beforeUpdateCRTB, lConn, c.AuthConfigType, baseDN,
		groupSearchDN, uidAttribute, gidAttribute, searchAttribute, groupSearchAttribute)

	for _, crtb := range preparedCRTB {
		if !c.IsDryRun {
			_, err := management.ClusterRoleTemplateBindings(crtb.Namespace).Update(&crtb)
			if err != nil {
				logrus.Errorf("failed to update crtb %s, ns %s with error: %v", crtb.Name, crtb.Namespace, err)
				logrus.Infof("failed crtb is: %++v", crtb)
				continue
			}
		} else {
			logrus.Infof("Update CRTB %s, ns %s with user principal %s, group principal %s", crtb.Name, crtb.Namespace, crtb.UserPrincipalName, crtb.GroupPrincipalName)
		}
	}

	preparedPRTB, failedPRTB := rollbackProjectPermission(beforeUpdatePRTB, lConn, c.AuthConfigType, baseDN,
		groupSearchDN, uidAttribute, gidAttribute, searchAttribute, groupSearchAttribute)

	for _, prtb := range preparedPRTB {
		if !c.IsDryRun {
			_, err := management.ProjectRoleTemplateBindings(prtb.Namespace).Update(&prtb)
			if err != nil {
				logrus.Errorf("failed to update prtb %s, ns %s with error: %v", prtb.Name, prtb.Namespace, err)
				logrus.Infof("failed prtb is: %++v", prtb)
				continue
			}
		} else {
			logrus.Infof("Update PRTB %s, ns %s with user principal %s, group principal %s", prtb.Name, prtb.Namespace, prtb.UserPrincipalName, prtb.GroupPrincipalName)
		}
	}


	logrus.Println("Step 4. Manual check data")
	for _, user := range failedUsers {
		logrus.Warnf("Failed to rollback user %s with principals %v, please manual check the data", user.Name, user.PrincipalIDs)
	}
	for _, mancrtb := range failedCRTB {
		logrus.Warnf("Failed to rollback crtb %s, ns %s with userPrincipal %s, " +
			"groupPrincipal %s, please manual check the data", mancrtb.Name, mancrtb.Namespace, mancrtb.UserPrincipalName, mancrtb.GroupPrincipalName)
	}
	for _, prtb := range failedPRTB {
		logrus.Warnf("Failed to rollback prtb %s, ns %s with userPrincipal %s, " +
			"groupPrincipal %s, please manual check the data", prtb.Name, prtb.Namespace, prtb.UserPrincipalName, prtb.GroupPrincipalName)
	}

	return nil
}

func rollbackUser(beforeUpdate map[string]v3.User, lConn *ldapv2.Conn,
	authConfigType, baseDN, uidAttribute string,
	searchAttribute []string) ([]v3.User, []v3.User) {
	failedUsers := []v3.User{}
	preparedUsers := []v3.User{}
	for _, user := range beforeUpdate {
		principalIDs := user.PrincipalIDs
		oldIndex := -1
		newIndex := 0
		var principalUID string
		for index, principalID := range principalIDs {
			if strings.HasPrefix(principalID, fmt.Sprintf("%s%s://", authConfigType, UserUIDScope)) {
				newIndex = index
				principalUID = principalID
			} else if strings.HasPrefix(principalID, fmt.Sprintf("%s%s://", authConfigType, UserScope)) {
				oldIndex = index
			}
		}
		// don't do anything if there's no uid principal
		if principalUID == "" {
			continue
		}

		oldPrincipalID, err := generateOldPrincipal(lConn, authConfigType, UserScope, principalUID, uidAttribute, baseDN, searchAttribute)
		if err != nil {
			failedUsers = append(failedUsers, user)
			logrus.Errorf("rollbackUser: %v", err)
			continue
		}
		if oldIndex >= 0 {
			principalIDs[oldIndex] = oldPrincipalID
		}
		newPrincipals := append(principalIDs[:newIndex], principalIDs[newIndex+1:]...)
		if oldIndex < 0 {
			newPrincipals = append([]string{oldPrincipalID}, newPrincipals...)
		}
		user.PrincipalIDs = newPrincipals
		preparedUsers = append(preparedUsers, user)
	}

	return preparedUsers, failedUsers
}

func rollbackClusterPermission(beforeUpdateCRTB []v3.ClusterRoleTemplateBinding, lConn *ldapv2.Conn,
	authConfigType, baseDN, groupDN, uidAttribute, gidAttribute string,
	searchAttribute, groupSearchAttribute []string) ([]v3.ClusterRoleTemplateBinding, []v3.ClusterRoleTemplateBinding) {
		prepredCRTB := []v3.ClusterRoleTemplateBinding{}
		failedCRTB := []v3.ClusterRoleTemplateBinding{}
	for _, crtb := range beforeUpdateCRTB {
		if crtb.UserPrincipalName != "" && strings.HasPrefix(crtb.UserPrincipalName, fmt.Sprintf("%s%s://", authConfigType, UserUIDScope)) {
			oldPrincipalID, err := generateOldPrincipal(lConn, authConfigType, UserScope, crtb.UserPrincipalName, uidAttribute, baseDN, searchAttribute)
			if err != nil {
				failedCRTB = append(failedCRTB, crtb)
				logrus.Errorf("rollbackClusterPermission: %v", err)
				continue
			}
			crtb.UserPrincipalName = oldPrincipalID
			prepredCRTB = append(prepredCRTB, crtb)
		} else if crtb.GroupPrincipalName != "" && strings.HasPrefix(crtb.GroupPrincipalName, fmt.Sprintf("%s%s://", authConfigType, GroupUIDScope)) {
			oldPrincipalID, err := generateOldPrincipal(lConn, authConfigType, GroupScope, crtb.GroupPrincipalName, gidAttribute, groupDN, groupSearchAttribute)
			if err != nil {
				failedCRTB = append(failedCRTB, crtb)
				logrus.Errorf("rollbackClusterPermission: %v", err)
				continue
			}
			crtb.GroupPrincipalName = oldPrincipalID
			prepredCRTB = append(prepredCRTB, crtb)
		}
	}

	return prepredCRTB, failedCRTB
}

func rollbackProjectPermission(beforeUpdatePRTB []v3.ProjectRoleTemplateBinding, lConn *ldapv2.Conn,
	authConfigType, baseDN, groupDN, uidAttribute, gidAttribute string,
	searchAttribute, groupSearchAttribute []string) ([]v3.ProjectRoleTemplateBinding, []v3.ProjectRoleTemplateBinding) {
	prepredPRTB := []v3.ProjectRoleTemplateBinding{}
	failedPRTB := []v3.ProjectRoleTemplateBinding{}
	for _, prtb := range beforeUpdatePRTB {
		if prtb.UserPrincipalName != "" && strings.HasPrefix(prtb.UserPrincipalName, fmt.Sprintf("%s%s://", authConfigType, UserUIDScope)) {
			oldPrincipalID, err := generateOldPrincipal(lConn, authConfigType, UserScope, prtb.UserPrincipalName, uidAttribute, baseDN, searchAttribute)
			if err != nil {
				failedPRTB = append(failedPRTB, prtb)
				logrus.Errorf("rollbackClusterPermission: %v", err)
				continue
			}
			prtb.UserPrincipalName = oldPrincipalID
			prepredPRTB = append(prepredPRTB, prtb)
		} else if prtb.GroupPrincipalName != "" && strings.HasPrefix(prtb.GroupPrincipalName, fmt.Sprintf("%s%s://", authConfigType, GroupUIDScope)) {
			oldPrincipalID, err := generateOldPrincipal(lConn, authConfigType, GroupScope, prtb.GroupPrincipalName, gidAttribute, groupDN, groupSearchAttribute)
			if err != nil {
				failedPRTB = append(failedPRTB, prtb)
				logrus.Errorf("rollbackClusterPermission: %v", err)
				continue
			}
			prtb.GroupPrincipalName = oldPrincipalID
			prepredPRTB = append(prepredPRTB, prtb)
		}
	}

	return prepredPRTB, failedPRTB
}

func generateOldPrincipal(lConn *ldapv2.Conn, authConfigType, scope, principalUID, uidAttribute, baseDN string,
	searchAttribute []string) (string, error) {
	// get distinguishedName by uid
	uid, _, err := GetDNAndScopeFromPrincipalID(principalUID)
	if err != nil {
		return "", fmt.Errorf("error get dn and scope by principalID %s, error: %v", principalUID, err)
	}
	var filterValue string
	if uidAttribute == "objectGUID" {
		objectGUID, err := FromString(uid)
		if err != nil {
			return "", fmt.Errorf("convert objectGUID from %s error: %v", uid, err)
		}
		filterValue = objectGUID.OctetString()
	} else {
		filterValue = uid
	}
	filter := fmt.Sprintf("(%v=%v)", uidAttribute, filterValue)
	search := ldapv2.NewSearchRequest(baseDN,
		ldapv2.ScopeWholeSubtree, ldapv2.NeverDerefAliases, 0, 0, false,
		filter,
		searchAttribute, nil)

	result, err := lConn.Search(search)
	if err != nil {
		if ldapErr, ok := err.(*ldapv2.Error); ok && ldapErr.ResultCode == 32 {
			return "", fmt.Errorf("search user for %s not found", filterValue)
		}
		return "", fmt.Errorf("search user with dn %s, filter %s error: %v", baseDN, filter, err)
	}

	if len(result.Entries) < 1 {
		return "", fmt.Errorf("no identities can be retrieved by filter %s", filter)
	} else if len(result.Entries) > 1 {
		return "", fmt.Errorf("more than one result found by filter %s", filter)
	}

	entry := result.Entries[0]
	oldPrincipalID := fmt.Sprintf("%s%s://%s", authConfigType, scope, entry.DN)
	return oldPrincipalID, nil
}
