package tool

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	"github.com/pkg/errors"
	corev1 "github.com/rancher/types/apis/core/v1"
	managementv3 "github.com/rancher/types/apis/management.cattle.io/v3"
	v3 "github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
	ldapv2 "gopkg.in/ldap.v2"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Upgrade(c *Config) error {
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

	logrus.Println("Begin to Upgrade")
	logrus.Println("Step 1. Get User list")
	userScopeType := fmt.Sprintf("%s%s://", c.AuthConfigType, UserScope)
	groupScopeType := fmt.Sprintf("%s%s://", c.AuthConfigType, GroupScope)
	beforeUpdate, err := GetUsersForUpdate(management, userScopeType)
	if err != nil {
		return fmt.Errorf("failed to get user list: %v", err)
	}

	if c.IsDryRun {
		for userID, user := range beforeUpdate {
			logrus.Infof("FOR DRY_RUN:: User %s need to update with principal id %v", userID, user.PrincipalIDs)
		}
	}
	logrus.Infof("Find %d users for update", len(beforeUpdate))

	logrus.Println("Step 2. Prepare user/groups for new principalID")
	// get auth config
	var lConn *ldapv2.Conn
	var objectFilter, groupFilter, uidAttribute, gidAttribute, baseDN, groupSearchDN string
	var searchAttribute, groupSearchAttribute []string
	if c.AuthConfigType == ActiveDirectoryAuth {
		authConfig, caPool, err := GetActiveDirectoryConfig(management, coreClient.Secrets(""))
		if err != nil {
			return err
		}
		logrus.Infof("Get Active Directory Auth config: %++v", *authConfig)
		lConn, err = NewLDAPConn(authConfig.Servers, authConfig.TLS, authConfig.StartTLS, authConfig.Port, authConfig.ConnectionTimeout, caPool)
		if err != nil {
			return err
		}
		objectFilter = fmt.Sprintf("(objectClass=%v)", authConfig.UserObjectClass)
		groupFilter = fmt.Sprintf("(objectClass=%v)", authConfig.GroupObjectClass)
		uidAttribute = authConfig.UserUniqueIDAttribute
		if uidAttribute == "" {
			uidAttribute = "objectGUID"
		}
		gidAttribute = authConfig.GroupUniqueIDAttribute
		if gidAttribute == "" {
			gidAttribute = "objectGUID"
		}
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
		lConn, err = NewLDAPConn(ldapConfig.Servers, ldapConfig.TLS, ldapConfig.StartTLS, ldapConfig.Port, ldapConfig.ConnectionTimeout, caPool)
		if err != nil {
			return err
		}
		objectFilter = fmt.Sprintf("(objectClass=%v)", ldapConfig.UserObjectClass)
		groupFilter = fmt.Sprintf("(objectClass=%v)", ldapConfig.GroupObjectClass)
		uidAttribute = ldapConfig.UserUniqueIDAttribute
		if uidAttribute == "" {
			uidAttribute = "entryUUID"
		}
		gidAttribute = ldapConfig.GroupUniqueIDAttribute
		if gidAttribute == "" {
			gidAttribute = "entryUUID"
		}
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

	defer lConn.Close()

	if groupSearchDN == "" {
		groupSearchDN = baseDN
	}

	grbList, err := management.GlobalRoleBindings("").List(metav1.ListOptions{})
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

	crtbList, err := management.ClusterRoleTemplateBindings("").List(metav1.ListOptions{})
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

	prtbList, err := management.ProjectRoleTemplateBindings("").List(metav1.ListOptions{})
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

	preparedUsers, failedUsers := prepareUsers(beforeUpdate, lConn, userScopeType, c.AuthConfigType,
		objectFilter, uidAttribute, searchAttribute)

	preparedCRTB, failedCRTB, preparedPRTB, failedPRTB, preparedGRB, failedGRB  := preparePermissions(beforeUpdateCRTB, beforeUpdatePRTB, beforeUpdateGRB,
		lConn, groupScopeType, userScopeType, groupFilter,
		objectFilter, gidAttribute, uidAttribute, groupSearchAttribute, searchAttribute)

	logrus.Println("Step 3. Search for DN changed user/groups")

	manualUsers, deprecateUsers := prepareDNChangedUsers(failedUsers, preparedUsers, lConn, management, userScopeType,
		c.AuthConfigType, objectFilter, baseDN, uidAttribute, searchAttribute, beforeUpdate)

	manualCRTB, manualPRTB, newCRTB, newPRTB := preparedDNChangedPermission(failedCRTB, failedPRTB, preparedUsers,
		lConn, userScopeType, groupScopeType, objectFilter, groupFilter, groupSearchDN,
		baseDN, gidAttribute, uidAttribute, searchAttribute, groupSearchAttribute)

	preparedCRTB = append(preparedCRTB, newCRTB...)
	preparedPRTB = append(preparedPRTB, newPRTB...)

	logrus.Println("Step 4. Sync cluster permission with unique attribute id")
	logrus.Infof("RESULT:: Will update %d grb", len(preparedGRB))
	for _, grb := range preparedGRB {
		if !c.IsDryRun {
			_, err = management.GlobalRoleBindings("").Update(&grb)
			if err != nil {
				logrus.Errorf("failed to update grb %s, with error: %v", grb.Name, err)
				logrus.Infof("failed grb is: %++v", grb)
				continue
			}
		} else {
			logrus.Infof("Update GRB %s, with group principal %s", grb.Name, grb.GroupPrincipalName)
		}
	}

	logrus.Infof("RESULT:: Will update %d crtb", len(preparedCRTB))
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

	logrus.Infof("RESULT:: Will update %d prtb", len(preparedPRTB))
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

	logrus.Println("Step 5. Sync user with unique attribute id")
	logrus.Infof("RESULT:: Will update %d users", len(preparedUsers))

	for _, user := range preparedUsers {
		if !c.IsDryRun {
			_, err := management.Users("").Update(&user)
			if err != nil {
				logrus.Errorf("failed to update user %s with error: %v", user.Name, err)
				logrus.Infof("failed user is: %++v", user)
				continue
			}
		} else {
			logrus.Infof("DRY_RUN:: User %s need to sync by principalIDs: %v", user.Name, user.PrincipalIDs)
		}
	}

	logrus.Println("Step 6. Manual check data")
	for _, maUser := range manualUsers {
		logrus.Warnf("Find multiple results or not exist when sync user %s. Need to manual check dn", maUser)
	}

	for _, deprecateU := range deprecateUsers {
		logrus.Warnf("User %s login multiple times, please check and remove one.", deprecateU)
	}

	for _, mancrtb := range manualCRTB {
		logrus.Warnf("Find multiple results or not exist principal for crtb %s, ns %s, please manual check dn or remove permission", mancrtb.Name, mancrtb.Namespace)
	}

	for _, manuprtb := range manualPRTB {
		logrus.Warnf("Find multiple results or not exist principal for prtb %s, ns %s, please manual check dn or remove permission", manuprtb.Name, manuprtb.Namespace)
	}

	for _, manugrb := range failedGRB {
		logrus.Warnf("please manual check global role binding permission %v", manugrb.Name)
	}

	return nil
}

func getLdapUserForUpdate(lConn *ldapv2.Conn, distinguishedName, filter string, scopeBaseObject int, searchAttributes []string) (*ldapv2.SearchResult, error) {
	fmt.Printf("Query for distinguishedName %s, filter %s \n", distinguishedName, filter)
	search := ldapv2.NewSearchRequest(distinguishedName,
		scopeBaseObject, ldapv2.NeverDerefAliases, 0, 0, false,
		filter,
		searchAttributes, nil)
	result, err := lConn.Search(search)
	if err != nil {
		ldapErr, ok := reflect.ValueOf(err).Interface().(*ldapv2.Error)
		if ok && ldapErr.ResultCode != ldapv2.LDAPResultNoSuchObject {
			return nil, err
		}
		return nil, errors.New(NoResultFoundError)
	}

	if len(result.Entries) < 1 {
		return nil, errors.New(NoResultFoundError)
	}

	return result, nil
}

func getGroupPrincipal(userID, authConfigType string, management managementv3.Interface) ([]v3.Principal, error) {
	userAttributes, err := management.UserAttributes("").Get(userID, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	groupPrincipals := userAttributes.GroupPrincipals[authConfigType].Items

	return groupPrincipals, nil
}

func checkHasUIDAttribute(principalIDs []string, userScopeType, authConfigType string) (int, bool) {
	var oldPrincipalIndex int
	hasFinishedSync := false
	for index, principalID := range principalIDs {
		if strings.HasPrefix(principalID, userScopeType) {
			oldPrincipalIndex = index
		} else if strings.HasPrefix(principalID, fmt.Sprintf("%s%s_uid://", authConfigType, UserScope)) {
			hasFinishedSync = true
			break
		}
	}
	return oldPrincipalIndex, hasFinishedSync
}

func prepareUsers(beforeUpdate map[string]v3.User, lConn *ldapv2.Conn,
	userScopeType, authConfigType, objectFilter, uidAttribute string,
	searchAttribute []string) (map[string]v3.User, map[string]v3.User) {
	failedUsers := map[string]v3.User{}
	preparedUsers := map[string]v3.User{}
	for userID, user := range beforeUpdate {
		principalIDs := user.PrincipalIDs
		oldPrincipalIndex, hasFinishedSync := checkHasUIDAttribute(principalIDs, userScopeType, authConfigType)
		if !hasFinishedSync {
			principalID := principalIDs[oldPrincipalIndex]
			_, principalUID, uid, err := generateNewPrincipalByDN(lConn, principalID, userScopeType, objectFilter, uidAttribute, searchAttribute)
			if err != nil {
				if strings.EqualFold(err.Error(), NoResultFoundError) {
					logrus.Warnf("No identies found for user %s using current principal: %s", userID, principalID)
					failedUsers[userID] = user
				} else {
					logrus.Errorf("failed to get user %s using principal: %s, err: %v", userID, principalID, err)
				}
				continue
			}
			principalIDs = append([]string{principalUID}, principalIDs...)
			user.PrincipalIDs = principalIDs
			preparedUsers[uid] = user
			logrus.Infof("Using %s find unique attribute value %s for user %s", principalID, uid, userID)
		}
	}

	return preparedUsers, failedUsers
}

func generateNewPrincipalByDN(lConn *ldapv2.Conn, principalID, scopeType,
	filter, uniqueAttribute string, searchAttribute []string) (string, string, string, error) {
	externalID, scope, err := GetDNAndScopeFromPrincipalID(principalID)
	if err != nil {
		return "", "", "", err
	}

	results, err := getLdapUserForUpdate(lConn, externalID, filter, ldapv2.ScopeBaseObject, searchAttribute)
	if err != nil {
		return "", "", "", err
	}
	entry := results.Entries[0]
	principalIDOfDN, principalOfUID, uniqueID := getUniqueAttribute(entry, scopeType, scope, uniqueAttribute)
	return principalIDOfDN, principalOfUID, uniqueID, nil
}

func generateNewPrincipalForDNChanged(lConn *ldapv2.Conn, principalID, scopeType, objectFilter,
	baseDN, uniqueAttribute string, searchAttributes []string) (string, string, string, *ldapv2.SearchResult, error) {
	externalID, scope, err := GetDNAndScopeFromPrincipalID(principalID)
	if err != nil {
		logrus.Errorf("Error to get DN from principal %s with error: %v", principalID, err)
		return "", "", "", nil, err
	}
	dnArray := strings.Split(externalID, ",")
	// got first attribute of DN
	filter := fmt.Sprintf("(&%s(%s))", objectFilter, dnArray[0])
	var entry *ldapv2.Entry
	results, err := getLdapUserForUpdate(lConn, baseDN, filter, ldapv2.ScopeWholeSubtree, searchAttributes)
	if err != nil {
		return "", "", "", nil, err
	}
	if len(results.Entries) < 1 {
		return "", "", "", nil, errors.New(NoResultFoundError)
	} else if len(results.Entries) > 1 {
		return "", "", "", results, errors.New(MutipleResultFoundError)
	}
	entry = results.Entries[0]
	logrus.Infof("generateNewPrincipalForDNChanged: Find unique user by filter %s, for original DN %s", filter, principalID)
	principalIDOfDN, principalOfUID, uniqueID := getUniqueAttribute(entry, scopeType, scope, uniqueAttribute)

	return principalIDOfDN, principalOfUID, uniqueID, results, nil
}

func getUniqueAttribute(entry *ldapv2.Entry, scopeType, scope, uniqueAttribute string) (string, string, string) {
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

func preparePermissions(beforeCRTB []v3.ClusterRoleTemplateBinding, beforePRTB []v3.ProjectRoleTemplateBinding, beforeGRB []v3.GlobalRoleBinding,
	lConn *ldapv2.Conn, groupScopeType, userScopeType, groupFilter, objectFilter,
	gidAttribute, uidAttribute string, groupSearchAttribute, searchAttribute []string) (preparedCRTB []v3.ClusterRoleTemplateBinding,
	failedCRTB []v3.ClusterRoleTemplateBinding, preparedPRTB []v3.ProjectRoleTemplateBinding,
	failedPRTB []v3.ProjectRoleTemplateBinding, preparedGRB []v3.GlobalRoleBinding, failedGRB []v3.GlobalRoleBinding) {

	preparedCRTB = []v3.ClusterRoleTemplateBinding{}
	failedCRTB = []v3.ClusterRoleTemplateBinding{}
	for _, crtb := range beforeCRTB {
		var principalID string
		if crtb.UserPrincipalName != "" && strings.HasPrefix(crtb.UserPrincipalName, userScopeType) {
			principalID = crtb.UserPrincipalName
			_, principalUID, _, err := generateNewPrincipalByDN(lConn, principalID, userScopeType, objectFilter, uidAttribute, searchAttribute)
			if err != nil {
				if strings.EqualFold(err.Error(), NoResultFoundError) {
					logrus.Warnf("No identies found using current principal %s for crtb %s, ns %s", principalID, crtb.Name, crtb.Namespace)
					failedCRTB = append(failedCRTB, crtb)
				} else {
					logrus.Errorf("failed to find user using principal %s for crtb %s, ns %s, err: %v", principalID, crtb.Name, crtb.Namespace, err)
				}
				continue
			}
			crtb.UserPrincipalName = principalUID
		} else if crtb.GroupPrincipalName != "" && strings.HasPrefix(crtb.GroupPrincipalName, groupScopeType) {
			principalID = crtb.GroupPrincipalName
			_, principalUID, _, err := generateNewPrincipalByDN(lConn, principalID, groupScopeType, groupFilter, gidAttribute, groupSearchAttribute)
			if err != nil {
				if strings.EqualFold(err.Error(), NoResultFoundError) {
					logrus.Warnf("No identies found using current principal %s for crtb %s, ns %s", principalID, crtb.Name, crtb.Namespace)
					failedCRTB = append(failedCRTB, crtb)
				} else {
					logrus.Errorf("failed to find group using principal %s for crtb %s, ns %s, err: %v", principalID, crtb.Name, crtb.Namespace, err)
				}
				continue
			}
			crtb.GroupPrincipalName = principalUID
		}
		if principalID == "" {
			continue
		}
		preparedCRTB = append(preparedCRTB, crtb)
	}

	preparedPRTB = []v3.ProjectRoleTemplateBinding{}
	failedPRTB = []v3.ProjectRoleTemplateBinding{}
	for _, prtb := range beforePRTB {
		var principalID string
		if prtb.UserPrincipalName != "" && strings.HasPrefix(prtb.UserPrincipalName, userScopeType) {
			principalID = prtb.UserPrincipalName
			_, principalUID, _, err := generateNewPrincipalByDN(lConn, principalID, userScopeType, objectFilter, uidAttribute, searchAttribute)
			if err != nil {
				if strings.EqualFold(err.Error(), NoResultFoundError) {
					logrus.Warnf("No identies found using current principalID %s for prtb %s, ns %s", principalID, prtb.Name, prtb.Namespace)
					failedPRTB = append(failedPRTB, prtb)
				} else {
					logrus.Errorf("failed to get user using principalID %s for prtb %s, ns %s, err: %v", principalID, prtb.Name, prtb.Namespace, err)
				}
				continue
			}
			prtb.UserPrincipalName = principalUID
		} else if prtb.GroupPrincipalName != "" && strings.HasPrefix(prtb.GroupPrincipalName, groupScopeType) {
			principalID = prtb.GroupPrincipalName
			_, principalUID, _, err := generateNewPrincipalByDN(lConn, principalID, groupScopeType, groupFilter, gidAttribute, groupSearchAttribute)
			if err != nil {
				if strings.EqualFold(err.Error(), NoResultFoundError) {
					logrus.Warnf("No identies found using current principalID: %s for prtb %s, ns %s", principalID, prtb.Name, prtb.Namespace)
					failedPRTB = append(failedPRTB, prtb)
				} else {
					logrus.Errorf("failed to get group using principalID %s for prtb %s, ns %s, err: %v", principalID, prtb.Name, prtb.Namespace, err)
				}
				continue
			}
			prtb.GroupPrincipalName = principalUID
		}
		if principalID == "" {
			continue
		}
		preparedPRTB = append(preparedPRTB, prtb)
	}

	preparedGRB = []v3.GlobalRoleBinding{}
	failedGRB = []v3.GlobalRoleBinding{}
	for _, grb := range beforeGRB {
		if grb.GroupPrincipalName != "" && strings.HasPrefix(grb.GroupPrincipalName, groupScopeType) {
			principalID := grb.GroupPrincipalName
			_, principalUID, _, err := generateNewPrincipalByDN(lConn, principalID, groupScopeType, groupFilter, gidAttribute, groupSearchAttribute)
			if err != nil {
				if strings.EqualFold(err.Error(), NoResultFoundError) {
					logrus.Warnf("No identies found using current principalID: %s for grb %s", principalID, grb.Name)
					failedGRB = append(failedGRB, grb)
				} else {
					logrus.Errorf("failed to get group using principalID %s for grb %s, err: %v", principalID, grb.Name, err)
				}
				continue
			}
			grb.GroupPrincipalName = principalUID
			preparedGRB = append(preparedGRB, grb)
		}
	}

	return preparedCRTB, failedCRTB, preparedPRTB, failedPRTB, preparedGRB, failedGRB
}

func prepareDNChangedUsers(failedUsers map[string]v3.User, preparedUsers map[string]v3.User,
	lConn *ldapv2.Conn, management managementv3.Interface,
	userScopeType, authConfigType, objectFilter, baseDN, uidAttribute string,
	searchAttribute []string, beforeUpdate map[string]v3.User) ([]string, []string) {
	manualUsers := []string{}
	deprecateUsers := []string{}
	for userID, user := range failedUsers {
		principalIDs := user.PrincipalIDs
		oldPrincipalIndex, hasFinishedSync := checkHasUIDAttribute(principalIDs, userScopeType, authConfigType)
		if !hasFinishedSync {
			principalID := principalIDs[oldPrincipalIndex]
			var newPrincipalID, principalUID, uid string
			var err error
			var results *ldapv2.SearchResult
			newPrincipalID, principalUID, uid, results, err = generateNewPrincipalForDNChanged(lConn, principalID, userScopeType, objectFilter,
				baseDN, uidAttribute, searchAttribute)
			if err != nil {
				if strings.EqualFold(err.Error(), NoResultFoundError) {
					logrus.Warnf("No identities can be retrieved to get user %s, principal %s", userID, principalID)
					manualUsers = append(manualUsers, userID)
					continue
				} else if strings.EqualFold(err.Error(), MutipleResultFoundError) {
					logrus.Warnf("sync user %s:: find multiple users for principal %s", userID, principalID)
					checkEntries, err := checkForGroups(userID, authConfigType, management, results)
					if err != nil {
						if apierrors.IsNotFound(err) {
							logrus.Warnf("Skip for user %s with empty user group", userID)
							manualUsers = append(manualUsers, userID)
							continue
						}
						logrus.Errorf("failed to get group principals for user %s with error: %v", userID, err)
						continue
					}
					if len(checkEntries) > 1 {
						logrus.Warnf("Found multiple users with same group, need to check user %s manually", userID)
						manualUsers = append(manualUsers, userID)
						continue
					} else if len(checkEntries) == 0 {
						logrus.Warnf("No identities found, need to check user %s manually", userID)
						manualUsers = append(manualUsers, userID)
						continue
					}
					_, scope, err := GetDNAndScopeFromPrincipalID(principalID)
					if err != nil {
						logrus.Errorf("Get DN from principal %s error: %v", principalID, err)
						continue
					}
					// if find unique user
					newPrincipalID, principalUID, uid = getUniqueAttribute(checkEntries[0], userScopeType, scope, uidAttribute)
				} else {
					continue
				}
			}
			// check is only user
			deprecateUsers = append(deprecateUsers, checkUniqueUser(uid, principalUID, newPrincipalID, oldPrincipalIndex, preparedUsers, user, beforeUpdate)...)
		}
	}

	return manualUsers, deprecateUsers
}

func preparedDNChangedPermission(failedCRTB []v3.ClusterRoleTemplateBinding,
	failedPRTB []v3.ProjectRoleTemplateBinding, preparedUser map[string]v3.User,
	lConn *ldapv2.Conn, userScopeType, groupScopeType, objectFilter,
	groupFilter, groupDN, baseDN, gidAttribute, uidAttribute string,
	searchAttributes, groupSearchAttributes []string) (manualCRTB []v3.ClusterRoleTemplateBinding,
	manualPRTB []v3.ProjectRoleTemplateBinding, newCRTB []v3.ClusterRoleTemplateBinding, newPRTB []v3.ProjectRoleTemplateBinding) {
	manualCRTB = []v3.ClusterRoleTemplateBinding{}
	manualPRTB = []v3.ProjectRoleTemplateBinding{}
	newCRTB = []v3.ClusterRoleTemplateBinding{}
	newPRTB = []v3.ProjectRoleTemplateBinding{}
	for _, crtb := range failedCRTB {
		if crtb.UserPrincipalName != "" && strings.HasPrefix(crtb.UserPrincipalName, userScopeType) {
			_, principalUID, uid, _, err := generateNewPrincipalForDNChanged(lConn, crtb.UserPrincipalName, userScopeType, objectFilter,
				baseDN, uidAttribute, searchAttributes)
			if err != nil {
				if strings.EqualFold(err.Error(), NoResultFoundError) {
					logrus.Warnf("No identities can be retrieved to get crtb %s, ns %s, principal %s", crtb.Name, crtb.Namespace, crtb.UserPrincipalName)
					manualCRTB = append(manualCRTB, crtb)
				} else if strings.EqualFold(err.Error(), MutipleResultFoundError) {
					logrus.Warnf("sync crtb %s, ns %s:: find multiple users for principal %s", crtb.Name, crtb.Namespace, crtb.UserPrincipalName)
					manualCRTB = append(manualCRTB, crtb)
				}
				continue
			}
			if u, ok := preparedUser[uid]; ok {
				if crtb.UserName != u.Name {
					crtb.UserName = u.Name
				}
			}
			crtb.UserPrincipalName = principalUID
			newCRTB = append(newCRTB, crtb)
		} else if crtb.GroupPrincipalName != "" && strings.HasPrefix(crtb.GroupPrincipalName, groupScopeType) {
			_, principalUID, _, _, err := generateNewPrincipalForDNChanged(lConn, crtb.GroupPrincipalName, groupScopeType, groupFilter,
				groupDN, gidAttribute, groupSearchAttributes)
			if err != nil {
				if strings.EqualFold(err.Error(), NoResultFoundError) {
					logrus.Warnf("No identities can be retrieved to get crtb %s, ns %s, principal %s", crtb.Name, crtb.Namespace, crtb.GroupPrincipalName)
					manualCRTB = append(manualCRTB, crtb)
				} else if strings.EqualFold(err.Error(), MutipleResultFoundError) {
					logrus.Warnf("sync crtb %s, ns %s:: find multiple group for principal %s", crtb.Name, crtb.Namespace, crtb.GroupPrincipalName)
					manualCRTB = append(manualCRTB, crtb)
				}
				continue
			}
			crtb.GroupPrincipalName = principalUID
			newCRTB = append(newCRTB, crtb)
		}
	}

	for _, prtb := range failedPRTB {
		if prtb.UserPrincipalName != "" && strings.HasPrefix(prtb.UserPrincipalName, userScopeType) {
			_, principalUID, uid, _, err := generateNewPrincipalForDNChanged(lConn, prtb.UserPrincipalName, userScopeType, objectFilter,
				baseDN, uidAttribute, searchAttributes)
			if err != nil {
				if strings.EqualFold(err.Error(), NoResultFoundError) {
					logrus.Warnf("No identities can be retrieved to get crtb %s, ns %s, principal %s", prtb.Name, prtb.Namespace, prtb.UserPrincipalName)
					manualPRTB = append(manualPRTB, prtb)
				} else if strings.EqualFold(err.Error(), MutipleResultFoundError) {
					logrus.Warnf("sync crtb %s, ns %s:: find multiple users for principal %s", prtb.Name, prtb.Namespace, prtb.UserPrincipalName)
					manualPRTB = append(manualPRTB, prtb)
				}
				continue
			}
			if u, ok := preparedUser[uid]; ok {
				if prtb.UserName != u.Name {
					prtb.UserName = u.Name
				}
			}
			prtb.UserPrincipalName = principalUID
			newPRTB = append(newPRTB, prtb)
		} else if prtb.GroupPrincipalName != "" && strings.HasPrefix(prtb.GroupPrincipalName, groupScopeType) {
			_, principalUID, _, _, err := generateNewPrincipalForDNChanged(lConn, prtb.GroupPrincipalName, groupScopeType, groupFilter,
				groupDN, gidAttribute, groupSearchAttributes)
			if err != nil {
				if strings.EqualFold(err.Error(), NoResultFoundError) {
					logrus.Warnf("No identities can be retrieved to get crtb %s, ns %s, principal %s", prtb.Name, prtb.Namespace, prtb.GroupPrincipalName)
					manualPRTB = append(manualPRTB, prtb)
				} else if strings.EqualFold(err.Error(), MutipleResultFoundError) {
					logrus.Warnf("sync crtb %s, ns %s:: find multiple group for principal %s", prtb.Name, prtb.Namespace, prtb.UserPrincipalName)
					manualPRTB = append(manualPRTB, prtb)
				}
				continue
			}
			prtb.GroupPrincipalName = principalUID
			newPRTB = append(newPRTB, prtb)
		}
	}

	return manualCRTB, manualPRTB, newCRTB, newPRTB
}

func checkForGroups(userID, authConfigType string, management managementv3.Interface, results *ldapv2.SearchResult) ([]*ldapv2.Entry, error) {
	groupPrincipals, err := getGroupPrincipal(userID, authConfigType, management)
	if err != nil {
		return nil, err
	}
	// check for groups
	checkEntries := []*ldapv2.Entry{}
	for _, entry := range results.Entries {
		memberOf := entry.GetAttributeValues("memberOf")
		if len(memberOf) == len(groupPrincipals) {
			isEqual := false
			if len(memberOf) == 0 {
				isEqual = true
			} else {
				for _, member := range memberOf {
					memberGroup := fmt.Sprintf("%s_group://%s", authConfigType, member)
					for _, groupPrincipal := range groupPrincipals {
						if strings.EqualFold(memberGroup, groupPrincipal.Name) {
							isEqual = true
							break
						}
					}
					if !isEqual {
						logrus.Infof("Skip for different memberOf=%v attribute: user=%s, account=%s, name=%s",
							memberOf,
							entry.DN, entry.GetAttributeValue("sAMAccountName"),
							entry.GetAttributeValue("name"))
						break
					}
				}
			}
			if isEqual {
				checkEntries = append(checkEntries, entry)
			}
		} else {
			logrus.Infof("Skip for different memberOf=%v attribute: user=%s, account=%s, name=%s",
				memberOf,
				entry.DN, entry.GetAttributeValue("sAMAccountName"),
				entry.GetAttributeValue("name"))
		}
	}
	return checkEntries, nil
}

func checkUniqueUser(uid, principalUID, newPrincipalID string, oldPrincipalIndex int,
	preparedUsers map[string]v3.User, user v3.User, beforeUpdate map[string]v3.User) []string {
	principalIDs := user.PrincipalIDs
	deprecateUsers := []string{}
	if pUser, ok := preparedUsers[uid]; ok {
		logrus.Infof("find exist user %s", pUser.Name)
		// find latest user
		if pUser.CreationTimestamp.Time.UnixNano() > user.CreationTimestamp.Time.UnixNano() {
			// keep latest user
			logrus.Infof("checkUniqueUser: Keep latest user %s, user %s will deprecate", pUser.Name, user.Name)
			deprecateUsers = append(deprecateUsers, user.Name)
		} else {
			logrus.Infof("checkUniqueUser: Keep latest user %s, user %s will deprecate", user.Name, pUser.Name)
			delete(preparedUsers, uid)
			deprecateUsers = append(deprecateUsers, pUser.Name)
			principalIDs[oldPrincipalIndex] = newPrincipalID
			principalIDs = append([]string{principalUID}, principalIDs...)
			user.PrincipalIDs = principalIDs
			preparedUsers[uid] = user
		}
	} else {
		// check from exist user
		isExist := false
		for userID, user := range beforeUpdate {
			pIDs := user.PrincipalIDs
			for _, pID := range pIDs {
				if strings.EqualFold(pID, principalUID) && userID != user.Name {
					deprecateUsers = append(deprecateUsers, user.Name)
					logrus.Warnf("User has exist with %s, user %s deprecated", userID, user.Name)
					isExist = true
					break
				}
			}
		}
		if !isExist {
			principalIDs[oldPrincipalIndex] = newPrincipalID
			principalIDs = append([]string{principalUID}, principalIDs...)
			user.PrincipalIDs = principalIDs
			preparedUsers[uid] = user
		}
	}

	return deprecateUsers
}
