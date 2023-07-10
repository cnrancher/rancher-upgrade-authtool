package tool

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	managementv3 "github.com/JacieChao/rancher-upgrade-authtool/pkg/generated/controllers/management.cattle.io/v3"
	ldapv3 "github.com/go-ldap/ldap/v3"
	"github.com/pkg/errors"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v32 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	ActiveDirectoryAuth     = "activedirectory"
	OpenLDAPAuth            = "openldap"
	UserScope               = "_user"
	GroupScope              = "_group"
	NoResultFoundError      = "No identities can be retrieved"
	MutipleResultFoundError = "Get more than one results"
	SecretsNamespace        = "cattle-global-data"
	UserUIDScope            = "_user_uid"
	GroupUIDScope           = "_group_uid"
)

type Config struct {
	RestConfig     *rest.Config
	KubeConfig     string
	AuthType       string
	AuthConfigType string
	IsDryRun       bool
	LogFilePath    string
}

type AuthUtil struct {
	management           managementv3.Interface
	coreClient           v1.CoreV1Interface
	client               dynamic.Interface
	conn                 *ldapv3.Conn
	userUniqueAttribute  string
	groupUniqueAttribute string
	userObjectFilter     string
	groupObjectFilter    string
	baseDN               string
	groupSearchDN        string
	userSearchAttribute  []string
	groupSearchAttribute []string

	manualCheckUsers []string
	deprecateUsers   []string
	manualCRTB       []v3.ClusterRoleTemplateBinding
	manualPRTB       []v3.ProjectRoleTemplateBinding
	manualGRB        []v3.GlobalRoleBinding
}

func NewAuthUtil() *AuthUtil {
	return &AuthUtil{
		manualCheckUsers: []string{},
		deprecateUsers:   []string{},
		manualCRTB:       []v3.ClusterRoleTemplateBinding{},
		manualPRTB:       []v3.ProjectRoleTemplateBinding{},
		manualGRB:        []v3.GlobalRoleBinding{},
	}
}

func (u *AuthUtil) print() {
	for _, maUser := range u.manualCheckUsers {
		logrus.Warnf("Find multiple results or not exist when sync user %s. Need to manual check dn", maUser)
	}

	for _, deprecateU := range u.deprecateUsers {
		logrus.Warnf("User %s login multiple times, please check and remove one.", deprecateU)
	}

	for _, mancrtb := range u.manualCRTB {
		logrus.Warnf("Find multiple results or not exist principal for crtb %s, ns %s, please manual check dn or remove permission", mancrtb.Name, mancrtb.Namespace)
	}

	for _, manuprtb := range u.manualPRTB {
		logrus.Warnf("Find multiple results or not exist principal for prtb %s, ns %s, please manual check dn or remove permission", manuprtb.Name, manuprtb.Namespace)
	}

	for _, manugrb := range u.manualGRB {
		logrus.Warnf("please manual check global role binding permission %v", manugrb.Name)
	}
}

func (u *AuthUtil) prepareUsers(list map[string]v3.User, authType string) map[string]v3.User {
	userScopeType := fmt.Sprintf("%s%s://", authType, UserScope)
	failedUsers := map[string]v3.User{}
	preparedUsers := map[string]v3.User{}
	// update user principal with unique id
	for userID, user := range list {
		principalIDs := user.PrincipalIDs
		oldPrincipalIndex, hasFinishedSync := checkHasUIDAttribute(principalIDs, userScopeType, authType)
		if !hasFinishedSync {
			principalID := principalIDs[oldPrincipalIndex]
			principalUID, uid, err := u.prepareForNewPrincipal(principalID, userScopeType, "")
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

	// sync failed users with DN change
	for userID, user := range failedUsers {
		logrus.Println("================ Search for DN changed users ================")
		principalIDs := user.PrincipalIDs
		oldPrincipalIndex, hasFinishedSync := checkHasUIDAttribute(principalIDs, userScopeType, authType)
		if !hasFinishedSync {
			principalID := principalIDs[oldPrincipalIndex]
			var newPrincipalID, principalUID, uid string
			var err error
			var results *ldapv3.SearchResult
			newPrincipalID, principalUID, uid, results, err = generateNewPrincipalForDNChanged(u.conn, principalID, userScopeType, u.userObjectFilter,
				u.baseDN, u.userUniqueAttribute, u.userSearchAttribute)
			if err != nil {
				if strings.EqualFold(err.Error(), NoResultFoundError) {
					logrus.Warnf("No identities can be retrieved to get user %s, principal %s", userID, principalID)
					u.manualCheckUsers = append(u.manualCheckUsers, userID)
					continue
				} else if strings.EqualFold(err.Error(), MutipleResultFoundError) {
					logrus.Warnf("sync user %s:: find multiple users for principal %s", userID, principalID)
					checkEntries, err := checkForGroups(userID, authType, u.management, results)
					if err != nil {
						if apierrors.IsNotFound(err) {
							logrus.Warnf("Skip for user %s with empty user group", userID)
							u.manualCheckUsers = append(u.manualCheckUsers, userID)
							continue
						}
						logrus.Errorf("failed to get group principals for user %s with error: %v", userID, err)
						continue
					}
					if len(checkEntries) > 1 {
						logrus.Warnf("Found multiple users with same group, need to check user %s manually", userID)
						u.manualCheckUsers = append(u.manualCheckUsers, userID)
						continue
					} else if len(checkEntries) == 0 {
						logrus.Warnf("No identities found, need to check user %s manually", userID)
						u.manualCheckUsers = append(u.manualCheckUsers, userID)
						continue
					}
					_, scope, err := GetDNAndScopeFromPrincipalID(principalID)
					if err != nil {
						logrus.Errorf("Get DN from principal %s error: %v", principalID, err)
						continue
					}
					// if find unique user
					newPrincipalID, principalUID, uid = getUniqueAttribute(checkEntries[0], userScopeType, scope, u.userUniqueAttribute)
				} else {
					continue
				}
			}
			// check is only user
			u.deprecateUsers = append(u.deprecateUsers, checkUniqueUser(uid, principalUID, newPrincipalID, oldPrincipalIndex, preparedUsers, user, list)...)
		}
	}
	return preparedUsers
}

func (u *AuthUtil) prepareGRB(grbList []v3.GlobalRoleBinding, groupScopeType string) []v3.GlobalRoleBinding {
	preparedGRB := []v3.GlobalRoleBinding{}
	failedGRB := []v3.GlobalRoleBinding{}
	for _, grb := range grbList {
		if grb.GroupPrincipalName != "" && strings.HasPrefix(grb.GroupPrincipalName, groupScopeType) {
			principalID := grb.GroupPrincipalName
			principalUID, _, err := u.prepareForNewPrincipal(principalID, "", groupScopeType)
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

	if len(failedGRB) > 0 {
		logrus.Println("================ Search for DN changed groups ================")
		for _, grb := range failedGRB {
			_, principalUID, _, _, err := generateNewPrincipalForDNChanged(u.conn, grb.GroupPrincipalName, groupScopeType, u.groupObjectFilter,
				u.groupSearchDN, u.groupUniqueAttribute, u.groupSearchAttribute)
			if err != nil {
				if strings.EqualFold(err.Error(), NoResultFoundError) {
					logrus.Warnf("No identities can be retrieved to get grb %s, principal %s", grb.Name, grb.GroupPrincipalName)
					u.manualGRB = append(u.manualGRB, grb)
				} else if strings.EqualFold(err.Error(), MutipleResultFoundError) {
					logrus.Warnf("sync crtb %s:: find multiple group for principal %s", grb.Name, grb.GroupPrincipalName)
					u.manualGRB = append(u.manualGRB, grb)
				}
				continue
			}
			grb.GroupPrincipalName = principalUID
			preparedGRB = append(preparedGRB, grb)
		}
	}

	return preparedGRB
}

func (u *AuthUtil) prepareCRTB(crtbList []v3.ClusterRoleTemplateBinding, userScopeType, groupScopeType string) []v3.ClusterRoleTemplateBinding {
	preparedCRTB := []v3.ClusterRoleTemplateBinding{}
	failedCRTB := []v3.ClusterRoleTemplateBinding{}
	for _, crtb := range crtbList {
		var principalID string
		if crtb.UserPrincipalName != "" {
			principalID = crtb.UserPrincipalName
		} else if crtb.GroupPrincipalName != "" {
			principalID = crtb.GroupPrincipalName
		}
		if principalID == "" {
			continue
		}
		principalUID, _, err := u.prepareForNewPrincipal(principalID, userScopeType, groupScopeType)
		if err != nil {
			if strings.EqualFold(err.Error(), NoResultFoundError) {
				logrus.Warnf("No identies found using current principal %s for crtb %s, ns %s", principalID, crtb.Name, crtb.Namespace)
				failedCRTB = append(failedCRTB, crtb)
			} else {
				logrus.Errorf("failed to find user using principal %s for crtb %s, ns %s, err: %v", principalID, crtb.Name, crtb.Namespace, err)
			}
			continue
		}

		if crtb.UserPrincipalName != "" {
			crtb.UserPrincipalName = principalUID
		} else if crtb.GroupPrincipalName != "" {
			crtb.GroupPrincipalName = principalUID
		}
		preparedCRTB = append(preparedCRTB, crtb)
	}

	if len(failedCRTB) > 0 {
		logrus.Println("================ Search for DN changed CRTB users/groups ================")
		for _, crtb := range failedCRTB {
			if crtb.UserPrincipalName != "" && strings.HasPrefix(crtb.UserPrincipalName, userScopeType) {
				_, principalUID, _, _, err := generateNewPrincipalForDNChanged(u.conn, crtb.UserPrincipalName, userScopeType, u.userObjectFilter,
					u.baseDN, u.userUniqueAttribute, u.userSearchAttribute)
				if err != nil {
					if strings.EqualFold(err.Error(), NoResultFoundError) {
						logrus.Warnf("No identities can be retrieved to get crtb %s, ns %s, principal %s", crtb.Name, crtb.Namespace, crtb.UserPrincipalName)
						u.manualCRTB = append(u.manualCRTB, crtb)
					} else if strings.EqualFold(err.Error(), MutipleResultFoundError) {
						logrus.Warnf("sync crtb %s, ns %s:: find multiple users for principal %s", crtb.Name, crtb.Namespace, crtb.UserPrincipalName)
						u.manualCRTB = append(u.manualCRTB, crtb)
					}
					continue
				}
				crtb.UserPrincipalName = principalUID
				preparedCRTB = append(preparedCRTB, crtb)
			} else if crtb.GroupPrincipalName != "" && strings.HasPrefix(crtb.GroupPrincipalName, groupScopeType) {
				_, principalUID, _, _, err := generateNewPrincipalForDNChanged(u.conn, crtb.GroupPrincipalName, groupScopeType, u.groupObjectFilter,
					u.groupSearchDN, u.groupUniqueAttribute, u.groupSearchAttribute)
				if err != nil {
					if strings.EqualFold(err.Error(), NoResultFoundError) {
						logrus.Warnf("No identities can be retrieved to get crtb %s, ns %s, principal %s", crtb.Name, crtb.Namespace, crtb.GroupPrincipalName)
						u.manualCRTB = append(u.manualCRTB, crtb)
					} else if strings.EqualFold(err.Error(), MutipleResultFoundError) {
						logrus.Warnf("sync crtb %s, ns %s:: find multiple group for principal %s", crtb.Name, crtb.Namespace, crtb.GroupPrincipalName)
						u.manualCRTB = append(u.manualCRTB, crtb)
					}
					continue
				}
				crtb.GroupPrincipalName = principalUID
				preparedCRTB = append(preparedCRTB, crtb)
			}
		}
	}

	return preparedCRTB
}

func (u *AuthUtil) preparePRTB(prtbList []v3.ProjectRoleTemplateBinding, userScopeType, groupScopeType string) []v3.ProjectRoleTemplateBinding {
	preparedPRTB := []v3.ProjectRoleTemplateBinding{}
	failedPRTB := []v3.ProjectRoleTemplateBinding{}
	for _, prtb := range prtbList {
		var principalID string
		if prtb.UserPrincipalName != "" {
			principalID = prtb.UserPrincipalName
		} else if prtb.GroupPrincipalName != "" {
			principalID = prtb.GroupPrincipalName
		}
		if principalID == "" {
			continue
		}

		principalUID, _, err := u.prepareForNewPrincipal(principalID, userScopeType, groupScopeType)
		if err != nil {
			if strings.EqualFold(err.Error(), NoResultFoundError) {
				logrus.Warnf("No identies found using current principalID %s for prtb %s, ns %s", principalID, prtb.Name, prtb.Namespace)
				failedPRTB = append(failedPRTB, prtb)
			} else {
				logrus.Errorf("failed to get user using principalID %s for prtb %s, ns %s, err: %v", principalID, prtb.Name, prtb.Namespace, err)
			}
			continue
		}

		if prtb.UserPrincipalName != "" {
			prtb.UserPrincipalName = principalUID
		} else if prtb.GroupPrincipalName != "" {
			prtb.GroupPrincipalName = principalUID
		}

		preparedPRTB = append(preparedPRTB, prtb)
	}

	if len(failedPRTB) > 0 {
		logrus.Println("================ Search for DN changed PRTB users/groups ================")
		for _, prtb := range failedPRTB {
			if prtb.UserPrincipalName != "" && strings.HasPrefix(prtb.UserPrincipalName, userScopeType) {
				_, principalUID, _, _, err := generateNewPrincipalForDNChanged(u.conn, prtb.UserPrincipalName, userScopeType, u.userObjectFilter,
					u.baseDN, u.userUniqueAttribute, u.userSearchAttribute)
				if err != nil {
					if strings.EqualFold(err.Error(), NoResultFoundError) {
						logrus.Warnf("No identities can be retrieved to get crtb %s, ns %s, principal %s", prtb.Name, prtb.Namespace, prtb.UserPrincipalName)
						u.manualPRTB = append(u.manualPRTB, prtb)
					} else if strings.EqualFold(err.Error(), MutipleResultFoundError) {
						logrus.Warnf("sync crtb %s, ns %s:: find multiple users for principal %s", prtb.Name, prtb.Namespace, prtb.UserPrincipalName)
						u.manualPRTB = append(u.manualPRTB, prtb)
					}
					continue
				}
				prtb.UserPrincipalName = principalUID
				preparedPRTB = append(preparedPRTB, prtb)
			} else if prtb.GroupPrincipalName != "" && strings.HasPrefix(prtb.GroupPrincipalName, groupScopeType) {
				_, principalUID, _, _, err := generateNewPrincipalForDNChanged(u.conn, prtb.GroupPrincipalName, groupScopeType, u.groupObjectFilter,
					u.groupSearchDN, u.groupUniqueAttribute, u.groupSearchAttribute)
				if err != nil {
					if strings.EqualFold(err.Error(), NoResultFoundError) {
						logrus.Warnf("No identities can be retrieved to get crtb %s, ns %s, principal %s", prtb.Name, prtb.Namespace, prtb.GroupPrincipalName)
						u.manualPRTB = append(u.manualPRTB, prtb)
					} else if strings.EqualFold(err.Error(), MutipleResultFoundError) {
						logrus.Warnf("sync crtb %s, ns %s:: find multiple group for principal %s", prtb.Name, prtb.Namespace, prtb.UserPrincipalName)
						u.manualPRTB = append(u.manualPRTB, prtb)
					}
					continue
				}
				prtb.GroupPrincipalName = principalUID
				preparedPRTB = append(preparedPRTB, prtb)
			}
		}
	}

	return preparedPRTB
}

func (u *AuthUtil) prepareAllowedPrincipals(userScopeType, groupScopeType string, oldPrincipals []string) ([]string, error) {
	newAllowedPrincipals := []string{}
	failedPrincipalIDs := []string{}
	for _, allowedPrincipal := range oldPrincipals {
		if strings.HasPrefix(allowedPrincipal, fmt.Sprintf("%s_uid://", userScopeType)) ||
			strings.HasPrefix(allowedPrincipal, fmt.Sprintf("%s_uid://", groupScopeType)) {
			newAllowedPrincipals = append(newAllowedPrincipals, allowedPrincipal)
			continue
		}
		logrus.Infof("Prepare update for allowedPrincipal %s", allowedPrincipal)
		newPrincipal, _, err := u.prepareForNewPrincipal(allowedPrincipal, userScopeType, groupScopeType)
		if err != nil {
			if err != nil {
				if strings.EqualFold(err.Error(), NoResultFoundError) {
					logrus.Warnf("No identies found using current principal %s ", allowedPrincipal)
					failedPrincipalIDs = append(failedPrincipalIDs, allowedPrincipal)
					continue
				}
				return nil, err
			}
		}
		newAllowedPrincipals = append(newAllowedPrincipals, newPrincipal)
	}

	manualPrincipal := []string{}
	if len(failedPrincipalIDs) > 0 {
		logrus.Println("================ AuthProvider:: Search for DN changed principals ================")
		for _, principal := range failedPrincipalIDs {
			if principal != "" && strings.HasPrefix(principal, fmt.Sprintf("%s://", userScopeType)) {
				_, principalUID, _, _, err := generateNewPrincipalForDNChanged(u.conn, principal, fmt.Sprintf("%s://", userScopeType), u.userObjectFilter,
					u.baseDN, u.userUniqueAttribute, u.userSearchAttribute)
				if err != nil {
					if strings.EqualFold(err.Error(), NoResultFoundError) {
						logrus.Warnf("No identities can be retrieved to get principal %s", principal)
						manualPrincipal = append(manualPrincipal, principal)
					} else if strings.EqualFold(err.Error(), MutipleResultFoundError) {
						logrus.Warnf("find multiple users for principal %s", principal)
						manualPrincipal = append(manualPrincipal, principal)
					}
					continue
				}
				newAllowedPrincipals = append(newAllowedPrincipals, principalUID)
			} else if principal != "" && strings.HasPrefix(principal, fmt.Sprintf("%s://", groupScopeType)) {
				_, principalUID, _, _, err := generateNewPrincipalForDNChanged(u.conn, principal, fmt.Sprintf("%s://", groupScopeType), u.groupObjectFilter,
					u.groupSearchDN, u.groupUniqueAttribute, u.groupSearchAttribute)
				if err != nil {
					if strings.EqualFold(err.Error(), NoResultFoundError) {
						logrus.Warnf("No identities can be retrieved to get principal %s", principal)
						manualPrincipal = append(manualPrincipal, principal)
					} else if strings.EqualFold(err.Error(), MutipleResultFoundError) {
						logrus.Warnf("find multiple group for principal %s", principal)
						manualPrincipal = append(manualPrincipal, principal)
					}
					continue
				}
				newAllowedPrincipals = append(newAllowedPrincipals, principalUID)
			}
		}
	}

	if len(manualPrincipal) > 0 {
		return nil, fmt.Errorf("couldn't hanle DN changed principals, please manual check for these principals set for Auth provider: %v", manualPrincipal)
	}
	return newAllowedPrincipals, nil
}

func (u *AuthUtil) UpdateGRB(grbList []v3.GlobalRoleBinding, isDryRun bool) {
	logrus.Infof("RESULT:: Will update %d grb", len(grbList))
	for _, grb := range grbList {
		if !isDryRun {
			_, err := u.management.GlobalRoleBinding().Update(&grb)
			if err != nil {
				logrus.Errorf("failed to update grb %s, with error: %v", grb.Name, err)
				continue
			}
		} else {
			logrus.Infof("Update GRB %s, with group principal %s", grb.Name, grb.GroupPrincipalName)
		}
	}
}

func (u *AuthUtil) UpdateCRTB(crtbList []v3.ClusterRoleTemplateBinding, isDryRun bool) {
	logrus.Infof("RESULT:: Will update %d crtb", len(crtbList))
	for _, crtb := range crtbList {
		if !isDryRun {
			// create a new one
			newCRTB := &v3.ClusterRoleTemplateBinding{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: crtb.GenerateName,
					Namespace:    crtb.Namespace,
				},
				RoleTemplateName:   crtb.RoleTemplateName,
				UserName:           crtb.UserName,
				UserPrincipalName:  crtb.UserPrincipalName,
				GroupName:          crtb.GroupName,
				GroupPrincipalName: crtb.GroupPrincipalName,
				ClusterName:        crtb.ClusterName,
			}
			err := u.management.ClusterRoleTemplateBinding().Delete(crtb.Namespace, crtb.Name, &metav1.DeleteOptions{})
			if err != nil {
				logrus.Errorf("failed to remove old crtb %++v with error: %v", crtb, err)
				continue
			}
			_, err = u.management.ClusterRoleTemplateBinding().Create(newCRTB)
			if err != nil {
				logrus.Errorf("failed to create new crtb %++v with error: %v", newCRTB, err)
				continue
			}
		} else {
			logrus.Infof("Will update CRTB %s, ns %s with user principal %s, group principal %s", crtb.Name, crtb.Namespace, crtb.UserPrincipalName, crtb.GroupPrincipalName)
		}
	}
}

func (u *AuthUtil) UpdatePRTB(prtbList []v3.ProjectRoleTemplateBinding, isDryRun bool) {
	logrus.Infof("RESULT:: Will update %d prtb", len(prtbList))
	for _, prtb := range prtbList {
		if !isDryRun {
			newPRTB := &v3.ProjectRoleTemplateBinding{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: prtb.GenerateName,
					Namespace:    prtb.Namespace,
				},
				RoleTemplateName:   prtb.RoleTemplateName,
				UserName:           prtb.UserName,
				UserPrincipalName:  prtb.UserPrincipalName,
				GroupName:          prtb.GroupName,
				GroupPrincipalName: prtb.GroupPrincipalName,
				ProjectName:        prtb.ProjectName,
				ServiceAccount:     prtb.ServiceAccount,
			}
			err := u.management.ProjectRoleTemplateBinding().Delete(prtb.Namespace, prtb.Name, &metav1.DeleteOptions{})
			if err != nil {
				logrus.Errorf("remove old prtb %++v error: %v", prtb, err)
				continue
			}
			_, err = u.management.ProjectRoleTemplateBinding().Create(newPRTB)
			if err != nil {
				logrus.Errorf("failed to create new prtb %++v with error: %v", prtb, err)
				continue
			}
		} else {
			logrus.Infof("Will update PRTB %s, ns %s with user principal %s, group principal %s", prtb.Name, prtb.Namespace, prtb.UserPrincipalName, prtb.GroupPrincipalName)
		}
	}
}

func (u *AuthUtil) UpdateUser(userList map[string]v3.User, isDryRun bool) {
	logrus.Infof("RESULT:: Will update %d users", len(userList))
	for _, user := range userList {
		if !isDryRun {
			_, err := u.management.User().Update(&user)
			if err != nil {
				logrus.Errorf("failed to update user %s with error: %v", user.Name, err)
				logrus.Infof("failed user is: %++v", user)
				continue
			}
		} else {
			logrus.Infof("DRY_RUN:: User %s need to sync by principalIDs: %v", user.Name, user.PrincipalIDs)
		}
	}
}

func (u *AuthUtil) prepareForNewPrincipal(principalID, userScopeType, groupScopeType string) (string, string, error) {
	externalID, scope, err := GetDNAndScopeFromPrincipalID(principalID)
	if err != nil {
		return "", "", err
	}

	var filter, searchString, uniqueAttribute, scopeType string
	var searchCode int
	var searchAttribute []string

	if !strings.HasSuffix(principalID, u.baseDN) {
		filter = fmt.Sprintf("(&%s(%v=%v))", u.userObjectFilter, "objectGUID", EscapeUUID(externalID))
		searchCode = ldapv3.ScopeWholeSubtree
		searchString = u.baseDN
	} else {
		searchCode = ldapv3.ScopeBaseObject
		searchString = externalID
	}

	if strings.HasPrefix(principalID, fmt.Sprintf("%s", userScopeType)) {
		if filter == "" {
			filter = u.userObjectFilter
		}
		scopeType = userScopeType
		uniqueAttribute = u.userUniqueAttribute
		searchAttribute = u.userSearchAttribute
	} else {
		scopeType = groupScopeType
		filter = u.groupObjectFilter
		uniqueAttribute = u.groupUniqueAttribute
		searchAttribute = u.groupSearchAttribute
	}

	results, err := getLdapUserForUpdate(u.conn, searchString, filter, searchCode, searchAttribute)
	if err != nil {
		return "", "", err
	}

	entry := results.Entries[0]
	_, newPrincipalID, uniqueID := getUniqueAttribute(entry, scopeType, scope, uniqueAttribute)
	logrus.Infof("Old user allowedPrincipal %s will be replaced with new uniqueID: %s", principalID, uniqueID)
	return newPrincipalID, uniqueID, nil
}

func GetConfig(c *Config) (*rest.Config, error) {
	if c.KubeConfig != "" {
		return clientcmd.BuildConfigFromFlags("", c.KubeConfig)
	}
	if c.RestConfig != nil {
		return c.RestConfig, nil
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

func NewLDAPConn(servers []string, TLS, startTLS bool, port int64, connectionTimeout int64, caPool *x509.CertPool) (*ldapv3.Conn, error) {
	var lConn *ldapv3.Conn
	var err error
	var tlsConfig *tls.Config
	ldapv3.DefaultTimeout = time.Duration(connectionTimeout) * time.Millisecond
	// TODO implment multi-server support
	if len(servers) != 1 {
		return nil, errors.New("invalid server config. only exactly 1 server is currently supported")
	}
	server := servers[0]
	tlsConfig = &tls.Config{RootCAs: caPool, InsecureSkipVerify: false, ServerName: server}
	if TLS {
		lConn, err = ldapv3.DialTLS("tcp", fmt.Sprintf("%s:%d", server, port), tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("Error creating ssl connection: %v", err)
		}
	} else if startTLS {
		lConn, err = ldapv3.Dial("tcp", fmt.Sprintf("%s:%d", server, port))
		if err != nil {
			return nil, fmt.Errorf("Error creating connection for startTLS: %v", err)
		}
		if err := lConn.StartTLS(tlsConfig); err != nil {
			return nil, fmt.Errorf("Error upgrading startTLS connection: %v", err)
		}
	} else {
		lConn, err = ldapv3.Dial("tcp", fmt.Sprintf("%s:%d", server, port))
		if err != nil {
			return nil, fmt.Errorf("Error creating connection: %v", err)
		}
	}

	lConn.SetTimeout(time.Duration(connectionTimeout) * time.Millisecond)

	return lConn, nil
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

func GetUsersForUpdate(management managementv3.Interface, authType string) (map[string]v32.User, error) {
	userList, err := management.User().List(metav1.ListOptions{})
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

func ReadFromSecret(coreClient v1.CoreV1Interface, secretInfo string, field string) (string, error) {
	if strings.HasPrefix(secretInfo, SecretsNamespace) {
		split := strings.SplitN(secretInfo, ":", 2)
		if len(split) == 2 {
			secret, err := coreClient.Secrets(split[0]).Get(context.TODO(), split[1], metav1.GetOptions{})
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

func generateNewPrincipalForDNChanged(lConn *ldapv3.Conn, principalID, scopeType, objectFilter,
	baseDN, uniqueAttribute string, searchAttributes []string) (string, string, string, *ldapv3.SearchResult, error) {
	externalID, scope, err := GetDNAndScopeFromPrincipalID(principalID)
	if err != nil {
		logrus.Errorf("Error to get DN from principal %s with error: %v", principalID, err)
		return "", "", "", nil, err
	}
	dnArray := strings.Split(externalID, ",")
	// got first attribute of DN
	filter := fmt.Sprintf("(&%s(%s))", objectFilter, dnArray[0])
	var entry *ldapv3.Entry
	results, err := getLdapUserForUpdate(lConn, baseDN, filter, ldapv3.ScopeWholeSubtree, searchAttributes)
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

//func generateNewPrincipalByDN(lConn *ldapv3.Conn, principalID, scopeType,
//	filter, uniqueAttribute string, searchAttribute []string) (string, string, string, error) {
//	externalID, scope, err := GetDNAndScopeFromPrincipalID(principalID)
//	if err != nil {
//		return "", "", "", err
//	}
//
//	results, err := getLdapUserForUpdate(lConn, externalID, filter, ldapv3.ScopeBaseObject, searchAttribute)
//	if err != nil {
//		return "", "", "", err
//	}
//	entry := results.Entries[0]
//	principalIDOfDN, principalOfUID, uniqueID := getUniqueAttribute(entry, scopeType, scope, uniqueAttribute)
//	return principalIDOfDN, principalOfUID, uniqueID, nil
//}

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

func getGroupPrincipal(userID, authConfigType string, management managementv3.Interface) ([]v3.Principal, error) {
	userAttributes, err := management.UserAttribute().Get(userID, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	groupPrincipals := userAttributes.GroupPrincipals[authConfigType].Items

	return groupPrincipals, nil
}

func checkForGroups(userID, authConfigType string, management managementv3.Interface, results *ldapv3.SearchResult) ([]*ldapv3.Entry, error) {
	groupPrincipals, err := getGroupPrincipal(userID, authConfigType, management)
	if err != nil {
		return nil, err
	}
	// check for groups
	checkEntries := []*ldapv3.Entry{}
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

// EscapeUUID will take a UUID string in string form and will add backslashes to every 2nd character.
// The returned result is the string that needs to be added to the LDAP filter to properly filter
// by objectGUID, which is stored as binary data.
func EscapeUUID(s string) string {
	var buffer bytes.Buffer
	var n1 = 1
	var l1 = len(s) - 1
	buffer.WriteRune('\\')
	for i, r := range s {
		buffer.WriteRune(r)
		if i%2 == n1 && i != l1 {
			buffer.WriteRune('\\')
		}
	}
	return buffer.String()
}
