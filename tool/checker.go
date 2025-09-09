package tool

import (
	"context"
	"fmt"
	"strings"

	"github.com/JacieChao/rancher-upgrade-authtool/pkg/generated/controllers/management.cattle.io"
	managementv3 "github.com/JacieChao/rancher-upgrade-authtool/pkg/generated/controllers/management.cattle.io/v3"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	rbacv1 "k8s.io/client-go/kubernetes/typed/rbac/v1"
	"k8s.io/client-go/tools/clientcmd"
)

var orphanBindings []string

type Client struct {
	mgmt        managementv3.Interface
	mgmtRbac    rbacv1.RbacV1Interface
	clusterRbac rbacv1.RbacV1Interface
}

func Checker(c *Config) error {
	client := &Client{}
	if c.KubeConfig != "" {
		localRestConfig, err := clientcmd.BuildConfigFromFlags("", c.KubeConfig)
		if err != nil {
			return err
		}
		mgmt, err := management.NewFactoryFromConfig(localRestConfig)
		if err != nil {
			return err
		}
		client.mgmt = mgmt.Management().V3()
		k8sClient, err := kubernetes.NewForConfig(localRestConfig)
		if err != nil {
			return err
		}
		client.mgmtRbac = k8sClient.RbacV1()
	}

	if c.TargetClusterConfig != "" {
		restCfg, err := clientcmd.BuildConfigFromFlags("", c.TargetClusterConfig)
		if err != nil {
			return err
		}
		k8sClient, err := kubernetes.NewForConfig(restCfg)
		if err != nil {
			return err
		}
		client.clusterRbac = k8sClient.RbacV1()
	}

	users, err := client.getUsers()
	if err != nil {
		return err
	}

	// get crtb
	crtb, err := client.mgmt.ClusterRoleTemplateBinding().List(c.Cluster, metav1.ListOptions{})
	if err != nil {
		return err
	}

	// get prtb
	prtbList := []v3.ProjectRoleTemplateBinding{}
	projects, err := client.getProjects(c.Cluster)
	if err != nil {
		return err
	}
	for _, project := range projects {
		prtb, err := client.mgmt.ProjectRoleTemplateBinding().List(project.Name, metav1.ListOptions{})
		if err != nil {
			logrus.Errorf("failed to get prtb for project %s: %v", project.Name, err)
			continue
		}
		prtbList = append(prtbList, prtb.Items...)
	}

	crbs, err := client.clusterRbac.ClusterRoleBindings().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	rbs, err := client.clusterRbac.RoleBindings("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	filterRBs := []v1.RoleBinding{}
	for _, rb := range rbs.Items {
		// skip for helm-operation bindings
		if strings.HasPrefix(rb.Name, "helm-operation") {
			logrus.Infof("skip for helm-operation rolebindings for namespace=%s, name=%s", rb.Namespace, rb.Name)
			continue
		}
		filterRBs = append(filterRBs, rb)
	}

	// check user rbac
	for _, user := range users {
		logrus.Infof("check rbac for user %s: %v", user.Name, user.PrincipalIDs)
		err = client.checkPermission(user, crtb.Items, prtbList, crbs.Items, filterRBs)
		if err != nil {
			logrus.Errorf("failed to check permission for user %s: %v", user.Name, err)
			continue
		}
	}

	logrus.Info("Found orphan bindings below")
	logrus.Info("----------------------------------------------")
	// Output for orphan bindings
	for _, orphan := range orphanBindings {
		orphanResources := strings.Split(orphan, "_")
		if len(orphanResources) == 1 {
			logrus.Warnf("found orphan clusterrolebinding %s", orphan)
		} else if len(orphanResources) == 2 {
			logrus.Warnf("found orphan rolebinding namespace=%s, name=%s", orphanResources[0], orphanResources[1])
		}
	}
	logrus.Info("----------------------------------------------")
	logrus.Infof("check finish")

	return nil
}

func (c *Client) getUsers() ([]v3.User, error) {
	// only check local user and AD user
	users, err := c.mgmt.User().List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	userList := []v3.User{}
	for _, user := range users.Items {
		if len(user.PrincipalIDs) == 1 {
			userList = append(userList, user)
		} else {
			for _, principal := range user.PrincipalIDs {
				if strings.HasPrefix(principal, ActiveDirectoryAuth) {
					userList = append(userList, user)
					break
				}
			}
		}
	}

	return userList, nil
}

func (c *Client) getProjects(cluster string) ([]v3.Project, error) {
	projects, err := c.mgmt.Project().List(cluster, metav1.ListOptions{})
	return projects.Items, err
}

func (c *Client) checkPermission(user v3.User, crtbs []v3.ClusterRoleTemplateBinding,
	prtbs []v3.ProjectRoleTemplateBinding, crbs []v1.ClusterRoleBinding, rbs []v1.RoleBinding) error {
	userCRTB := map[string]v3.ClusterRoleTemplateBinding{}
	for _, crtb := range crtbs {
		if crtb.UserName == user.Name {
			userCRTB[fmt.Sprintf("%s_%s", crtb.Namespace, crtb.Name)] = crtb
		}
	}
	userPRTB := map[string]v3.ProjectRoleTemplateBinding{}
	for _, prtb := range prtbs {
		if prtb.UserName == user.Name {
			userPRTB[fmt.Sprintf("%s_%s", prtb.Namespace, prtb.Name)] = prtb
		}
	}
	// check cluster rbac
	// authz.cluster.cattle.io/rtb-owner-updated: c-697sk_crtb-h22f7
	// p-jgz2j_prtb-kfvwm: owner-user
	for _, crb := range crbs {
		isOwnedCRTB := false
		isUser := false
		for _, sub := range crb.Subjects {
			if sub.Kind == "User" && sub.Name == user.Name {
				isUser = true
				// check crtb label
				rtbLabel := crb.Labels["authz.cluster.cattle.io/rtb-owner-updated"]
				if rtbLabel != "" {
					if _, ok := userCRTB[rtbLabel]; ok {
						isOwnedCRTB = true
						break
					}
				}
				// check for prtb label
				for key := range userPRTB {
					if _, ok := crb.Labels[key]; ok {
						isOwnedCRTB = true
						break
					}
				}
			}
		}
		if isUser && !isOwnedCRTB {
			if strings.HasPrefix(crb.Name, "globaladmin") {
				logrus.Infof("found admin permission %s for user %s: %v", crb.Name, user.Name, user.PrincipalIDs)
				break
			}
			orphanBindings = append(orphanBindings, crb.Name)
			//logrus.Warnf("found orphan clusterrolebinding %s", crb.Name)
		}
	}

	// check project rbac
	// authz.cluster.cattle.io/rtb-owner-updated: p-jgz2j_prtb-kfvwm
	for _, rb := range rbs {
		isOwnedRB := false
		isUser := false
		for _, sub := range rb.Subjects {
			if sub.Kind == "User" && sub.Name == user.Name {
				isUser = true
				// check prtb label
				rtbLabel := rb.Labels["authz.cluster.cattle.io/rtb-owner-updated"]
				if rtbLabel != "" {
					if _, ok := userPRTB[rtbLabel]; ok {
						isOwnedRB = true
						break
					}
				}
			}
		}
		if isUser && !isOwnedRB {
			orphanBindings = append(orphanBindings, fmt.Sprintf("%s_%s", rb.Namespace, rb.Name))
			//logrus.Warnf("found orphan rolebinding namespace=%s, name=%s", rb.Namespace, rb.Name)
		}
	}

	return nil
}
