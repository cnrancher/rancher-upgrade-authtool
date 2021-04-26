package client

import (
	"github.com/rancher/norman/types"
)

const (
	NotificationTemplateType                      = "notificationTemplate"
	NotificationTemplateFieldAnnotations          = "annotations"
	NotificationTemplateFieldClusterID            = "clusterId"
	NotificationTemplateFieldContent              = "content"
	NotificationTemplateFieldCreated              = "created"
	NotificationTemplateFieldCreatorID            = "creatorId"
	NotificationTemplateFieldEnabled              = "enabled"
	NotificationTemplateFieldLabels               = "labels"
	NotificationTemplateFieldName                 = "name"
	NotificationTemplateFieldNamespaceId          = "namespaceId"
	NotificationTemplateFieldOwnerReferences      = "ownerReferences"
	NotificationTemplateFieldRemoved              = "removed"
	NotificationTemplateFieldState                = "state"
	NotificationTemplateFieldStatus               = "status"
	NotificationTemplateFieldTransitioning        = "transitioning"
	NotificationTemplateFieldTransitioningMessage = "transitioningMessage"
	NotificationTemplateFieldUUID                 = "uuid"
)

type NotificationTemplate struct {
	types.Resource
	Annotations          map[string]string           `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	ClusterID            string                      `json:"clusterId,omitempty" yaml:"clusterId,omitempty"`
	Content              string                      `json:"content,omitempty" yaml:"content,omitempty"`
	Created              string                      `json:"created,omitempty" yaml:"created,omitempty"`
	CreatorID            string                      `json:"creatorId,omitempty" yaml:"creatorId,omitempty"`
	Enabled              bool                        `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Labels               map[string]string           `json:"labels,omitempty" yaml:"labels,omitempty"`
	Name                 string                      `json:"name,omitempty" yaml:"name,omitempty"`
	NamespaceId          string                      `json:"namespaceId,omitempty" yaml:"namespaceId,omitempty"`
	OwnerReferences      []OwnerReference            `json:"ownerReferences,omitempty" yaml:"ownerReferences,omitempty"`
	Removed              string                      `json:"removed,omitempty" yaml:"removed,omitempty"`
	State                string                      `json:"state,omitempty" yaml:"state,omitempty"`
	Status               *NotificationTemplateStatus `json:"status,omitempty" yaml:"status,omitempty"`
	Transitioning        string                      `json:"transitioning,omitempty" yaml:"transitioning,omitempty"`
	TransitioningMessage string                      `json:"transitioningMessage,omitempty" yaml:"transitioningMessage,omitempty"`
	UUID                 string                      `json:"uuid,omitempty" yaml:"uuid,omitempty"`
}

type NotificationTemplateCollection struct {
	types.Collection
	Data   []NotificationTemplate `json:"data,omitempty"`
	client *NotificationTemplateClient
}

type NotificationTemplateClient struct {
	apiClient *Client
}

type NotificationTemplateOperations interface {
	List(opts *types.ListOpts) (*NotificationTemplateCollection, error)
	ListAll(opts *types.ListOpts) (*NotificationTemplateCollection, error)
	Create(opts *NotificationTemplate) (*NotificationTemplate, error)
	Update(existing *NotificationTemplate, updates interface{}) (*NotificationTemplate, error)
	Replace(existing *NotificationTemplate) (*NotificationTemplate, error)
	ByID(id string) (*NotificationTemplate, error)
	Delete(container *NotificationTemplate) error
}

func newNotificationTemplateClient(apiClient *Client) *NotificationTemplateClient {
	return &NotificationTemplateClient{
		apiClient: apiClient,
	}
}

func (c *NotificationTemplateClient) Create(container *NotificationTemplate) (*NotificationTemplate, error) {
	resp := &NotificationTemplate{}
	err := c.apiClient.Ops.DoCreate(NotificationTemplateType, container, resp)
	return resp, err
}

func (c *NotificationTemplateClient) Update(existing *NotificationTemplate, updates interface{}) (*NotificationTemplate, error) {
	resp := &NotificationTemplate{}
	err := c.apiClient.Ops.DoUpdate(NotificationTemplateType, &existing.Resource, updates, resp)
	return resp, err
}

func (c *NotificationTemplateClient) Replace(obj *NotificationTemplate) (*NotificationTemplate, error) {
	resp := &NotificationTemplate{}
	err := c.apiClient.Ops.DoReplace(NotificationTemplateType, &obj.Resource, obj, resp)
	return resp, err
}

func (c *NotificationTemplateClient) List(opts *types.ListOpts) (*NotificationTemplateCollection, error) {
	resp := &NotificationTemplateCollection{}
	err := c.apiClient.Ops.DoList(NotificationTemplateType, opts, resp)
	resp.client = c
	return resp, err
}

func (c *NotificationTemplateClient) ListAll(opts *types.ListOpts) (*NotificationTemplateCollection, error) {
	resp := &NotificationTemplateCollection{}
	resp, err := c.List(opts)
	if err != nil {
		return resp, err
	}
	data := resp.Data
	for next, err := resp.Next(); next != nil && err == nil; next, err = next.Next() {
		data = append(data, next.Data...)
		resp = next
		resp.Data = data
	}
	if err != nil {
		return resp, err
	}
	return resp, err
}

func (cc *NotificationTemplateCollection) Next() (*NotificationTemplateCollection, error) {
	if cc != nil && cc.Pagination != nil && cc.Pagination.Next != "" {
		resp := &NotificationTemplateCollection{}
		err := cc.client.apiClient.Ops.DoNext(cc.Pagination.Next, resp)
		resp.client = cc.client
		return resp, err
	}
	return nil, nil
}

func (c *NotificationTemplateClient) ByID(id string) (*NotificationTemplate, error) {
	resp := &NotificationTemplate{}
	err := c.apiClient.Ops.DoByID(NotificationTemplateType, id, resp)
	return resp, err
}

func (c *NotificationTemplateClient) Delete(container *NotificationTemplate) error {
	return c.apiClient.Ops.DoResourceDelete(NotificationTemplateType, &container.Resource)
}
