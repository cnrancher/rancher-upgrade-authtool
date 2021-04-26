package v3

import (
	"context"
	"time"

	"github.com/rancher/norman/controller"
	"github.com/rancher/norman/objectclient"
	"github.com/rancher/norman/resource"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

var (
	NotificationTemplateGroupVersionKind = schema.GroupVersionKind{
		Version: Version,
		Group:   GroupName,
		Kind:    "NotificationTemplate",
	}
	NotificationTemplateResource = metav1.APIResource{
		Name:         "notificationtemplates",
		SingularName: "notificationtemplate",
		Namespaced:   true,

		Kind: NotificationTemplateGroupVersionKind.Kind,
	}

	NotificationTemplateGroupVersionResource = schema.GroupVersionResource{
		Group:    GroupName,
		Version:  Version,
		Resource: "notificationtemplates",
	}
)

func init() {
	resource.Put(NotificationTemplateGroupVersionResource)
}

func NewNotificationTemplate(namespace, name string, obj NotificationTemplate) *NotificationTemplate {
	obj.APIVersion, obj.Kind = NotificationTemplateGroupVersionKind.ToAPIVersionAndKind()
	obj.Name = name
	obj.Namespace = namespace
	return &obj
}

type NotificationTemplateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NotificationTemplate `json:"items"`
}

type NotificationTemplateHandlerFunc func(key string, obj *NotificationTemplate) (runtime.Object, error)

type NotificationTemplateChangeHandlerFunc func(obj *NotificationTemplate) (runtime.Object, error)

type NotificationTemplateLister interface {
	List(namespace string, selector labels.Selector) (ret []*NotificationTemplate, err error)
	Get(namespace, name string) (*NotificationTemplate, error)
}

type NotificationTemplateController interface {
	Generic() controller.GenericController
	Informer() cache.SharedIndexInformer
	Lister() NotificationTemplateLister
	AddHandler(ctx context.Context, name string, handler NotificationTemplateHandlerFunc)
	AddFeatureHandler(ctx context.Context, enabled func() bool, name string, sync NotificationTemplateHandlerFunc)
	AddClusterScopedHandler(ctx context.Context, name, clusterName string, handler NotificationTemplateHandlerFunc)
	AddClusterScopedFeatureHandler(ctx context.Context, enabled func() bool, name, clusterName string, handler NotificationTemplateHandlerFunc)
	Enqueue(namespace, name string)
	EnqueueAfter(namespace, name string, after time.Duration)
	Sync(ctx context.Context) error
	Start(ctx context.Context, threadiness int) error
}

type NotificationTemplateInterface interface {
	ObjectClient() *objectclient.ObjectClient
	Create(*NotificationTemplate) (*NotificationTemplate, error)
	GetNamespaced(namespace, name string, opts metav1.GetOptions) (*NotificationTemplate, error)
	Get(name string, opts metav1.GetOptions) (*NotificationTemplate, error)
	Update(*NotificationTemplate) (*NotificationTemplate, error)
	Delete(name string, options *metav1.DeleteOptions) error
	DeleteNamespaced(namespace, name string, options *metav1.DeleteOptions) error
	List(opts metav1.ListOptions) (*NotificationTemplateList, error)
	ListNamespaced(namespace string, opts metav1.ListOptions) (*NotificationTemplateList, error)
	Watch(opts metav1.ListOptions) (watch.Interface, error)
	DeleteCollection(deleteOpts *metav1.DeleteOptions, listOpts metav1.ListOptions) error
	Controller() NotificationTemplateController
	AddHandler(ctx context.Context, name string, sync NotificationTemplateHandlerFunc)
	AddFeatureHandler(ctx context.Context, enabled func() bool, name string, sync NotificationTemplateHandlerFunc)
	AddLifecycle(ctx context.Context, name string, lifecycle NotificationTemplateLifecycle)
	AddFeatureLifecycle(ctx context.Context, enabled func() bool, name string, lifecycle NotificationTemplateLifecycle)
	AddClusterScopedHandler(ctx context.Context, name, clusterName string, sync NotificationTemplateHandlerFunc)
	AddClusterScopedFeatureHandler(ctx context.Context, enabled func() bool, name, clusterName string, sync NotificationTemplateHandlerFunc)
	AddClusterScopedLifecycle(ctx context.Context, name, clusterName string, lifecycle NotificationTemplateLifecycle)
	AddClusterScopedFeatureLifecycle(ctx context.Context, enabled func() bool, name, clusterName string, lifecycle NotificationTemplateLifecycle)
}

type notificationTemplateLister struct {
	controller *notificationTemplateController
}

func (l *notificationTemplateLister) List(namespace string, selector labels.Selector) (ret []*NotificationTemplate, err error) {
	err = cache.ListAllByNamespace(l.controller.Informer().GetIndexer(), namespace, selector, func(obj interface{}) {
		ret = append(ret, obj.(*NotificationTemplate))
	})
	return
}

func (l *notificationTemplateLister) Get(namespace, name string) (*NotificationTemplate, error) {
	var key string
	if namespace != "" {
		key = namespace + "/" + name
	} else {
		key = name
	}
	obj, exists, err := l.controller.Informer().GetIndexer().GetByKey(key)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(schema.GroupResource{
			Group:    NotificationTemplateGroupVersionKind.Group,
			Resource: "notificationTemplate",
		}, key)
	}
	return obj.(*NotificationTemplate), nil
}

type notificationTemplateController struct {
	controller.GenericController
}

func (c *notificationTemplateController) Generic() controller.GenericController {
	return c.GenericController
}

func (c *notificationTemplateController) Lister() NotificationTemplateLister {
	return &notificationTemplateLister{
		controller: c,
	}
}

func (c *notificationTemplateController) AddHandler(ctx context.Context, name string, handler NotificationTemplateHandlerFunc) {
	c.GenericController.AddHandler(ctx, name, func(key string, obj interface{}) (interface{}, error) {
		if obj == nil {
			return handler(key, nil)
		} else if v, ok := obj.(*NotificationTemplate); ok {
			return handler(key, v)
		} else {
			return nil, nil
		}
	})
}

func (c *notificationTemplateController) AddFeatureHandler(ctx context.Context, enabled func() bool, name string, handler NotificationTemplateHandlerFunc) {
	c.GenericController.AddHandler(ctx, name, func(key string, obj interface{}) (interface{}, error) {
		if !enabled() {
			return nil, nil
		} else if obj == nil {
			return handler(key, nil)
		} else if v, ok := obj.(*NotificationTemplate); ok {
			return handler(key, v)
		} else {
			return nil, nil
		}
	})
}

func (c *notificationTemplateController) AddClusterScopedHandler(ctx context.Context, name, cluster string, handler NotificationTemplateHandlerFunc) {
	c.GenericController.AddHandler(ctx, name, func(key string, obj interface{}) (interface{}, error) {
		if obj == nil {
			return handler(key, nil)
		} else if v, ok := obj.(*NotificationTemplate); ok && controller.ObjectInCluster(cluster, obj) {
			return handler(key, v)
		} else {
			return nil, nil
		}
	})
}

func (c *notificationTemplateController) AddClusterScopedFeatureHandler(ctx context.Context, enabled func() bool, name, cluster string, handler NotificationTemplateHandlerFunc) {
	c.GenericController.AddHandler(ctx, name, func(key string, obj interface{}) (interface{}, error) {
		if !enabled() {
			return nil, nil
		} else if obj == nil {
			return handler(key, nil)
		} else if v, ok := obj.(*NotificationTemplate); ok && controller.ObjectInCluster(cluster, obj) {
			return handler(key, v)
		} else {
			return nil, nil
		}
	})
}

type notificationTemplateFactory struct {
}

func (c notificationTemplateFactory) Object() runtime.Object {
	return &NotificationTemplate{}
}

func (c notificationTemplateFactory) List() runtime.Object {
	return &NotificationTemplateList{}
}

func (s *notificationTemplateClient) Controller() NotificationTemplateController {
	s.client.Lock()
	defer s.client.Unlock()

	c, ok := s.client.notificationTemplateControllers[s.ns]
	if ok {
		return c
	}

	genericController := controller.NewGenericController(NotificationTemplateGroupVersionKind.Kind+"Controller",
		s.objectClient)

	c = &notificationTemplateController{
		GenericController: genericController,
	}

	s.client.notificationTemplateControllers[s.ns] = c
	s.client.starters = append(s.client.starters, c)

	return c
}

type notificationTemplateClient struct {
	client       *Client
	ns           string
	objectClient *objectclient.ObjectClient
	controller   NotificationTemplateController
}

func (s *notificationTemplateClient) ObjectClient() *objectclient.ObjectClient {
	return s.objectClient
}

func (s *notificationTemplateClient) Create(o *NotificationTemplate) (*NotificationTemplate, error) {
	obj, err := s.objectClient.Create(o)
	return obj.(*NotificationTemplate), err
}

func (s *notificationTemplateClient) Get(name string, opts metav1.GetOptions) (*NotificationTemplate, error) {
	obj, err := s.objectClient.Get(name, opts)
	return obj.(*NotificationTemplate), err
}

func (s *notificationTemplateClient) GetNamespaced(namespace, name string, opts metav1.GetOptions) (*NotificationTemplate, error) {
	obj, err := s.objectClient.GetNamespaced(namespace, name, opts)
	return obj.(*NotificationTemplate), err
}

func (s *notificationTemplateClient) Update(o *NotificationTemplate) (*NotificationTemplate, error) {
	obj, err := s.objectClient.Update(o.Name, o)
	return obj.(*NotificationTemplate), err
}

func (s *notificationTemplateClient) Delete(name string, options *metav1.DeleteOptions) error {
	return s.objectClient.Delete(name, options)
}

func (s *notificationTemplateClient) DeleteNamespaced(namespace, name string, options *metav1.DeleteOptions) error {
	return s.objectClient.DeleteNamespaced(namespace, name, options)
}

func (s *notificationTemplateClient) List(opts metav1.ListOptions) (*NotificationTemplateList, error) {
	obj, err := s.objectClient.List(opts)
	return obj.(*NotificationTemplateList), err
}

func (s *notificationTemplateClient) ListNamespaced(namespace string, opts metav1.ListOptions) (*NotificationTemplateList, error) {
	obj, err := s.objectClient.ListNamespaced(namespace, opts)
	return obj.(*NotificationTemplateList), err
}

func (s *notificationTemplateClient) Watch(opts metav1.ListOptions) (watch.Interface, error) {
	return s.objectClient.Watch(opts)
}

// Patch applies the patch and returns the patched deployment.
func (s *notificationTemplateClient) Patch(o *NotificationTemplate, patchType types.PatchType, data []byte, subresources ...string) (*NotificationTemplate, error) {
	obj, err := s.objectClient.Patch(o.Name, o, patchType, data, subresources...)
	return obj.(*NotificationTemplate), err
}

func (s *notificationTemplateClient) DeleteCollection(deleteOpts *metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	return s.objectClient.DeleteCollection(deleteOpts, listOpts)
}

func (s *notificationTemplateClient) AddHandler(ctx context.Context, name string, sync NotificationTemplateHandlerFunc) {
	s.Controller().AddHandler(ctx, name, sync)
}

func (s *notificationTemplateClient) AddFeatureHandler(ctx context.Context, enabled func() bool, name string, sync NotificationTemplateHandlerFunc) {
	s.Controller().AddFeatureHandler(ctx, enabled, name, sync)
}

func (s *notificationTemplateClient) AddLifecycle(ctx context.Context, name string, lifecycle NotificationTemplateLifecycle) {
	sync := NewNotificationTemplateLifecycleAdapter(name, false, s, lifecycle)
	s.Controller().AddHandler(ctx, name, sync)
}

func (s *notificationTemplateClient) AddFeatureLifecycle(ctx context.Context, enabled func() bool, name string, lifecycle NotificationTemplateLifecycle) {
	sync := NewNotificationTemplateLifecycleAdapter(name, false, s, lifecycle)
	s.Controller().AddFeatureHandler(ctx, enabled, name, sync)
}

func (s *notificationTemplateClient) AddClusterScopedHandler(ctx context.Context, name, clusterName string, sync NotificationTemplateHandlerFunc) {
	s.Controller().AddClusterScopedHandler(ctx, name, clusterName, sync)
}

func (s *notificationTemplateClient) AddClusterScopedFeatureHandler(ctx context.Context, enabled func() bool, name, clusterName string, sync NotificationTemplateHandlerFunc) {
	s.Controller().AddClusterScopedFeatureHandler(ctx, enabled, name, clusterName, sync)
}

func (s *notificationTemplateClient) AddClusterScopedLifecycle(ctx context.Context, name, clusterName string, lifecycle NotificationTemplateLifecycle) {
	sync := NewNotificationTemplateLifecycleAdapter(name+"_"+clusterName, true, s, lifecycle)
	s.Controller().AddClusterScopedHandler(ctx, name, clusterName, sync)
}

func (s *notificationTemplateClient) AddClusterScopedFeatureLifecycle(ctx context.Context, enabled func() bool, name, clusterName string, lifecycle NotificationTemplateLifecycle) {
	sync := NewNotificationTemplateLifecycleAdapter(name+"_"+clusterName, true, s, lifecycle)
	s.Controller().AddClusterScopedFeatureHandler(ctx, enabled, name, clusterName, sync)
}
