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
	CloneAppGroupVersionKind = schema.GroupVersionKind{
		Version: Version,
		Group:   GroupName,
		Kind:    "CloneApp",
	}
	CloneAppResource = metav1.APIResource{
		Name:         "cloneapps",
		SingularName: "cloneapp",
		Namespaced:   true,

		Kind: CloneAppGroupVersionKind.Kind,
	}

	CloneAppGroupVersionResource = schema.GroupVersionResource{
		Group:    GroupName,
		Version:  Version,
		Resource: "cloneapps",
	}
)

func init() {
	resource.Put(CloneAppGroupVersionResource)
}

func NewCloneApp(namespace, name string, obj CloneApp) *CloneApp {
	obj.APIVersion, obj.Kind = CloneAppGroupVersionKind.ToAPIVersionAndKind()
	obj.Name = name
	obj.Namespace = namespace
	return &obj
}

type CloneAppList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CloneApp `json:"items"`
}

type CloneAppHandlerFunc func(key string, obj *CloneApp) (runtime.Object, error)

type CloneAppChangeHandlerFunc func(obj *CloneApp) (runtime.Object, error)

type CloneAppLister interface {
	List(namespace string, selector labels.Selector) (ret []*CloneApp, err error)
	Get(namespace, name string) (*CloneApp, error)
}

type CloneAppController interface {
	Generic() controller.GenericController
	Informer() cache.SharedIndexInformer
	Lister() CloneAppLister
	AddHandler(ctx context.Context, name string, handler CloneAppHandlerFunc)
	AddFeatureHandler(ctx context.Context, enabled func() bool, name string, sync CloneAppHandlerFunc)
	AddClusterScopedHandler(ctx context.Context, name, clusterName string, handler CloneAppHandlerFunc)
	AddClusterScopedFeatureHandler(ctx context.Context, enabled func() bool, name, clusterName string, handler CloneAppHandlerFunc)
	Enqueue(namespace, name string)
	EnqueueAfter(namespace, name string, after time.Duration)
	Sync(ctx context.Context) error
	Start(ctx context.Context, threadiness int) error
}

type CloneAppInterface interface {
	ObjectClient() *objectclient.ObjectClient
	Create(*CloneApp) (*CloneApp, error)
	GetNamespaced(namespace, name string, opts metav1.GetOptions) (*CloneApp, error)
	Get(name string, opts metav1.GetOptions) (*CloneApp, error)
	Update(*CloneApp) (*CloneApp, error)
	Delete(name string, options *metav1.DeleteOptions) error
	DeleteNamespaced(namespace, name string, options *metav1.DeleteOptions) error
	List(opts metav1.ListOptions) (*CloneAppList, error)
	ListNamespaced(namespace string, opts metav1.ListOptions) (*CloneAppList, error)
	Watch(opts metav1.ListOptions) (watch.Interface, error)
	DeleteCollection(deleteOpts *metav1.DeleteOptions, listOpts metav1.ListOptions) error
	Controller() CloneAppController
	AddHandler(ctx context.Context, name string, sync CloneAppHandlerFunc)
	AddFeatureHandler(ctx context.Context, enabled func() bool, name string, sync CloneAppHandlerFunc)
	AddLifecycle(ctx context.Context, name string, lifecycle CloneAppLifecycle)
	AddFeatureLifecycle(ctx context.Context, enabled func() bool, name string, lifecycle CloneAppLifecycle)
	AddClusterScopedHandler(ctx context.Context, name, clusterName string, sync CloneAppHandlerFunc)
	AddClusterScopedFeatureHandler(ctx context.Context, enabled func() bool, name, clusterName string, sync CloneAppHandlerFunc)
	AddClusterScopedLifecycle(ctx context.Context, name, clusterName string, lifecycle CloneAppLifecycle)
	AddClusterScopedFeatureLifecycle(ctx context.Context, enabled func() bool, name, clusterName string, lifecycle CloneAppLifecycle)
}

type cloneAppLister struct {
	controller *cloneAppController
}

func (l *cloneAppLister) List(namespace string, selector labels.Selector) (ret []*CloneApp, err error) {
	err = cache.ListAllByNamespace(l.controller.Informer().GetIndexer(), namespace, selector, func(obj interface{}) {
		ret = append(ret, obj.(*CloneApp))
	})
	return
}

func (l *cloneAppLister) Get(namespace, name string) (*CloneApp, error) {
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
			Group:    CloneAppGroupVersionKind.Group,
			Resource: "cloneApp",
		}, key)
	}
	return obj.(*CloneApp), nil
}

type cloneAppController struct {
	controller.GenericController
}

func (c *cloneAppController) Generic() controller.GenericController {
	return c.GenericController
}

func (c *cloneAppController) Lister() CloneAppLister {
	return &cloneAppLister{
		controller: c,
	}
}

func (c *cloneAppController) AddHandler(ctx context.Context, name string, handler CloneAppHandlerFunc) {
	c.GenericController.AddHandler(ctx, name, func(key string, obj interface{}) (interface{}, error) {
		if obj == nil {
			return handler(key, nil)
		} else if v, ok := obj.(*CloneApp); ok {
			return handler(key, v)
		} else {
			return nil, nil
		}
	})
}

func (c *cloneAppController) AddFeatureHandler(ctx context.Context, enabled func() bool, name string, handler CloneAppHandlerFunc) {
	c.GenericController.AddHandler(ctx, name, func(key string, obj interface{}) (interface{}, error) {
		if !enabled() {
			return nil, nil
		} else if obj == nil {
			return handler(key, nil)
		} else if v, ok := obj.(*CloneApp); ok {
			return handler(key, v)
		} else {
			return nil, nil
		}
	})
}

func (c *cloneAppController) AddClusterScopedHandler(ctx context.Context, name, cluster string, handler CloneAppHandlerFunc) {
	c.GenericController.AddHandler(ctx, name, func(key string, obj interface{}) (interface{}, error) {
		if obj == nil {
			return handler(key, nil)
		} else if v, ok := obj.(*CloneApp); ok && controller.ObjectInCluster(cluster, obj) {
			return handler(key, v)
		} else {
			return nil, nil
		}
	})
}

func (c *cloneAppController) AddClusterScopedFeatureHandler(ctx context.Context, enabled func() bool, name, cluster string, handler CloneAppHandlerFunc) {
	c.GenericController.AddHandler(ctx, name, func(key string, obj interface{}) (interface{}, error) {
		if !enabled() {
			return nil, nil
		} else if obj == nil {
			return handler(key, nil)
		} else if v, ok := obj.(*CloneApp); ok && controller.ObjectInCluster(cluster, obj) {
			return handler(key, v)
		} else {
			return nil, nil
		}
	})
}

type cloneAppFactory struct {
}

func (c cloneAppFactory) Object() runtime.Object {
	return &CloneApp{}
}

func (c cloneAppFactory) List() runtime.Object {
	return &CloneAppList{}
}

func (s *cloneAppClient) Controller() CloneAppController {
	s.client.Lock()
	defer s.client.Unlock()

	c, ok := s.client.cloneAppControllers[s.ns]
	if ok {
		return c
	}

	genericController := controller.NewGenericController(CloneAppGroupVersionKind.Kind+"Controller",
		s.objectClient)

	c = &cloneAppController{
		GenericController: genericController,
	}

	s.client.cloneAppControllers[s.ns] = c
	s.client.starters = append(s.client.starters, c)

	return c
}

type cloneAppClient struct {
	client       *Client
	ns           string
	objectClient *objectclient.ObjectClient
	controller   CloneAppController
}

func (s *cloneAppClient) ObjectClient() *objectclient.ObjectClient {
	return s.objectClient
}

func (s *cloneAppClient) Create(o *CloneApp) (*CloneApp, error) {
	obj, err := s.objectClient.Create(o)
	return obj.(*CloneApp), err
}

func (s *cloneAppClient) Get(name string, opts metav1.GetOptions) (*CloneApp, error) {
	obj, err := s.objectClient.Get(name, opts)
	return obj.(*CloneApp), err
}

func (s *cloneAppClient) GetNamespaced(namespace, name string, opts metav1.GetOptions) (*CloneApp, error) {
	obj, err := s.objectClient.GetNamespaced(namespace, name, opts)
	return obj.(*CloneApp), err
}

func (s *cloneAppClient) Update(o *CloneApp) (*CloneApp, error) {
	obj, err := s.objectClient.Update(o.Name, o)
	return obj.(*CloneApp), err
}

func (s *cloneAppClient) Delete(name string, options *metav1.DeleteOptions) error {
	return s.objectClient.Delete(name, options)
}

func (s *cloneAppClient) DeleteNamespaced(namespace, name string, options *metav1.DeleteOptions) error {
	return s.objectClient.DeleteNamespaced(namespace, name, options)
}

func (s *cloneAppClient) List(opts metav1.ListOptions) (*CloneAppList, error) {
	obj, err := s.objectClient.List(opts)
	return obj.(*CloneAppList), err
}

func (s *cloneAppClient) ListNamespaced(namespace string, opts metav1.ListOptions) (*CloneAppList, error) {
	obj, err := s.objectClient.ListNamespaced(namespace, opts)
	return obj.(*CloneAppList), err
}

func (s *cloneAppClient) Watch(opts metav1.ListOptions) (watch.Interface, error) {
	return s.objectClient.Watch(opts)
}

// Patch applies the patch and returns the patched deployment.
func (s *cloneAppClient) Patch(o *CloneApp, patchType types.PatchType, data []byte, subresources ...string) (*CloneApp, error) {
	obj, err := s.objectClient.Patch(o.Name, o, patchType, data, subresources...)
	return obj.(*CloneApp), err
}

func (s *cloneAppClient) DeleteCollection(deleteOpts *metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	return s.objectClient.DeleteCollection(deleteOpts, listOpts)
}

func (s *cloneAppClient) AddHandler(ctx context.Context, name string, sync CloneAppHandlerFunc) {
	s.Controller().AddHandler(ctx, name, sync)
}

func (s *cloneAppClient) AddFeatureHandler(ctx context.Context, enabled func() bool, name string, sync CloneAppHandlerFunc) {
	s.Controller().AddFeatureHandler(ctx, enabled, name, sync)
}

func (s *cloneAppClient) AddLifecycle(ctx context.Context, name string, lifecycle CloneAppLifecycle) {
	sync := NewCloneAppLifecycleAdapter(name, false, s, lifecycle)
	s.Controller().AddHandler(ctx, name, sync)
}

func (s *cloneAppClient) AddFeatureLifecycle(ctx context.Context, enabled func() bool, name string, lifecycle CloneAppLifecycle) {
	sync := NewCloneAppLifecycleAdapter(name, false, s, lifecycle)
	s.Controller().AddFeatureHandler(ctx, enabled, name, sync)
}

func (s *cloneAppClient) AddClusterScopedHandler(ctx context.Context, name, clusterName string, sync CloneAppHandlerFunc) {
	s.Controller().AddClusterScopedHandler(ctx, name, clusterName, sync)
}

func (s *cloneAppClient) AddClusterScopedFeatureHandler(ctx context.Context, enabled func() bool, name, clusterName string, sync CloneAppHandlerFunc) {
	s.Controller().AddClusterScopedFeatureHandler(ctx, enabled, name, clusterName, sync)
}

func (s *cloneAppClient) AddClusterScopedLifecycle(ctx context.Context, name, clusterName string, lifecycle CloneAppLifecycle) {
	sync := NewCloneAppLifecycleAdapter(name+"_"+clusterName, true, s, lifecycle)
	s.Controller().AddClusterScopedHandler(ctx, name, clusterName, sync)
}

func (s *cloneAppClient) AddClusterScopedFeatureLifecycle(ctx context.Context, enabled func() bool, name, clusterName string, lifecycle CloneAppLifecycle) {
	sync := NewCloneAppLifecycleAdapter(name+"_"+clusterName, true, s, lifecycle)
	s.Controller().AddClusterScopedFeatureHandler(ctx, enabled, name, clusterName, sync)
}
