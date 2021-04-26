package v3

import (
	"github.com/rancher/norman/lifecycle"
	"github.com/rancher/norman/resource"
	"k8s.io/apimachinery/pkg/runtime"
)

type NotificationTemplateLifecycle interface {
	Create(obj *NotificationTemplate) (runtime.Object, error)
	Remove(obj *NotificationTemplate) (runtime.Object, error)
	Updated(obj *NotificationTemplate) (runtime.Object, error)
}

type notificationTemplateLifecycleAdapter struct {
	lifecycle NotificationTemplateLifecycle
}

func (w *notificationTemplateLifecycleAdapter) HasCreate() bool {
	o, ok := w.lifecycle.(lifecycle.ObjectLifecycleCondition)
	return !ok || o.HasCreate()
}

func (w *notificationTemplateLifecycleAdapter) HasFinalize() bool {
	o, ok := w.lifecycle.(lifecycle.ObjectLifecycleCondition)
	return !ok || o.HasFinalize()
}

func (w *notificationTemplateLifecycleAdapter) Create(obj runtime.Object) (runtime.Object, error) {
	o, err := w.lifecycle.Create(obj.(*NotificationTemplate))
	if o == nil {
		return nil, err
	}
	return o, err
}

func (w *notificationTemplateLifecycleAdapter) Finalize(obj runtime.Object) (runtime.Object, error) {
	o, err := w.lifecycle.Remove(obj.(*NotificationTemplate))
	if o == nil {
		return nil, err
	}
	return o, err
}

func (w *notificationTemplateLifecycleAdapter) Updated(obj runtime.Object) (runtime.Object, error) {
	o, err := w.lifecycle.Updated(obj.(*NotificationTemplate))
	if o == nil {
		return nil, err
	}
	return o, err
}

func NewNotificationTemplateLifecycleAdapter(name string, clusterScoped bool, client NotificationTemplateInterface, l NotificationTemplateLifecycle) NotificationTemplateHandlerFunc {
	if clusterScoped {
		resource.PutClusterScoped(NotificationTemplateGroupVersionResource)
	}
	adapter := &notificationTemplateLifecycleAdapter{lifecycle: l}
	syncFn := lifecycle.NewObjectLifecycleAdapter(name, clusterScoped, adapter, client.ObjectClient())
	return func(key string, obj *NotificationTemplate) (runtime.Object, error) {
		newObj, err := syncFn(key, obj)
		if o, ok := newObj.(runtime.Object); ok {
			return o, err
		}
		return nil, err
	}
}
