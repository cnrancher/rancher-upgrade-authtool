package v3

import (
	"github.com/rancher/norman/lifecycle"
	"github.com/rancher/norman/resource"
	"k8s.io/apimachinery/pkg/runtime"
)

type CloneAppLifecycle interface {
	Create(obj *CloneApp) (runtime.Object, error)
	Remove(obj *CloneApp) (runtime.Object, error)
	Updated(obj *CloneApp) (runtime.Object, error)
}

type cloneAppLifecycleAdapter struct {
	lifecycle CloneAppLifecycle
}

func (w *cloneAppLifecycleAdapter) HasCreate() bool {
	o, ok := w.lifecycle.(lifecycle.ObjectLifecycleCondition)
	return !ok || o.HasCreate()
}

func (w *cloneAppLifecycleAdapter) HasFinalize() bool {
	o, ok := w.lifecycle.(lifecycle.ObjectLifecycleCondition)
	return !ok || o.HasFinalize()
}

func (w *cloneAppLifecycleAdapter) Create(obj runtime.Object) (runtime.Object, error) {
	o, err := w.lifecycle.Create(obj.(*CloneApp))
	if o == nil {
		return nil, err
	}
	return o, err
}

func (w *cloneAppLifecycleAdapter) Finalize(obj runtime.Object) (runtime.Object, error) {
	o, err := w.lifecycle.Remove(obj.(*CloneApp))
	if o == nil {
		return nil, err
	}
	return o, err
}

func (w *cloneAppLifecycleAdapter) Updated(obj runtime.Object) (runtime.Object, error) {
	o, err := w.lifecycle.Updated(obj.(*CloneApp))
	if o == nil {
		return nil, err
	}
	return o, err
}

func NewCloneAppLifecycleAdapter(name string, clusterScoped bool, client CloneAppInterface, l CloneAppLifecycle) CloneAppHandlerFunc {
	if clusterScoped {
		resource.PutClusterScoped(CloneAppGroupVersionResource)
	}
	adapter := &cloneAppLifecycleAdapter{lifecycle: l}
	syncFn := lifecycle.NewObjectLifecycleAdapter(name, clusterScoped, adapter, client.ObjectClient())
	return func(key string, obj *CloneApp) (runtime.Object, error) {
		newObj, err := syncFn(key, obj)
		if o, ok := newObj.(runtime.Object); ok {
			return o, err
		}
		return nil, err
	}
}
