// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1alpha1 "github.com/openshift/cluster-kube-apiserver-operator/pkg/generated/clientset/versioned/typed/kubeapiserver/v1alpha1"
	rest "k8s.io/client-go/rest"
	testing "k8s.io/client-go/testing"
)

type FakeKubeapiserverV1alpha1 struct {
	*testing.Fake
}

func (c *FakeKubeapiserverV1alpha1) KubeApiserverOperatorConfigs() v1alpha1.KubeApiserverOperatorConfigInterface {
	return &FakeKubeApiserverOperatorConfigs{c}
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *FakeKubeapiserverV1alpha1) RESTClient() rest.Interface {
	var ret *rest.RESTClient
	return ret
}
