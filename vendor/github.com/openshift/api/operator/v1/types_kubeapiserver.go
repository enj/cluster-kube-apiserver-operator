package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openshift/api/config/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// KubeAPIServer provides information to configure an operator to manage kube-apiserver.
type KubeAPIServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	// +required
	Spec KubeAPIServerSpec `json:"spec"`
	// +optional
	Status KubeAPIServerStatus `json:"status"`
}

type KubeAPIServerSpec struct {
	StaticPodOperatorSpec `json:",inline"`
}

type KubeAPIServerStatus struct {
	StaticPodOperatorStatus `json:",inline"`

	EncryptionStatus EncryptionStatus `json:"encryptionStatus"`
}

type EncryptionStatus struct {
	Resources []EncryptionResource `json:"resources"`
}

type EncryptionResource struct {
	GroupResource metav1.GroupResource `json:"groupResource"`

	CurrentWriteKey configv1.SecretNameReference `json:"currentWriteKey"`

	NextWriteKey configv1.SecretNameReference `json:"nextWriteKey"`

	ReadKey configv1.SecretNameReference `json:"readKey"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// KubeAPIServerList is a collection of items
type KubeAPIServerList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ListMeta `json:"metadata"`
	// Items contains the items
	Items []KubeAPIServer `json:"items"`
}
