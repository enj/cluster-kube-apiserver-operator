package encryption

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

type runner interface {
	run(stopCh <-chan struct{})
}

func NewEncryptionControllers(
	targetNamespace, destName string,
	operatorClient operatorv1helpers.StaticPodOperatorClient,
	kubeInformersForNamespaces operatorv1helpers.KubeInformersForNamespaces,
	kubeClient kubernetes.Interface,
	secretClient corev1client.SecretsGetter,
	podClient corev1client.PodsGetter,
	eventRecorder events.Recorder,
	resourceSyncer resourcesynccontroller.ResourceSyncer,
	dynamicClient dynamic.Interface, // temporary hack for in-process storage migration
	groupResources ...schema.GroupResource,
) *EncryptionControllers {
	syncEncryptionConfig(resourceSyncer, targetNamespace, destName)

	validGRs := map[schema.GroupResource]bool{}
	for _, gr := range groupResources {
		validGRs[gr] = true
	}

	return &EncryptionControllers{
		controllers: []runner{
			newEncryptionKeyController(
				targetNamespace,
				operatorClient,
				kubeInformersForNamespaces,
				kubeClient,
				eventRecorder,
				validGRs,
			),
			newEncryptionStateController(
				targetNamespace,
				destName,
				operatorClient,
				kubeInformersForNamespaces,
				secretClient,
				podClient,
				eventRecorder,
				validGRs,
			),
			newEncryptionPruneController(
				targetNamespace,
				operatorClient,
				kubeInformersForNamespaces,
				kubeClient,
				eventRecorder,
				validGRs,
			),
			newEncryptionMigrationController(
				targetNamespace,
				operatorClient,
				kubeInformersForNamespaces,
				secretClient,
				podClient,
				eventRecorder,
				validGRs,
				dynamicClient,
			),
			newEncryptionPodStateController(
				targetNamespace,
				operatorClient,
				kubeInformersForNamespaces,
				secretClient,
				podClient,
				eventRecorder,
				validGRs,
			),
		},
	}
}

type EncryptionControllers struct {
	controllers []runner
}

func (c *EncryptionControllers) Run(stopCh <-chan struct{}) {
	for _, controller := range c.controllers {
		con := controller // capture range variable
		go con.run(stopCh)
	}
	<-stopCh
}
