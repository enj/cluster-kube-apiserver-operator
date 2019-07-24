package encryption

import (
	"github.com/openshift/cluster-kube-apiserver-operator/pkg/operator/operatorclient"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
)

func syncEncryptionConfig(syncer resourcesynccontroller.ResourceSyncer, targetNamespace, sourceName string) {
	if err := syncer.SyncSecret(
		resourcesynccontroller.ResourceLocation{Namespace: targetNamespace, Name: encryptionConfSecret},
		resourcesynccontroller.ResourceLocation{Namespace: operatorclient.GlobalMachineSpecifiedConfigNamespace, Name: sourceName},
	); err != nil {
		panic(err) // coding error
	}
}
