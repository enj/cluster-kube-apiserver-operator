package encryption

import (
	"fmt"

	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/config/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"

	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
)

const (
	encryptionConfFilePath = "/etc/kubernetes/static-pod-resources/secrets/encryption-config/encryption-config"
	encryptionKeysSecret   = "encryption-keys"
	encryptionConfSecret   = "encryption-config"
)

type SecretLister interface {
	SecretLister() corev1listers.SecretLister
	ResourceSyncer() resourcesynccontroller.ResourceSyncer
}

func NewEncryptionObserver(operatorNamespace, targetNamespace string, encryptionConfigPath []string, resources ...schema.GroupResource) configobserver.ObserveConfigFunc {
	return func(genericListers configobserver.Listers, recorder events.Recorder, existingConfig map[string]interface{}) (map[string]interface{}, []error) {
		listers := genericListers.(SecretLister)
		var errs []error
		previouslyObservedConfig := map[string]interface{}{}

		existingEncryptionConfig, _, err := unstructured.NestedStringSlice(existingConfig, encryptionConfigPath...)
		if err != nil {
			return previouslyObservedConfig, append(errs, err)
		}

		if len(existingEncryptionConfig) > 0 {
			if err := unstructured.SetNestedStringSlice(previouslyObservedConfig, existingEncryptionConfig, encryptionConfigPath...); err != nil {
				errs = append(errs, err)
			}
		}

		observedConfig := map[string]interface{}{}

		encryptionKeys, err := listers.SecretLister().Secrets(operatorNamespace).Get(encryptionKeysSecret)
		if errors.IsNotFound(err) {
			recorder.Warningf("ObserveEncryptionConfig", "Required key secret %s/%s not found", operatorNamespace, encryptionKeysSecret)
			return observedConfig, errs
		}
		if err != nil {
			return previouslyObservedConfig, errs
		}

		encryptionConfigSecret, err := getEncryptionConfiguration()
		if err != nil {
			return previouslyObservedConfig, errs
		}
		encryptionConfigSecret, changed, err := resourceapply.ApplySecret(nil, recorder, encryptionConfigSecret)

		cloudProvider := getPlatformName(encryptionKeys.Status.Platform, recorder)
		if len(cloudProvider) > 0 {
			if err := unstructured.SetNestedStringSlice(observedConfig, []string{cloudProvider}, cloudProvidersPath...); err != nil {
				errs = append(errs, err)
			}
		}

		sourceCloudConfigMap := encryptionKeys.Spec.CloudConfig.Name
		sourceCloudConfigNamespace := configNamespace
		sourceLocation := resourcesynccontroller.ResourceLocation{
			Namespace: sourceCloudConfigNamespace,
			Name:      sourceCloudConfigMap,
		}

		// we set cloudprovider configmap values only for some cloud providers.
		validCloudProviders := sets.NewString("azure", "vsphere")
		if !validCloudProviders.Has(cloudProvider) {
			sourceCloudConfigMap = ""
		}

		if len(sourceCloudConfigMap) == 0 {
			sourceLocation = resourcesynccontroller.ResourceLocation{}
		}

		err = listers.ResourceSyncer().SyncSecret(
			resourcesynccontroller.ResourceLocation{
				Namespace: targetNamespace,
				Name:      "cloud-config",
			},
			sourceLocation,
		)

		if err != nil {
			errs = append(errs, err)
			return observedConfig, errs
		}

		if len(sourceCloudConfigMap) == 0 {
			return observedConfig, errs
		}

		// usually key will be simply config but we should refer it just in case
		staticCloudConfFile := fmt.Sprintf(encryptionConfFilePath, encryptionKeys.Spec.CloudConfig.Key)

		if err := unstructured.SetNestedStringSlice(observedConfig, []string{staticCloudConfFile}, encryptionConfigPath...); err != nil {
			recorder.Warningf("ObserveCloudProviderNames", "Failed setting cloud-config : %v", err)
			errs = append(errs, err)
		}

		if !equality.Semantic.DeepEqual(existingEncryptionConfig, []string{staticCloudConfFile}) {
			recorder.Eventf("ObserveCloudProviderNamesChanges", "CloudProvider config file changed to %s", staticCloudConfFile)
		}

		return observedConfig, errs
	}
}

func getEncryptionConfiguration() (*corev1.Secret, error) {
	ec := apiserverconfigv1.EncryptionConfiguration{
		Resources: []apiserverconfigv1.ResourceConfiguration{
			{
				Resources: []string{},
				Providers: []apiserverconfigv1.ProviderConfiguration{
					{
						AESCBC: &apiserverconfigv1.AESConfiguration{
							Keys: nil,
						},
						Identity: &apiserverconfigv1.IdentityConfiguration{},
					},
				},
			},
		},
	}
}
