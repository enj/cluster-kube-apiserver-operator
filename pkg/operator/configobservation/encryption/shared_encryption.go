package encryption

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/config/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog"

	"github.com/openshift/library-go/pkg/operator/management"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

// labels used to find secrets that build up the final encryption config
// the names of the secrets are in format <shared prefix>-<unique monotonically increasing uint>
// they are listed in ascending order
// the latest secret is the current desired write key
const (
	encryptionSecretComponent = "encryption.operator.openshift.io/component"

	encryptionSecretGroup    = "encryption.operator.openshift.io/group"
	encryptionSecretResource = "encryption.operator.openshift.io/resource"
)

// annotations used to mark the current state of the secret
const (
	encryptionSecretMigrationTimestamp = "encryption.operator.openshift.io/migration-timestamp"
	// encryptionSecretMigrationJob       = "encryption.operator.openshift.io/migration-job"
)

// keys used to find specific values in the secret
const (
	encryptionSecretKeyData = "encryption.operator.openshift.io-key"
)

const revisionLabel = "revision"

var codec runtime.Serializer

func init() {
	scheme := runtime.NewScheme()
	codecs := serializer.NewCodecFactory(scheme)
	utilruntime.Must(apiserverconfigv1.AddToScheme(scheme))
	codec = codecs.LegacyCodec(apiserverconfigv1.SchemeGroupVersion)
}

type groupResourcesState map[schema.GroupResource]keys
type keys struct {
	desiredWriteKey       apiserverconfigv1.Key
	desiredWriteKeyID     uint64
	desiredWriteKeySecret *corev1.Secret

	readKeys []apiserverconfigv1.Key

	migratedSecrets   []*corev1.Secret
	unmigratedSecrets []*corev1.Secret
}

func getEncryptionState(encryptionSecrets []*corev1.Secret, validGRs map[schema.GroupResource]bool) groupResourcesState {
	// make sure we order to get the correct desired write key, see comment at top
	sort.Slice(encryptionSecrets, func(i, j int) bool {
		a, _ := secretToKeyID(encryptionSecrets[i])
		b, _ := secretToKeyID(encryptionSecrets[j])
		return a < b
	})

	encryptionState := groupResourcesState{}

	for _, encryptionSecret := range encryptionSecrets {
		gr, key, keyID, ok := secretToKey(encryptionSecret, validGRs)
		if !ok {
			klog.Infof("skipping encryption secret %s as it has invalid data", encryptionSecret.Name)
			continue
		}

		grState := encryptionState[gr]

		// always append to read keys since we do not know which key is the current write key until the end
		grState.readKeys = append(grState.readKeys, key)
		// keep overwriting the write key with the latest key that has been migrated to
		if len(encryptionSecret.Annotations[encryptionSecretMigrationTimestamp]) > 0 {
			grState.desiredWriteKey = key
			grState.desiredWriteKeyID = keyID
			grState.desiredWriteKeySecret = encryptionSecret
			grState.migratedSecrets = append(grState.migratedSecrets, encryptionSecret)
		} else {
			grState.unmigratedSecrets = append(grState.unmigratedSecrets, encryptionSecret)
		}

		encryptionState[gr] = grState
	}

	return encryptionState
}

func secretToKey(encryptionSecret *corev1.Secret, validGRs map[schema.GroupResource]bool) (schema.GroupResource, apiserverconfigv1.Key, uint64, bool) {
	group := encryptionSecret.Labels[encryptionSecretGroup]
	resource := encryptionSecret.Labels[encryptionSecretResource]
	keyData := encryptionSecret.Data[encryptionSecretKeyData]

	keyID, validKeyID := secretToKeyID(encryptionSecret)

	gr := schema.GroupResource{Group: group, Resource: resource}
	key := apiserverconfigv1.Key{
		// limit the length of the name as it is used as a prefix for every value in etcd
		// this means that each resource can have 1,000 active keys (0 - 999 so three ASCII letters max)
		// thus to avoid collisions something must prune the old ones (that is fine since we need pruning anyway)
		Name:   strconv.FormatUint(keyID%1000, 10),
		Secret: base64.StdEncoding.EncodeToString(keyData),
	}
	invalidKey := len(resource) == 0 || len(keyData) == 0 || !validKeyID || !validGRs[gr]

	return gr, key, keyID, !invalidKey
}

func secretToKeyID(encryptionSecret *corev1.Secret) (uint64, bool) {
	// see format and ordering comment at top
	lastIdx := strings.LastIndex(encryptionSecret.Name, "-")
	keyIDStr := encryptionSecret.Name[lastIdx+1:]
	keyID, keyIDErr := strconv.ParseUint(keyIDStr, 10, 0)
	invalidKeyID := lastIdx == -1 || keyIDErr != nil
	return keyID, !invalidKeyID
}

func getResourceConfigs(encryptionState groupResourcesState) []apiserverconfigv1.ResourceConfiguration {
	resourceConfigs := make([]apiserverconfigv1.ResourceConfiguration, 0, len(encryptionState))

	for gr, grKeys := range encryptionState {
		resourceConfigs = append(resourceConfigs, apiserverconfigv1.ResourceConfiguration{
			Resources: []string{gr.String()}, // we are forced to lose data here because this API is broken
			Providers: keysToProviders(grKeys),
		})
	}

	// make sure our output is stable
	sort.Slice(resourceConfigs, func(i, j int) bool {
		return resourceConfigs[i].Resources[0] < resourceConfigs[j].Resources[0] // each resource has its own keys
	})

	return resourceConfigs
}

func keysToProviders(grKeys keys) []apiserverconfigv1.ProviderConfiguration {
	hasWriteKey := len(grKeys.desiredWriteKey.Secret) != 0

	// read keys have a duplicate of the write key
	// or there is no write key
	allKeys := make([]apiserverconfigv1.Key, 0, len(grKeys.readKeys))

	// write key comes first
	if hasWriteKey {
		allKeys = append(allKeys, grKeys.desiredWriteKey)
	}

	// iterate in reverse to order the read keys in optimal order
	for i := len(grKeys.readKeys) - 1; i >= 0; i-- {
		readKey := grKeys.readKeys[i]
		if readKey.Name == grKeys.desiredWriteKey.Name {
			continue // if present, drop the duplicate write key from the list
		}
		allKeys = append(allKeys, readKey)
	}

	aescbc := apiserverconfigv1.ProviderConfiguration{
		AESCBC: &apiserverconfigv1.AESConfiguration{
			Keys: allKeys,
		},
	}
	identity := apiserverconfigv1.ProviderConfiguration{
		Identity: &apiserverconfigv1.IdentityConfiguration{},
	}

	// assume the common case of having a write key so identity comes last
	providers := []apiserverconfigv1.ProviderConfiguration{aescbc, identity}
	// if we have no write key, identity comes first
	if !hasWriteKey {
		providers = []apiserverconfigv1.ProviderConfiguration{identity, aescbc}
	}

	return providers
}

func shouldRunEncryptionController(operatorClient operatorv1helpers.StaticPodOperatorClient) (bool, error) {
	operatorSpec, _, _, err := operatorClient.GetStaticPodOperatorState()
	if err != nil {
		return false, err
	}

	return management.IsOperatorManaged(operatorSpec.ManagementState), nil
}

func labelSelectorOrDie(label string) labels.Selector {
	labelSelector, err := metav1.ParseToLabelSelector(label)
	if err != nil {
		panic(err) // coding error
	}
	componentSelector, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		panic(err) // coding error
	}
	return componentSelector
}

func getRevision(podLister corev1listers.PodNamespaceLister) (string, error) {
	apiServerPods, err := podLister.List(labelSelectorOrDie("apiserver=true"))
	if err != nil {
		return "", err
	}

	revisions := sets.NewString()
	for _, apiServerPod := range apiServerPods {
		switch apiServerPod.Status.Phase {
		case corev1.PodRunning, corev1.PodPending:
			for _, condition := range apiServerPod.Status.Conditions {
				if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
					revisions.Insert(apiServerPod.Labels[revisionLabel])
				}
			}
		}
	}

	if len(revisions) != 1 {
		return "", nil // api servers have not converged onto a single revision
	}
	revision, _ := revisions.PopAny()
	return revision, nil
}

func getEncryptionConfig(secrets corev1client.SecretInterface, revision string) (*apiserverconfigv1.EncryptionConfiguration, error) {
	encryptionConfigSecret, err := secrets.Get(encryptionConfSecret+"-"+revision, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	encryptionConfigObj, err := runtime.Decode(codec, encryptionConfigSecret.Data[encryptionConfSecret])
	if err != nil {
		return nil, err
	}

	encryptionConfig, ok := encryptionConfigObj.(*apiserverconfigv1.EncryptionConfiguration)
	if !ok {
		return nil, fmt.Errorf("encryption config has wrong type %T", encryptionConfigObj)
	}
	return encryptionConfig, nil
}

func getActualKeys(encryptionConfig *apiserverconfigv1.EncryptionConfiguration) map[schema.GroupResource][]apiserverconfigv1.Key {
	actualKeys := map[schema.GroupResource][]apiserverconfigv1.Key{}
	for _, resourceConfig := range encryptionConfig.Resources {
		if len(resourceConfig.Resources) == 0 || len(resourceConfig.Providers) == 0 {
			continue // should never happen
		}
		gr := schema.ParseGroupResource(resourceConfig.Resources[0])
		provider := resourceConfig.Providers[0]
		if provider.AESCBC != nil && len(provider.AESCBC.Keys) != 0 {
			actualKeys[gr] = provider.AESCBC.Keys
		}
	}
	return actualKeys
}
