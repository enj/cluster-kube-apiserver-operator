package encryption

import (
	"encoding/base64"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/config/v1"
	"k8s.io/klog"
)

// labels used to find secrets that build up the final encryption config
// the names of the secrets are lexicographically ordered with the latest secret being the current write key
const (
	encryptionSecretComponent = "encryption.operator.openshift.io/component"

	encryptionSecretGroup    = "encryption.operator.openshift.io/group"
	encryptionSecretResource = "encryption.operator.openshift.io/resource"
)

// annotations used to mark the current state of the secret
const (
	encryptionSecretMigrationTimestamp = "encryption.operator.openshift.io/migration-timestamp"
	encryptionSecretMigrationJob       = "encryption.operator.openshift.io/migration-job"
)

// keys used to find specific values in the secret
const (
	encryptionSecretKeyData = "encryption.operator.openshift.io-key"
)

var encoder runtime.Encoder

func init() {
	scheme := runtime.NewScheme()
	codecs := serializer.NewCodecFactory(scheme)
	utilruntime.Must(apiserverconfigv1.AddToScheme(scheme))
	encoder = codecs.LegacyCodec(apiserverconfigv1.SchemeGroupVersion)
}

type groupResourcesState map[schema.GroupResource]keys
type keys struct {
	writeKey          apiserverconfigv1.Key
	readKeys          []apiserverconfigv1.Key
	migratedSecrets   []string
	unmigratedSecrets []*corev1.Secret
}

func getEncryptionState(encryptionSecrets []*corev1.Secret) groupResourcesState {
	// make sure we order lexicographically to get the correct write key
	sort.Slice(encryptionSecrets, func(i, j int) bool {
		return encryptionSecrets[i].Name < encryptionSecrets[j].Name
	})

	encryptionState := groupResourcesState{}

	for _, encryptionSecret := range encryptionSecrets {
		gr, key, ok := secretToKey(encryptionSecret)
		if !ok {
			klog.Infof("skipping encryption secret %s as it has invalid data", encryptionSecret.Name)
			continue
		}

		grState := encryptionState[gr]

		// always append to read keys since we do not know which key is the current write key until the end
		grState.readKeys = append(grState.readKeys, key)
		// keep overwriting the write key with the latest key that has been migrated to
		if len(encryptionSecret.Annotations[encryptionSecretMigrationTimestamp]) > 0 {
			grState.writeKey = key
			grState.migratedSecrets = append(grState.migratedSecrets, encryptionSecret.Name)
		} else {
			grState.unmigratedSecrets = append(grState.unmigratedSecrets, encryptionSecret)
		}

		encryptionState[gr] = grState
	}

	return encryptionState
}

func secretToKey(encryptionSecret *corev1.Secret) (schema.GroupResource, apiserverconfigv1.Key, bool) {
	group := encryptionSecret.Labels[encryptionSecretGroup]
	resource := encryptionSecret.Labels[encryptionSecretResource]
	keyData := encryptionSecret.Data[encryptionSecretKeyData]

	// name of secret is expected to have format <shared prefix>-<unique monotonically increasing uint>
	// see lexicographical ordering above in getEncryptionState func
	lastIdx := strings.LastIndex(encryptionSecret.Name, "-")
	keyIDStr := encryptionSecret.Name[lastIdx+1:]
	keyID, keyIDErr := strconv.ParseUint(keyIDStr, 10, 0)

	gr := schema.GroupResource{Group: group, Resource: resource}
	key := apiserverconfigv1.Key{
		// limit the length of the name as it is used as a prefix for every value in etcd
		// this means that each resource can have 1,000 active keys (0 - 999 so three ASCII letters max)
		// thus to avoid collisions something must prune the old ones (that is fine since we need pruning anyway)
		Name:   strconv.FormatUint(keyID%1000, 10),
		Secret: base64.StdEncoding.EncodeToString(keyData),
	}
	invalidKey := len(resource) == 0 || len(keyData) == 0 || lastIdx == -1 || keyIDErr != nil

	return gr, key, !invalidKey
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
	hasWriteKey := len(grKeys.writeKey.Secret) != 0

	// read keys have a duplicate of the write key
	// or there is no write key
	allKeys := make([]apiserverconfigv1.Key, 0, len(grKeys.readKeys))

	// write key comes first
	if hasWriteKey {
		allKeys = append(allKeys, grKeys.writeKey)
	}

	// iterate in reverse to order the read keys in optimal order
	for i := len(grKeys.readKeys) - 1; i >= 0; i-- {
		readKey := grKeys.readKeys[i]
		if readKey.Name == grKeys.writeKey.Name {
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
