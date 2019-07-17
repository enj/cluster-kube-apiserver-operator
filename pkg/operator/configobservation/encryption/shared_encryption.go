package encryption

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	apiserverconfig "k8s.io/apiserver/pkg/apis/config"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/config/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
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
	encryptionSecretMigratedTimestamp = "encryption.operator.openshift.io/migrated-timestamp"
	// encryptionSecretMigrationJob       = "encryption.operator.openshift.io/migration-job"

	encryptionSecretReadTimestamp  = "encryption.operator.openshift.io/read-timestamp"
	encryptionSecretWriteTimestamp = "encryption.operator.openshift.io/write-timestamp"
)

// keys used to find specific values in the secret
const (
	encryptionSecretKeyData = "encryption.operator.openshift.io-key"
)

const revisionLabel = "revision"

var (
	encoder runtime.Encoder
	decoder runtime.Decoder
)

func init() {
	scheme := runtime.NewScheme()
	codecs := serializer.NewCodecFactory(scheme)
	utilruntime.Must(apiserverconfigv1.AddToScheme(scheme))
	utilruntime.Must(apiserverconfig.AddToScheme(scheme))
	encoder = codecs.LegacyCodec(apiserverconfigv1.SchemeGroupVersion)
	decoder = codecs.UniversalDecoder(apiserverconfigv1.SchemeGroupVersion)
}

type groupResourcesState map[schema.GroupResource]keysState
type keysState struct {
	keys        []apiserverconfigv1.Key
	secrets     []*corev1.Secret
	keyToSecret map[apiserverconfigv1.Key]*corev1.Secret
	secretToKey map[string]apiserverconfigv1.Key

	secretsReadYes []*corev1.Secret
	secretsReadNo  []*corev1.Secret

	secretsWriteYes []*corev1.Secret
	secretsWriteNo  []*corev1.Secret

	secretsMigratedYes []*corev1.Secret
	secretsMigratedNo  []*corev1.Secret
}

type desiredKeys struct {
	hasWriteKey bool
	writeKey    apiserverconfigv1.Key
	readKeys    []apiserverconfigv1.Key
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
		gr, key, _, ok := secretToKey(encryptionSecret, validGRs)
		if !ok {
			klog.Infof("skipping encryption secret %s as it has invalid data", encryptionSecret.Name)
			continue
		}

		grState := encryptionState[gr]

		// TODO figure out which lists can be dropped, maps may be better in some places

		grState.keys = append(grState.keys, key)
		grState.secrets = append(grState.secrets, encryptionSecret)

		if grState.keyToSecret == nil {
			grState.keyToSecret = map[apiserverconfigv1.Key]*corev1.Secret{}
		}
		grState.keyToSecret[key] = encryptionSecret

		if grState.secretToKey == nil {
			grState.secretToKey = map[string]apiserverconfigv1.Key{}
		}
		grState.secretToKey[encryptionSecret.Name] = key

		appendSecretPerAnnotationState(&grState.secretsReadYes, &grState.secretsReadNo, encryptionSecret, encryptionSecretReadTimestamp)
		appendSecretPerAnnotationState(&grState.secretsWriteYes, &grState.secretsWriteNo, encryptionSecret, encryptionSecretWriteTimestamp)
		appendSecretPerAnnotationState(&grState.secretsMigratedYes, &grState.secretsMigratedNo, encryptionSecret, encryptionSecretMigratedTimestamp)

		encryptionState[gr] = grState
	}

	return encryptionState
}

func appendSecretPerAnnotationState(in, out *[]*corev1.Secret, secret *corev1.Secret, annotation string) {
	if len(secret.Annotations[annotation]) != 0 {
		*in = append(*in, secret)
	} else {
		*out = append(*out, secret)
	}
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

func grKeysToDesiredKeys(grKeys keysState) desiredKeys {
	desired := desiredKeys{}

	desired.writeKey, desired.hasWriteKey = determineWriteKey(grKeys)

	// keys have a duplicate of the write key
	// or there is no write key

	// iterate in reverse to order the read keys in optimal order
	for i := len(grKeys.keys) - 1; i >= 0; i-- {
		readKey := grKeys.keys[i]
		if desired.hasWriteKey && readKey == desired.writeKey {
			continue // if present, drop the duplicate write key from the list
		}
		desired.readKeys = append(desired.readKeys, readKey)
	}

	return desired
}

func determineWriteKey(grKeys keysState) (apiserverconfigv1.Key, bool) {
	// first write that is not migrated
	for _, writeYes := range grKeys.secretsWriteYes {
		if len(writeYes.Annotations[encryptionSecretMigratedTimestamp]) == 0 {
			return grKeys.secretToKey[writeYes.Name], true
		}
	}

	// first read that is not write
	for _, readYes := range grKeys.secretsReadYes {
		if len(readYes.Annotations[encryptionSecretWriteTimestamp]) == 0 {
			return grKeys.secretToKey[readYes.Name], true
		}
	}

	// no key is transitioning so just use last migrated
	if len(grKeys.secretsMigratedYes) > 0 {
		lastMigrated := grKeys.secretsMigratedYes[len(grKeys.secretsMigratedYes)-1]
		return grKeys.secretToKey[lastMigrated.Name], true
	}

	// no write key
	return apiserverconfigv1.Key{}, false
}

func keysToProviders(grKeys keysState) []apiserverconfigv1.ProviderConfiguration {
	desired := grKeysToDesiredKeys(grKeys)

	allKeys := desired.readKeys

	// write key comes first
	if desired.hasWriteKey {
		allKeys = append([]apiserverconfigv1.Key{desired.writeKey}, allKeys...)
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
	if !desired.hasWriteKey {
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

func getRevision(podClient corev1client.PodInterface) (string, error) {
	// do a live list so we never get confused about what revision we are on
	apiServerPods, err := podClient.List(metav1.ListOptions{LabelSelector: "apiserver=true"})
	if err != nil {
		return "", err
	}

	revisions := sets.NewString()
	for _, apiServerPod := range apiServerPods.Items {
		switch apiServerPod.Status.Phase {
		case corev1.PodRunning:
			if !isPodReady(apiServerPod) {
				return "", nil // pods are not fully ready
			}
			revisions.Insert(apiServerPod.Labels[revisionLabel])
		case corev1.PodPending, corev1.PodUnknown:
			return "", nil // pods are not fully ready
		}
	}

	if len(revisions) != 1 {
		return "", nil // api servers have not converged onto a single revision
	}
	revision, _ := revisions.PopAny()
	return revision, nil
}

func isPodReady(pod corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func getEncryptionConfig(secrets corev1client.SecretInterface, revision string) (*apiserverconfigv1.EncryptionConfiguration, error) {
	encryptionConfigSecret, err := secrets.Get(encryptionConfSecret+"-"+revision, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	encryptionConfigObj, err := runtime.Decode(decoder, encryptionConfigSecret.Data[encryptionConfSecret])
	if err != nil {
		return nil, err
	}

	encryptionConfig, ok := encryptionConfigObj.(*apiserverconfigv1.EncryptionConfiguration)
	if !ok {
		return nil, fmt.Errorf("encryption config has wrong type %T", encryptionConfigObj)
	}
	return encryptionConfig, nil
}

type actualKeys struct {
	hasWriteKey bool
	writeKey    apiserverconfigv1.Key
	readKeys    []apiserverconfigv1.Key
}

func getGRsActualKeys(encryptionConfig *apiserverconfigv1.EncryptionConfiguration) map[schema.GroupResource]actualKeys {
	out := map[schema.GroupResource]actualKeys{}
	for _, resourceConfig := range encryptionConfig.Resources {
		if len(resourceConfig.Resources) == 0 || len(resourceConfig.Providers) < 2 {
			continue // should never happen
		}

		gr := schema.ParseGroupResource(resourceConfig.Resources[0])
		provider1 := resourceConfig.Providers[0]
		provider2 := resourceConfig.Providers[1]

		switch {
		case provider1.AESCBC != nil && len(provider1.AESCBC.Keys) != 0:
			out[gr] = actualKeys{
				hasWriteKey: true,
				writeKey:    provider1.AESCBC.Keys[0],
				readKeys:    provider1.AESCBC.Keys[1:],
			}
		case provider1.Identity != nil && provider2.AESCBC != nil && len(provider2.AESCBC.Keys) != 0:
			out[gr] = actualKeys{
				readKeys: provider2.AESCBC.Keys,
			}
		}
	}
	return out
}

func setSecretAnnotation(secretClient corev1client.SecretsGetter, recorder events.Recorder, secret *corev1.Secret, annotation string) error {
	if len(secret.Annotations[annotation]) != 0 {
		return nil
	}
	secret = secret.DeepCopy()

	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
	}
	secret.Annotations[annotation] = time.Now().Format(time.RFC3339)

	_, _, updateErr := resourceapply.ApplySecret(secretClient, recorder, secret)
	return updateErr // let conflict errors cause a retry
}
