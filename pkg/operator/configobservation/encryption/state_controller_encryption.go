package encryption

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/config/v1"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/cluster-kube-apiserver-operator/pkg/operator/operatorclient"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/management"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

const stateWorkKey = "key"

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

type EncryptionStateController struct {
	operatorClient operatorv1helpers.StaticPodOperatorClient

	queue         workqueue.RateLimitingInterface
	eventRecorder events.Recorder

	preRunCachesSynced []cache.InformerSynced

	destName          string
	componentSelector labels.Selector

	secretLister corev1listers.SecretNamespaceLister
	secretClient corev1client.SecretsGetter
}

func NewEncryptionStateController(
	targetNamespace, destName string,
	operatorClient operatorv1helpers.StaticPodOperatorClient,
	kubeInformersForNamespaces operatorv1helpers.KubeInformersForNamespaces,
	kubeClient kubernetes.Interface,
	eventRecorder events.Recorder,
) *EncryptionStateController {
	c := &EncryptionStateController{
		operatorClient: operatorClient,
		eventRecorder:  eventRecorder.WithComponentSuffix("encryption-state-controller"),

		queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "EncryptionStateController"),

		preRunCachesSynced: []cache.InformerSynced{
			operatorClient.Informer().HasSynced,
			kubeInformersForNamespaces.InformersFor(operatorclient.GlobalMachineSpecifiedConfigNamespace).Core().V1().Secrets().Informer().HasSynced,
		},

		destName: destName,
	}

	labelSelector, err := metav1.ParseToLabelSelector(encryptionSecretComponent + "=" + targetNamespace)
	if err != nil {
		panic(err) // coding error
	}
	componentSelector, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		panic(err) // coding error
	}
	c.componentSelector = componentSelector

	operatorClient.Informer().AddEventHandler(c.eventHandler())
	kubeInformersForNamespaces.InformersFor(operatorclient.GlobalMachineSpecifiedConfigNamespace).Core().V1().Secrets().Informer().AddEventHandler(c.eventHandler())

	c.secretLister = kubeInformersForNamespaces.InformersFor(operatorclient.GlobalMachineSpecifiedConfigNamespace).
		Core().V1().Secrets().Lister().Secrets(operatorclient.GlobalMachineSpecifiedConfigNamespace)
	c.secretClient = kubeClient.CoreV1()

	return c
}

func (c *EncryptionStateController) sync() error {
	operatorSpec, _, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return err
	}

	if !management.IsOperatorManaged(operatorSpec.ManagementState) {
		return nil
	}

	if ready, err := isStaticPodAtLatestRevision(c.operatorClient); err != nil || !ready {
		return err // we will get re-kicked when the operator status updates
	}

	configError := c.handleEncryptionStateConfig()

	// update failing condition
	cond := operatorv1.OperatorCondition{
		Type:   "EncryptionStateControllerDegraded",
		Status: operatorv1.ConditionFalse,
	}
	if configError != nil {
		cond.Status = operatorv1.ConditionTrue
		cond.Reason = "Error"
		cond.Message = configError.Error()
	}
	if _, _, updateError := operatorv1helpers.UpdateStatus(c.operatorClient, operatorv1helpers.UpdateConditionFn(cond)); updateError != nil {
		return updateError
	}

	return configError
}

func (c *EncryptionStateController) handleEncryptionStateConfig() error {
	encryptionSecrets, err := c.secretLister.List(c.componentSelector)
	if err != nil {
		return err
	}

	encryptionState := getEncryptionState(encryptionSecrets)

	resourceConfigs := getResourceConfigs(encryptionState)

	// if we have no config, do not create the secret
	if len(resourceConfigs) == 0 {
		return nil
	}

	return c.applyEncryptionConfigSecret(resourceConfigs)
}

type groupResourcesState map[schema.GroupResource]keys
type keys struct {
	writeKey apiserverconfigv1.Key
	readKeys []apiserverconfigv1.Key
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

func (c *EncryptionStateController) applyEncryptionConfigSecret(resourceConfigs []apiserverconfigv1.ResourceConfiguration) error {
	encryptionConfig := &apiserverconfigv1.EncryptionConfiguration{Resources: resourceConfigs}
	encryptionConfigBytes, err := runtime.Encode(encoder, encryptionConfig)
	if err != nil {
		return err // indicates static generated code is broken, unrecoverable
	}

	_, _, applyErr := resourceapply.ApplySecret(c.secretClient, c.eventRecorder, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.destName,
			Namespace: operatorclient.GlobalMachineSpecifiedConfigNamespace,
		},
		Data: map[string][]byte{encryptionConfSecret: encryptionConfigBytes},
	})
	return applyErr
}

func (c *EncryptionStateController) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting EncryptionStateController")
	defer klog.Infof("Shutting down EncryptionStateController")
	if !cache.WaitForCacheSync(stopCh, c.preRunCachesSynced...) {
		utilruntime.HandleError(fmt.Errorf("caches did not sync"))
		return
	}

	// only start one worker
	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh
}

func (c *EncryptionStateController) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *EncryptionStateController) processNextWorkItem() bool {
	dsKey, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(dsKey)

	err := c.sync()
	if err == nil {
		c.queue.Forget(dsKey)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with: %v", dsKey, err))
	c.queue.AddRateLimited(dsKey)

	return true
}

func (c *EncryptionStateController) eventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.queue.Add(stateWorkKey) },
		UpdateFunc: func(old, new interface{}) { c.queue.Add(stateWorkKey) },
		DeleteFunc: func(obj interface{}) { c.queue.Add(stateWorkKey) },
	}
}

func isStaticPodAtLatestRevision(operatorClient operatorv1helpers.StaticPodOperatorClient) (bool, error) {
	_, status, _, err := operatorClient.GetStaticPodOperatorStateWithQuorum() // force live read
	if err != nil {
		return false, err
	}

	if len(status.NodeStatuses) == 0 {
		return false, nil
	}

	for _, nodeStatus := range status.NodeStatuses {
		if nodeStatus.CurrentRevision != status.LatestAvailableRevision {
			return false, nil
		}
	}

	return true, nil
}
