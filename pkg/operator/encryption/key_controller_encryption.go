package encryption

import (
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/cluster-kube-apiserver-operator/pkg/operator/operatorclient"
	"github.com/openshift/library-go/pkg/operator/events"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

const encWorkKey = "key"

// encryptionKeyController watches secrets in openshift-config-managed
// to determine if a new AES-256 bit encryption key should be created.
// It finds the secrets that contain the keys using the encryptionSecretSelector.
// There are distinct keys for each resource that is encrypted per encryptedGRs.
// Thus the key rotation of all encrypted resources is independent of other resources.
// The criteria for a making a new key is as follows:
//   1. There are no unmigrated keys (see encryptionMigrationController).
//   2. If all existing keys are migrated, determine when the last migration completed.
//   3. If the current time is after last migration + encryptionSecretMigrationInterval,
//      create a new key.  Thus the speed of migration serves as back pressure.
// A key is always created when no other keys exist.
// Each key contains the following data:
//   1. A key ID.  This is a monotonically increasing integer that is used to order keys.
//   2. The component which will consume the key (generally the namespace of said component).
//   3. The group and resource that the key will be used to encrypt.
//   4. The AES-256 bit encryption key itself.
// Note that keys live in openshift-config-managed because deleting them is
// catastrophic to the cluster - this namespace is immortal and cannot be deleted.
type encryptionKeyController struct {
	operatorClient operatorv1helpers.StaticPodOperatorClient

	queue         workqueue.RateLimitingInterface
	eventRecorder events.Recorder

	preRunCachesSynced []cache.InformerSynced

	encryptedGRs map[schema.GroupResource]bool

	targetNamespace          string
	encryptionSecretSelector metav1.ListOptions

	secretClient corev1client.SecretInterface
}

func newEncryptionKeyController(
	targetNamespace string,
	operatorClient operatorv1helpers.StaticPodOperatorClient,
	kubeInformersForNamespaces operatorv1helpers.KubeInformersForNamespaces,
	secretClient corev1client.SecretsGetter,
	encryptionSecretSelector metav1.ListOptions,
	eventRecorder events.Recorder,
	encryptedGRs map[schema.GroupResource]bool,
) *encryptionKeyController {
	c := &encryptionKeyController{
		operatorClient: operatorClient,

		queue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "EncryptionKeyController"),
		eventRecorder: eventRecorder.WithComponentSuffix("encryption-key-controller"), // TODO unused

		encryptedGRs:    encryptedGRs,
		targetNamespace: targetNamespace,

		encryptionSecretSelector: encryptionSecretSelector,
		secretClient:             secretClient.Secrets(operatorclient.GlobalMachineSpecifiedConfigNamespace),
	}

	c.preRunCachesSynced = setUpGlobalMachineConfigEncryptionInformers(operatorClient, kubeInformersForNamespaces, c.eventHandler())

	return c
}

func (c *encryptionKeyController) sync() error {
	if ready, err := shouldRunEncryptionController(c.operatorClient); err != nil || !ready {
		return err // we will get re-kicked when the operator status updates
	}

	configError := c.checkAndCreateKeys()

	// update failing condition
	cond := operatorv1.OperatorCondition{
		Type:   "EncryptionKeyControllerDegraded",
		Status: operatorv1.ConditionFalse,
	}
	if configError != nil {
		cond.Status = operatorv1.ConditionTrue
		cond.Reason = "Error"
		cond.Message = configError.Error()
	}
	if _, _, updateError := operatorv1helpers.UpdateStaticPodStatus(c.operatorClient, operatorv1helpers.UpdateStaticPodConditionFn(cond)); updateError != nil {
		return updateError
	}

	return configError
}

func (c *encryptionKeyController) checkAndCreateKeys() error {
	currentMode, externalReason, err := getCurrentModeAndExternalReason()
	if err != nil {
		return err
	}

	encryptionState, err := getEncryptionState(c.secretClient, c.targetNamespace, c.encryptionSecretSelector, c.encryptedGRs)
	if err != nil {
		return err
	}

	// make sure we look for all resources that we are managing
	// this assumes that our API server operand controls these group resources
	// TODO maybe use the api service resource to filter down a complete list
	// TODO this would allow an end user to configure extra resources to encrypt
	// TODO alternatively we could just encrypt all resources per operand ...
	for gr := range c.encryptedGRs {
		if _, ok := encryptionState[gr]; !ok {
			encryptionState[gr] = keysState{}
		}
	}

	var errs []error
	for gr, grKeys := range encryptionState {
		keyID, internalReason, ok := needsNewKey(grKeys, currentMode, externalReason)
		if !ok {
			continue
		}

		nextKeyID := keyID + 1
		keySecret := c.generateKeySecret(gr, nextKeyID, currentMode, internalReason, externalReason)
		_, createErr := c.secretClient.Create(keySecret)
		if errors.IsAlreadyExists(createErr) {
			errs = append(errs, c.validateExistingKey(keySecret, gr, nextKeyID))
			continue
		}
		errs = append(errs, createErr)
	}
	return utilerrors.NewAggregate(errs)
}

func (c *encryptionKeyController) validateExistingKey(keySecret *corev1.Secret, gr schema.GroupResource, keyID uint64) error {
	actualKeySecret, err := c.secretClient.Get(keySecret.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	keyGR, _, actualKeyID, validKey := secretToKey(actualKeySecret, c.targetNamespace, c.encryptedGRs)
	if valid := keyGR == gr && actualKeyID == keyID && validKey; !valid {
		// TODO we can just get stuck in degraded here ...
		return fmt.Errorf("secret %s is in invalid state, new keys cannot be created for encryption target group=%s resource=%s", keySecret.Name, groupToHumanReadable(gr), gr.Resource)
	}

	return nil // we made this key earlier
}

func (c *encryptionKeyController) generateKeySecret(gr schema.GroupResource, keyID uint64, currentMode mode, internalReason, externalReason string) *corev1.Secret {
	group := groupToHumanReadable(gr)
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			// this ends up looking like openshift-kube-apiserver-core-secrets-encryption-3
			Name:      fmt.Sprintf("%s-%s-%s-encryption-%d", c.targetNamespace, group, gr.Resource, keyID),
			Namespace: operatorclient.GlobalMachineSpecifiedConfigNamespace,
			Labels: map[string]string{
				encryptionSecretComponent: c.targetNamespace,

				encryptionSecretGroup:    gr.Group,
				encryptionSecretResource: gr.Resource,
			},
			Annotations: map[string]string{
				kubernetesDescriptionKey: kubernetesDescriptionScaryValue,

				encryptionSecretMode:           string(currentMode),
				encryptionSecretInternalReason: internalReason,
				encryptionSecretExternalReason: externalReason,
			},
			Finalizers: []string{encryptionSecretFinalizer},
		},
		Data: map[string][]byte{
			encryptionSecretKeyData: modeToNewKeyFunc[currentMode](),
		},
	}
}

// TODO unit tests
func needsNewKey(grKeys keysState, currentMode mode, externalReason string) (uint64, string, bool) {
	// unmigrated secrets create back pressure against new key generation
	if len(grKeys.secretsMigratedNo) > 0 {
		return 0, "", false
	}

	// we always need to have some encryption keys unless we are turned off
	if len(grKeys.secrets) == 0 {
		return 0, "no-secrets", currentMode != identity
	}

	// if there are no unmigrated secrets but there are some secrets, then we must have migrated secrets
	// thus the lastMigrated field will always be set (and the secret will always have the annotations set)

	// if the last migrated secret was encrypted in a mode different than the current mode, we need to generate a new key
	if grKeys.lastMigrated.Annotations[encryptionSecretMode] != string(currentMode) {
		return grKeys.lastMigratedKeyID, "new-mode", true
	}

	// if the last migrated secret turned off encryption and we want to keep it that way, do nothing
	if grKeys.lastMigrated.Annotations[encryptionSecretMode] == string(identity) && currentMode == identity {
		return 0, "", false
	}

	// if the last migrated secret has a different external reason than the current reason, we need to generate a new key
	if grKeys.lastMigrated.Annotations[encryptionSecretExternalReason] != externalReason && len(externalReason) != 0 {
		return grKeys.lastMigratedKeyID, "new-external-reason", true
	}

	// we check for encryptionSecretMigratedTimestamp set by migration controller to determine when migration completed
	// this also generates back pressure for key rotation when migration takes a long time or was recently completed
	migrationTimestamp, err := time.Parse(time.RFC3339, grKeys.lastMigrated.Annotations[encryptionSecretMigratedTimestamp])
	if err != nil {
		klog.Infof("failed to parse migration timestamp for %s, forcing new key: %v", grKeys.lastMigrated.Name, err)
		return grKeys.lastMigratedKeyID, "timestamp-error", true
	}

	return grKeys.lastMigratedKeyID, "timestamp-too-old", time.Since(migrationTimestamp) > encryptionSecretMigrationInterval
}

func (c *encryptionKeyController) run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting EncryptionKeyController")
	defer klog.Infof("Shutting down EncryptionKeyController")
	if !cache.WaitForCacheSync(stopCh, c.preRunCachesSynced...) {
		utilruntime.HandleError(fmt.Errorf("caches did not sync"))
		return
	}

	// only start one worker
	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh
}

func (c *encryptionKeyController) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *encryptionKeyController) processNextWorkItem() bool {
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

func (c *encryptionKeyController) eventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.queue.Add(encWorkKey) },
		UpdateFunc: func(old, new interface{}) { c.queue.Add(encWorkKey) },
		DeleteFunc: func(obj interface{}) { c.queue.Add(encWorkKey) },
	}
}
