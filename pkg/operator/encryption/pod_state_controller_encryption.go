package encryption

import (
	"fmt"
	"time"

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

const podStateKey = "key"

type encryptionPodStateController struct {
	operatorClient operatorv1helpers.StaticPodOperatorClient

	queue         workqueue.RateLimitingInterface
	eventRecorder events.Recorder

	preRunCachesSynced []cache.InformerSynced

	encryptedGRs map[schema.GroupResource]bool

	targetNamespace          string
	encryptionSecretSelector metav1.ListOptions

	secretClient corev1client.SecretsGetter

	podClient corev1client.PodInterface
}

func newEncryptionPodStateController(
	targetNamespace string,
	operatorClient operatorv1helpers.StaticPodOperatorClient,
	kubeInformersForNamespaces operatorv1helpers.KubeInformersForNamespaces,
	secretClient corev1client.SecretsGetter,
	encryptionSecretSelector metav1.ListOptions,
	eventRecorder events.Recorder,
	encryptedGRs map[schema.GroupResource]bool,
	podClient corev1client.PodInterface,
) *encryptionPodStateController {
	c := &encryptionPodStateController{
		operatorClient: operatorClient,

		queue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "EncryptionPodStateController"),
		eventRecorder: eventRecorder.WithComponentSuffix("encryption-pod-state-controller"),

		encryptedGRs:    encryptedGRs,
		targetNamespace: targetNamespace,

		encryptionSecretSelector: encryptionSecretSelector,
		secretClient:             secretClient,
		podClient:                podClient,
	}

	c.preRunCachesSynced = setUpAllEncryptionInformers(operatorClient, targetNamespace, kubeInformersForNamespaces, c.eventHandler())

	return c
}

func (c *encryptionPodStateController) sync() error {
	if ready, err := shouldRunEncryptionController(c.operatorClient); err != nil || !ready {
		return err // we will get re-kicked when the operator status updates
	}

	configError, isProgressing := c.handleEncryptionPodState()

	// update failing condition
	degraded := operatorv1.OperatorCondition{
		Type:   "EncryptionPodStateControllerDegraded",
		Status: operatorv1.ConditionFalse,
	}
	if configError != nil {
		degraded.Status = operatorv1.ConditionTrue
		degraded.Reason = "Error"
		degraded.Message = configError.Error()
	}

	// update progressing condition
	progressing := operatorv1.OperatorCondition{
		Type:   "EncryptionPodStateControllerProgressing",
		Status: operatorv1.ConditionFalse,
	}
	if configError == nil && isProgressing { // TODO need to think this logic through
		degraded.Status = operatorv1.ConditionTrue
		degraded.Reason = "PodStateNotConverged"
		degraded.Message = "" // TODO
	}

	if _, _, updateError := operatorv1helpers.UpdateStatus(c.operatorClient,
		operatorv1helpers.UpdateConditionFn(degraded),
		operatorv1helpers.UpdateConditionFn(progressing),
	); updateError != nil {
		return updateError
	}

	return configError
}

func (c *encryptionPodStateController) handleEncryptionPodState() (error, bool) {
	// we need a stable view of the world
	revision, err := getAPIServerRevision(c.podClient)
	if err != nil || len(revision) == 0 {
		return err, err == nil
	}

	encryptionConfig, err := getEncryptionConfig(c.secretClient.Secrets(c.targetNamespace), revision)
	if err != nil {
		return err, false
	}

	encryptionState, err := getEncryptionState(c.secretClient.Secrets(operatorclient.GlobalMachineSpecifiedConfigNamespace), c.encryptionSecretSelector, c.encryptedGRs)
	if err != nil {
		return err, false
	}

	// now we can attempt to annotate based on current pod state
	var errs []error
	for gr, grActualKeys := range getGRsActualKeys(encryptionConfig) {
		keyToSecret := encryptionState[gr].keyToSecret

		for _, readKey := range grActualKeys.readKeys {
			readSecret, ok := keyToSecret[readKey]
			if !ok {
				// TODO may do not error and just set progressing ?
				errs = append(errs, fmt.Errorf("failed to find read secret for key %s in %s", readKey.Name, gr))
				continue
			}
			errs = append(errs, setSecretAnnotation(c.secretClient, c.eventRecorder, readSecret, encryptionSecretReadTimestamp))
		}

		if !grActualKeys.hasWriteKey {
			continue
		}

		writeSecret, ok := keyToSecret[grActualKeys.writeKey]
		if !ok {
			// TODO may do not error and just set progressing ?
			errs = append(errs, fmt.Errorf("failed to find write secret for key %s in %s", grActualKeys.writeKey.Name, gr))
			continue
		}
		errs = append(errs, setSecretAnnotation(c.secretClient, c.eventRecorder, writeSecret, encryptionSecretWriteTimestamp))
	}
	return utilerrors.NewAggregate(errs), false
}

func (c *encryptionPodStateController) run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting EncryptionPodStateController")
	defer klog.Infof("Shutting down EncryptionPodStateController")
	if !cache.WaitForCacheSync(stopCh, c.preRunCachesSynced...) {
		utilruntime.HandleError(fmt.Errorf("caches did not sync"))
		return
	}

	// only start one worker
	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh
}

func (c *encryptionPodStateController) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *encryptionPodStateController) processNextWorkItem() bool {
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

func (c *encryptionPodStateController) eventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.queue.Add(podStateKey) },
		UpdateFunc: func(old, new interface{}) { c.queue.Add(podStateKey) },
		DeleteFunc: func(obj interface{}) { c.queue.Add(podStateKey) },
	}
}
