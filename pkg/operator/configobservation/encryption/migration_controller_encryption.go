package encryption

import (
	"fmt"
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/cluster-kube-apiserver-operator/pkg/operator/operatorclient"
	"github.com/openshift/library-go/pkg/operator/events"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

const migrationWorkKey = "key"

type EncryptionMigrationController struct {
	operatorClient operatorv1helpers.StaticPodOperatorClient

	queue         workqueue.RateLimitingInterface
	eventRecorder events.Recorder

	preRunCachesSynced []cache.InformerSynced

	validGRs map[schema.GroupResource]bool

	targetNamespace   string
	componentSelector labels.Selector

	// TODO fix and combine
	secretLister corev1listers.SecretLister
	secretClient corev1client.SecretsGetter

	podLister corev1listers.PodNamespaceLister

	dynamicClient dynamic.Interface
}

func NewEncryptionMigrationController(
	targetNamespace string,
	operatorClient operatorv1helpers.StaticPodOperatorClient,
	kubeInformersForNamespaces operatorv1helpers.KubeInformersForNamespaces,
	secretClient corev1client.SecretsGetter,
	eventRecorder events.Recorder,
	validGRs map[schema.GroupResource]bool,
	dynamicClient dynamic.Interface, // temporary hack
) *EncryptionMigrationController {
	c := &EncryptionMigrationController{
		operatorClient: operatorClient,
		eventRecorder:  eventRecorder.WithComponentSuffix("encryption-migration-controller"),

		queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "EncryptionMigrationController"),

		preRunCachesSynced: []cache.InformerSynced{
			operatorClient.Informer().HasSynced,
			kubeInformersForNamespaces.InformersFor(operatorclient.GlobalMachineSpecifiedConfigNamespace).Core().V1().Secrets().Informer().HasSynced,
			kubeInformersForNamespaces.InformersFor(targetNamespace).Core().V1().Secrets().Informer().HasSynced,
			kubeInformersForNamespaces.InformersFor(targetNamespace).Core().V1().Pods().Informer().HasSynced,
		},

		validGRs: validGRs,

		targetNamespace: targetNamespace,
	}

	c.componentSelector = labelSelectorOrDie(encryptionSecretComponent + "=" + targetNamespace)

	operatorClient.Informer().AddEventHandler(c.eventHandler())
	kubeInformersForNamespaces.InformersFor(operatorclient.GlobalMachineSpecifiedConfigNamespace).Core().V1().Secrets().Informer().AddEventHandler(c.eventHandler())
	kubeInformersForNamespaces.InformersFor(targetNamespace).Core().V1().Secrets().Informer().AddEventHandler(c.eventHandler())
	kubeInformersForNamespaces.InformersFor(targetNamespace).Core().V1().Pods().Informer().AddEventHandler(c.eventHandler())

	c.secretLister = kubeInformersForNamespaces.InformersFor("").Core().V1().Secrets().Lister()
	c.secretClient = secretClient
	c.podLister = kubeInformersForNamespaces.InformersFor(targetNamespace).Core().V1().Pods().Lister().Pods(targetNamespace)
	c.dynamicClient = dynamicClient

	return c
}

func (c *EncryptionMigrationController) sync() error {
	if ready, err := shouldRunEncryptionController(c.operatorClient); err != nil || !ready {
		return err // we will get re-kicked when the operator status updates
	}

	configError, isProgressing := c.handleEncryptionMigration()

	// update failing condition
	degraded := operatorv1.OperatorCondition{
		Type:   "EncryptionMigrationControllerDegraded",
		Status: operatorv1.ConditionFalse,
	}
	if configError != nil {
		degraded.Status = operatorv1.ConditionTrue
		degraded.Reason = "Error"
		degraded.Message = configError.Error()
	}

	// update progressing condition
	progressing := operatorv1.OperatorCondition{
		Type:   "EncryptionMigrationControllerProgressing",
		Status: operatorv1.ConditionFalse,
	}
	if configError == nil && isProgressing { // TODO need to think this logic through
		degraded.Status = operatorv1.ConditionTrue
		degraded.Reason = "StorageMigration"
		degraded.Message = "" // TODO maybe put job information
	}

	if _, _, updateError := operatorv1helpers.UpdateStatus(c.operatorClient,
		operatorv1helpers.UpdateConditionFn(degraded),
		operatorv1helpers.UpdateConditionFn(progressing),
	); updateError != nil {
		return updateError
	}

	return configError
}

func (c *EncryptionMigrationController) handleEncryptionMigration() (error, bool) {
	// no storage migration during revision changes
	revision, err := getRevision(c.podLister)
	if err != nil || len(revision) == 0 {
		return err, err == nil
	}

	encryptionConfig, err := getEncryptionConfig(c.secretClient.Secrets(c.targetNamespace), revision)
	if err != nil {
		return err, false
	}

	encryptionSecrets, err := c.secretLister.Secrets(operatorclient.GlobalMachineSpecifiedConfigNamespace).List(c.componentSelector)
	if err != nil {
		return err, false
	}

	encryptionState := getEncryptionState(encryptionSecrets, c.validGRs)

	// TODO we need this check?  Could it dead lock?
	// no storage migration until all masters catch up with revision
	if !reflect.DeepEqual(encryptionConfig.Resources, getResourceConfigs(encryptionState)) {
		return fmt.Errorf("resource config not in sync"), false // TODO maybe synthetic retry
	}

	// now we can attempt migration
	var errs []error
	for gr, grActualKeys := range getGRsActualKeys(encryptionConfig) {
		if !grActualKeys.hasWriteKey {
			continue // no write key to migrate to
		}

		writeSecret, ok := findSecretFromKey(grActualKeys.writeKey, encryptionState[gr].secretsMigratedNo, c.validGRs)
		if !ok {
			continue // no migration needed
		}

		migrationErr := c.runStorageMigration(gr)
		errs = append(errs, migrationErr)
		if migrationErr != nil {
			continue
		}

		errs = append(errs, setSecretAnnotation(c.secretClient, c.eventRecorder, writeSecret, encryptionSecretMigratedTimestamp))
	}
	return utilerrors.NewAggregate(errs), false
}

func (c *EncryptionMigrationController) runStorageMigration(gr schema.GroupResource) error {
	// TODO version hack
	d := c.dynamicClient.Resource(gr.WithVersion("v1"))
	unstructuredList, err := d.List(metav1.ListOptions{})
	if err != nil {
		return err
	}
	var errs []error
	for _, obj := range unstructuredList.Items {
		retryErr := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			_, updateErr := d.Update(&obj, metav1.UpdateOptions{})
			return updateErr
		})
		errs = append(errs, retryErr)
	}
	return utilerrors.FilterOut(utilerrors.NewAggregate(errs), errors.IsNotFound)
}

func (c *EncryptionMigrationController) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting EncryptionMigrationController")
	defer klog.Infof("Shutting down EncryptionMigrationController")
	if !cache.WaitForCacheSync(stopCh, c.preRunCachesSynced...) {
		utilruntime.HandleError(fmt.Errorf("caches did not sync"))
		return
	}

	// only start one worker
	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh
}

func (c *EncryptionMigrationController) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *EncryptionMigrationController) processNextWorkItem() bool {
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

func (c *EncryptionMigrationController) eventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.queue.Add(migrationWorkKey) },
		UpdateFunc: func(old, new interface{}) { c.queue.Add(migrationWorkKey) },
		DeleteFunc: func(obj interface{}) { c.queue.Add(migrationWorkKey) },
	}
}
