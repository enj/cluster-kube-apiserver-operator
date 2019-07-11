package encryption

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
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

	componentSelector labels.Selector

	secretLister corev1listers.SecretNamespaceLister
	secretClient corev1client.SecretsGetter
}

func NewEncryptionMigrationController(
	targetNamespace string,
	operatorClient operatorv1helpers.StaticPodOperatorClient,
	kubeInformersForNamespaces operatorv1helpers.KubeInformersForNamespaces,
	kubeClient kubernetes.Interface,
	eventRecorder events.Recorder,
	validGRs map[schema.GroupResource]bool,
) *EncryptionMigrationController {
	c := &EncryptionMigrationController{
		operatorClient: operatorClient,
		eventRecorder:  eventRecorder.WithComponentSuffix("encryption-migration-controller"),

		queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "EncryptionMigrationController"),

		preRunCachesSynced: []cache.InformerSynced{
			operatorClient.Informer().HasSynced,
			kubeInformersForNamespaces.InformersFor(operatorclient.GlobalMachineSpecifiedConfigNamespace).Core().V1().Secrets().Informer().HasSynced,
		},

		validGRs: validGRs,
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
	encryptionSecrets, err := c.secretLister.List(c.componentSelector)
	if err != nil {
		return err, false
	}

	encryptionState := getEncryptionState(encryptionSecrets, c.validGRs)

	for gr, grKeys := range encryptionState {
		if len(grKeys.unmigratedSecrets) == 0 {
			continue
		}
		for _, unmigratedSecret := range grKeys.unmigratedSecrets {
			if len(unmigratedSecret.Annotations[encryptionSecretMigrationJob]) > 0 {
				// TODO
			}
		}
		_ = c.startMigration(gr) // TODO
	}

	return nil, false // TODO
}

func (c *EncryptionMigrationController) startMigration(gr schema.GroupResource) error {
	return nil
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
