package encryption

import (
	"fmt"
	"time"

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
	operatorv1client "github.com/openshift/client-go/operator/clientset/versioned/typed/operator/v1"
	"github.com/openshift/cluster-kube-apiserver-operator/pkg/operator/operatorclient"
	"github.com/openshift/library-go/pkg/operator/events"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

const workKey = "key"

type EncryptionController struct {
	operatorClient operatorv1helpers.StaticPodOperatorClient

	queue         workqueue.RateLimitingInterface
	eventRecorder events.Recorder

	preRunCachesSynced []cache.InformerSynced

	sourceName string
	resources  []string

	secretLister corev1listers.SecretNamespaceLister
	secretClient corev1client.SecretInterface
}

func NewEncryptionController(
	targetNamespace, sourceName string,
	operatorClient operatorv1helpers.StaticPodOperatorClient,
	kubeInformersForNamespaces operatorv1helpers.KubeInformersForNamespaces,
	operatorConfigClient operatorv1client.KubeAPIServersGetter,
	kubeClient kubernetes.Interface,
	eventRecorder events.Recorder,
	resources ...schema.GroupResource,
) *EncryptionController {
	c := &EncryptionController{
		operatorClient: operatorClient,
		eventRecorder:  eventRecorder.WithComponentSuffix("encryption-controller"),

		queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "EncryptionController"),

		preRunCachesSynced: []cache.InformerSynced{
			operatorClient.Informer().HasSynced,
			kubeInformersForNamespaces.InformersFor(operatorclient.GlobalMachineSpecifiedConfigNamespace).Core().V1().Secrets().Informer().HasSynced,
			kubeInformersForNamespaces.InformersFor(targetNamespace).Core().V1().Secrets().Informer().HasSynced,
		},

		sourceName: sourceName,
	}

	operatorClient.Informer().AddEventHandler(c.eventHandler())
	kubeInformersForNamespaces.InformersFor(operatorclient.GlobalMachineSpecifiedConfigNamespace).Core().V1().Secrets().Informer().AddEventHandler(c.eventHandler())
	kubeInformersForNamespaces.InformersFor(targetNamespace).Core().V1().Secrets().Informer().AddEventHandler(c.eventHandler())

	c.secretLister = kubeInformersForNamespaces.InformersFor(operatorclient.GlobalMachineSpecifiedConfigNamespace).
		Core().V1().Secrets().Lister().Secrets(operatorclient.GlobalMachineSpecifiedConfigNamespace)
	c.secretClient = kubeClient.CoreV1().Secrets(operatorclient.GlobalMachineSpecifiedConfigNamespace)

	for _, resource := range resources {
		c.resources = append(c.resources, resource.String())
	}

	return c
}

func (c *EncryptionController) sync() error {
	originalSpec, _, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return err
	}

	switch originalSpec.ManagementState {
	case operatorv1.Managed:
	case operatorv1.Unmanaged:
		return nil
	case operatorv1.Removed:
		// TODO probably just fail
		return nil
	default:
		c.eventRecorder.Warningf("ManagementStateUnknown", "Unrecognized operator management state %q", originalSpec.ManagementState)
		return nil
	}

	configError := c.handleEncryptionConfig()

	// update failing condition
	cond := operatorv1.OperatorCondition{
		Type:   "EncryptionControllerDegraded",
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

func (c *EncryptionController) handleEncryptionConfig() error {
	return nil // TODO
}

func (c *EncryptionController) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting EncryptionController")
	defer klog.Infof("Shutting down EncryptionController")
	if !cache.WaitForCacheSync(stopCh, c.preRunCachesSynced...) {
		utilruntime.HandleError(fmt.Errorf("caches did not sync"))
		return
	}

	// only start one worker
	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh
}

func (c *EncryptionController) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *EncryptionController) processNextWorkItem() bool {
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

func (c *EncryptionController) eventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { c.queue.Add(workKey) },
		UpdateFunc: func(old, new interface{}) { c.queue.Add(workKey) },
		DeleteFunc: func(obj interface{}) { c.queue.Add(workKey) },
	}
}
