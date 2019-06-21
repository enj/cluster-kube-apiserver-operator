package encryption

import (
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/config/v1"
	"k8s.io/client-go/kubernetes"
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
}

func NewEncryptionController(
	targetNamespace, sourceName string,
	operatorClient operatorv1helpers.StaticPodOperatorClient,
	kubeInformersForNamespaces operatorv1helpers.KubeInformersForNamespaces,
	operatorConfigClient operatorv1client.KubeAPIServersGetter,
	kubeClient kubernetes.Interface,
	eventRecorder events.Recorder,
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

	// do not mess with it when its doing stuff
	if !isStaticPodReady(c.operatorClient) {
		c.queue.AddAfter(workKey, 5*time.Second)
		return nil
	}

	var errs []error
	// TODO stuff here
	configError := operatorv1helpers.NewMultiLineAggregate(errs)

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
	_ = ec
	return nil, nil
}

func isStaticPodReady(operatorClient operatorv1helpers.StaticPodOperatorClient) bool {
	_, status, _, err := operatorClient.GetStaticPodOperatorStateWithQuorum()
	if err != nil {
		klog.Infof("failed to check operator state: %v", err)
		return false
	}

	// TODO fix
	if -1 != status.ObservedGeneration {
		return false
	}

	if operatorv1helpers.IsOperatorConditionPresentAndEqual(status.Conditions, operatorv1.OperatorStatusTypeProgressing, operatorv1.ConditionTrue) {
		return false
	}

	return operatorv1helpers.IsOperatorConditionPresentAndEqual(status.Conditions, operatorv1.OperatorStatusTypeAvailable, operatorv1.ConditionTrue)
}
