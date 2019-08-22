package encryption

import (
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/config/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	encryptionSecretKeyDataForTest = "encryption.operator.openshift.io-key"
)

type secretBuilder struct {
	secret *corev1.Secret
}

func (sb *secretBuilder) ToCoreV1Secret() *corev1.Secret {
	return sb.secret
}

func (sb *secretBuilder) WithEncryptionKey(key []byte) *secretBuilder {
	sb.secret.Data[encryptionSecretKeyDataForTest] = key
	return sb
}

func (sb *secretBuilder) WithEncryptionKeyFrom(secret *corev1.Secret) *secretBuilder {
	if rawKey, exist := secret.Data[encryptionSecretKeyDataForTest]; exist {
		sb.secret.Data[encryptionSecretKeyDataForTest] = rawKey
	}
	return sb
}

func createSecretBuilder(targetNS string, gr schema.GroupResource, keyID uint64) *secretBuilder {
	group := gr.Group
	if len(group) == 0 {
		group = "core"
	}

	return &secretBuilder{
		secret: &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-%s-%s-encryption-%d", targetNS, group, gr.Resource, keyID),
				Namespace: "openshift-config-managed",
				Labels: map[string]string{
					"encryption.operator.openshift.io/component": targetNS,
					"encryption.operator.openshift.io/group":     gr.Group,
					"encryption.operator.openshift.io/resource":  gr.Resource,
				},
			},
			Data: map[string][]byte{},
		},
	}
}

func createDummyKubeAPIPod(name, namespace string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"apiserver": "true",
				"revision":  "1",
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{
				corev1.PodCondition{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}
}

func secretDataToEncryptionConfig(secret *corev1.Secret) (*apiserverconfigv1.EncryptionConfiguration, error) {
	rawEncryptionConfig, exist := secret.Data["encryption-config"]
	if !exist {
		return nil, errors.New("the secret doesn't contain an encryption configuration")
	}

	decodedEncryptionConfig, err := runtime.Decode(decoder, rawEncryptionConfig)
	if err != nil {
		return nil, err
	}

	encryptionConfig, ok := decodedEncryptionConfig.(*apiserverconfigv1.EncryptionConfiguration)
	if !ok {
		return nil, fmt.Errorf("encryption config has wrong type %T", decodedEncryptionConfig)
	}
	return encryptionConfig, nil
}
