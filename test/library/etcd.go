package library

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"

	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

var protoEncodingPrefix = []byte{0x6b, 0x38, 0x73, 0x00}

const (
	jsonEncodingPrefix           = "{"
	protoEncryptedDataPrefix     = "k8s:enc:"
	aesCBCTransformerPrefixV1    = "k8s:enc:aescbc:v1:"
	secretboxTransformerPrefixV1 = "k8s:enc:secretbox:v1:"
)

func NewEtcdKVMust(t *testing.T, kubeClient kubernetes.Interface) (clientv3.KV, func()) {
	t.Helper()
	kv, done, err := NewEtcdKV(kubeClient)
	require.NoError(t, err)
	return kv, done
}

func NewEtcdKV(kubeClient kubernetes.Interface) (clientv3.KV, func(), error) {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "oc", "port-forward", "service/etcd", ":2379", "-n", "openshift-etcd")

	done := func() {
		cancel()
		_ = cmd.Wait() // wait to clean up resources but ignore returned error since cancel kills the process
	}

	var err error // so we can clean up on error
	defer func() {
		if err != nil {
			done()
		}
	}()

	stdOut, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}

	if err = cmd.Start(); err != nil {
		return nil, nil, err
	}

	scanner := bufio.NewScanner(stdOut)
	if !scanner.Scan() {
		return nil, nil, fmt.Errorf("failed to scan port forward std out")
	}
	if err = scanner.Err(); err != nil {
		return nil, nil, err
	}
	output := scanner.Text()

	port := strings.TrimSuffix(strings.TrimPrefix(output, "Forwarding from 127.0.0.1:"), " -> 2379")
	_, err = strconv.Atoi(port)
	if err != nil {
		return nil, nil, fmt.Errorf("port forward output not in expected format: %s", output)
	}

	coreV1 := kubeClient.CoreV1()
	etcdConfigMap, err := coreV1.ConfigMaps("openshift-config").Get("etcd-ca-bundle", metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	etcdSecret, err := coreV1.Secrets("openshift-config").Get("etcd-client", metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}

	tlsConfig, err := restclient.TLSConfigFor(&restclient.Config{
		TLSClientConfig: restclient.TLSClientConfig{
			CertData: etcdSecret.Data[corev1.TLSCertKey],
			KeyData:  etcdSecret.Data[corev1.TLSPrivateKeyKey],
			CAData:   []byte(etcdConfigMap.Data["ca-bundle.crt"]),
		},
	})
	if err != nil {
		return nil, nil, err
	}

	etcdClient3, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"https://127.0.0.1:" + port},
		DialTimeout: 30 * time.Second,
		TLS:         tlsConfig,
	})
	if err != nil {
		return nil, nil, err
	}

	return etcdClient3.KV, done, nil
}

func AssertEtcdSecretEncrypted(t *testing.T, kv clientv3.KV, namespace, name, expectedMode string) {
	t.Helper()
	secret := GetEtcdSecretMust(t, kv, namespace, name)

	require.NotEmpty(t, secret)
	require.NotEqual(t, []byte(aesCBCTransformerPrefixV1), secret)

	actualMode, isEncrypted := determineEncryptionMode(secret)
	require.Truef(t, isEncrypted, "not encrypted secret %s/%s\n%s", namespace, name, hex.Dump(secret))
	require.Equalf(t, expectedMode, actualMode, "unexpected mode %s for secret %s/%s\n%s", actualMode, namespace, name, hex.Dump(secret))
}

func AssertEtcdSecretNotEncrypted(t *testing.T, kv clientv3.KV, namespace, name string) {
	t.Helper()
	secret := GetEtcdSecretMust(t, kv, namespace, name)

	require.NotEmpty(t, secret)
	require.NotEqual(t, protoEncodingPrefix, secret)

	mode, isEncrypted := determineEncryptionMode(secret)
	require.Falsef(t, isEncrypted, "encrypted secret %s/%s\n%s", namespace, name, hex.Dump(secret))
	require.Equalf(t, "identity-proto", mode, "not protobuf secret %s/%s\n%s", namespace, name, hex.Dump(secret))
}

func determineEncryptionMode(data []byte) (string, bool) {
	isEncrypted := bytes.HasPrefix(data, []byte(protoEncryptedDataPrefix)) // all encrypted data has this prefix
	return func() string {
		switch {
		case bytes.HasPrefix(data, []byte(aesCBCTransformerPrefixV1)): // AES-CBC has this prefix
			return "aescbc"
		case bytes.HasPrefix(data, []byte(secretboxTransformerPrefixV1)): // Secretbox has this prefix
			return "secretbox"
		case bytes.HasPrefix(data, []byte(jsonEncodingPrefix)): // unencrypted json data has this prefix
			return "identity-json"
		case bytes.HasPrefix(data, protoEncodingPrefix): // unencrypted protobuf data has this prefix
			return "identity-proto"
		default:
			return "unknown" // this should never happen
		}
	}(), isEncrypted
}

func GetEtcdSecretMust(t *testing.T, kv clientv3.KV, namespace, name string) []byte {
	t.Helper()
	secret, err := GetEtcdSecret(kv, namespace, name)
	require.NoError(t, err)
	return secret
}

func GetEtcdSecret(kv clientv3.KV, namespace, name string) ([]byte, error) {
	key := fmt.Sprintf("/kubernetes.io/secrets/%s/%s", namespace, name)

	resp, err := kv.Get(context.Background(), key)
	switch {
	case err != nil:
		return nil, err
	case resp.Count == 0 || len(resp.Kvs) == 0:
		return nil, storage.NewKeyNotFoundError(key, 0)
	case resp.More || len(resp.Kvs) != 1 || resp.Count != 1:
		return nil, fmt.Errorf("invalid get response: %+v", resp)
	}

	return resp.Kvs[0].Value, nil
}

func ForceKeyRotation(operatorClient v1helpers.StaticPodOperatorClient, reason string) error {
	operatorSpec, _, resourceVersion, err := operatorClient.GetStaticPodOperatorStateWithQuorum()
	if err != nil {
		return err
	}

	data := map[string]map[string]string{
		"encryption": {
			"reason": reason,
		},
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}

	operatorSpec = operatorSpec.DeepCopy()
	operatorSpec.UnsupportedConfigOverrides.Raw = raw

	_, _, err = operatorClient.UpdateStaticPodOperatorSpec(resourceVersion, operatorSpec)
	return err
}
