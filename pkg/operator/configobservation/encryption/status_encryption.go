package encryption

import (
	"encoding/base64"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/config/v1"
)

var encoder runtime.Encoder

func init() {
	scheme := runtime.NewScheme()
	codecs := serializer.NewCodecFactory(scheme)
	utilruntime.Must(apiserverconfigv1.AddToScheme(scheme))
	encoder = codecs.LegacyCodec(apiserverconfigv1.SchemeGroupVersion)
}

type EncryptionStatusController struct{}

func (c *EncryptionStatusController) getEncryptionConfigurationOrDie(currKey, prevKey, nextKey []byte) []byte {
	encryptionConfig := &apiserverconfigv1.EncryptionConfiguration{
		Resources: []apiserverconfigv1.ResourceConfiguration{
			{
				Resources: c.resources,
				Providers: []apiserverconfigv1.ProviderConfiguration{
					keyToConfig(currKey),
					keyToConfig(nextKey),
					keyToConfig(prevKey),
				},
			},
		},
	}

	bytes, err := runtime.Encode(encoder, encryptionConfig)
	if err != nil {
		panic(err) // indicates static generated code is broken, unrecoverable
	}

	return bytes
}

func keyToConfig(key []byte) apiserverconfigv1.ProviderConfiguration {
	if len(key) == 0 {
		return apiserverconfigv1.ProviderConfiguration{
			Identity: &apiserverconfigv1.IdentityConfiguration{},
		}
	}
	return apiserverconfigv1.ProviderConfiguration{
		AESCBC: &apiserverconfigv1.AESConfiguration{
			Keys: []apiserverconfigv1.Key{
				{
					Name:   "??", // TODO fix
					Secret: base64.StdEncoding.EncodeToString(key),
				},
			},
		},
	}
}
