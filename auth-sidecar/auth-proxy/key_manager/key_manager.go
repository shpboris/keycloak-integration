package key_manager

import (
	"fmt"
	"github.com/Nerzal/gocloak/v11"
	"github.com/go-resty/resty/v2"
	"github.com/pkg/errors"
	"os"
)

func GetKey(keyId string, alg string) (*gocloak.CertResponseKey, error) {
	URI := os.Getenv("JWKS_URI")
	var certResponse gocloak.CertResponse
	client := resty.New()
	res, err := client.R().
		EnableTrace().
		SetResult(&certResponse).
		Get(URI)
	if res.IsError() || err != nil {
		return nil, errors.New("Failed to fetch JWKS info")
	}
	key := findUsedKey(keyId, alg, *certResponse.Keys)
	if key == nil {
		return nil, errors.New(fmt.Sprintf("Failed to find the key with id: %s in JWKS response", keyId))
	}
	return key, nil
}

func findUsedKey(keyId string, alg string, keys []gocloak.CertResponseKey) *gocloak.CertResponseKey {
	for _, key := range keys {
		if *(key.Kid) == keyId && *(key.Alg) == alg {
			return &key
		}
	}
	return nil
}
