package jwtverifier

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/patrickmn/go-cache"
)

type Adaptor interface {
	Decode(jwt string) (map[string]interface{}, error)
}

type JWXAdaptor struct {
	jwksUri     string
	jwkKeyCache *cache.Cache
}

func NewJWXAdaptor(metaDataUrl string) (Adaptor, error) {
	jwksUri, err := getJWKSURI(metaDataUrl)
	if err != nil {
		return nil, fmt.Errorf("failed go get jwks uri: %w", err)
	}

	return &JWXAdaptor{
		jwksUri:     jwksUri,
		jwkKeyCache: cache.New(24*time.Hour, time.Hour),
	}, nil
}

func (a *JWXAdaptor) Decode(jwt string) (map[string]interface{}, error) {
	kid, err := getKid(jwt)
	if err != nil {
		return nil, err
	}

	jwkKey, err := a.getJwkKey(kid)
	if err != nil {
		return nil, err
	}

	token, err := jws.VerifyWithJWK([]byte(jwt), jwkKey)
	if err != nil {
		return nil, err
	}

	var claims map[string]interface{}
	if err = json.Unmarshal(token, &claims); err != nil {
		return claims, err
	}

	return claims, nil

}

func (a *JWXAdaptor) getJwkKey(kid string) (jwk.Key, error) {
	if x, found := a.jwkKeyCache.Get(kid); found {
		switch v := x.(type) {
		case error:
			return nil, v
		case jwk.Key:
			return v, nil
		default:
			return nil, errors.New("unknown value found in jwkKeyCache")
		}
	}

	jwkSet, err := jwk.FetchHTTP(a.jwksUri)
	if err != nil {
		return nil, err
	}

	// TODO: This probably needs to be just the key...
	keys := jwkSet.LookupKeyID(kid)
	if len(keys) < 1 {
		a.jwkKeyCache.SetDefault(kid, ErrJWKNotFound)
		return nil, ErrJWKNotFound
	}

	key := keys[len(keys)-1]
	a.jwkKeyCache.SetDefault(kid, key)

	return key, nil
}

func getJWKSURI(metaDataUrl string) (string, error) {
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Get(metaDataUrl)
	if err != nil {
		return "", fmt.Errorf("request for metadata was not successful: %w", err)
	}
	defer resp.Body.Close()

	md := make(map[string]interface{})
	if err := json.NewDecoder(resp.Body).Decode(&md); err != nil {
		return "", err
	}

	uri, ok := md["jwks_uri"]
	if !ok {
		return "", errors.New("jwks_uri not present in metadata")
	}

	return uri.(string), nil
}

func getKid(token string) (string, error) {
	header := strings.Split(token, ".")[0]

	headerBts, err := ioutil.ReadAll(base64.NewDecoder(base64.RawURLEncoding, strings.NewReader(header)))
	if err != nil {
		return "", fmt.Errorf("failed to read header base64: %w", err)
	}

	hm := map[string]interface{}{}
	if err := json.Unmarshal(headerBts, &hm); err != nil {
		return "", fmt.Errorf("failed to unmarshal header: %w", err)
	}

	kid, f := hm["kid"]
	if !f {
		return "", errors.New("kid not found in header")
	}

	kidStr, ok := kid.(string)
	if !ok {
		return "", errors.New("kid wrong type")
	}

	return kidStr, nil
}
