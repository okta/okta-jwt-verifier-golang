/*******************************************************************************
 * Copyright 2018 Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/

package jwtverifier

import (
	"fmt"
	"github.com/okta/okta-jwt-verifier-golang/discovery"
	"github.com/okta/okta-jwt-verifier-golang/discovery/oidc"
	"net/http"
	"log"
	"encoding/json"
	"github.com/okta/okta-jwt-verifier-golang/adaptors"
	"github.com/okta/okta-jwt-verifier-golang/adaptors/lestrratGoJwx"
	"github.com/okta/okta-jwt-verifier-golang/errors"
	"time"
	"strings"
)

type JwtVerifier struct {
	Issuer string

	ClientId string

	ClaimsToValidate map[string]string

	Discovery discovery.Discovery

	Adaptor adaptors.Adaptor
}

type Jwt struct {
	Claims map[string]interface{}
}

func (j *JwtVerifier) New() *JwtVerifier {
	// Default to OIDC discovery if none is defined
	if j.Discovery == nil {
		disc := oidc.Oidc{}
		j.Discovery = disc.New()
	}

	// Default to LestrratGoJwx Adaptor if none is defined
	if j.Adaptor == nil {
		adaptor := lestrratGoJwx.LestrratGoJwx{}
		j.Adaptor = adaptor.New()
	}

	return j
}


func (j *JwtVerifier) Verify(jwt string) (*Jwt, error) {

	if jwt == "" {
		return nil, errors.JwtEmptyStringError()
	}

	metaData := j.getMetaData()

	resp, err := j.Adaptor.Decode(jwt, metaData["jwks_uri"].(string))

	if err != nil {
		return nil, fmt.Errorf("could not decode token: %s", err)
	}
	token := resp.(map[string]interface{})

	myJwt := Jwt{
		Claims: token,
	}

	err = j.validateClaims(token)

	if err != nil {
		return &myJwt, fmt.Errorf("could not validate all claims: %s", err)
	}

	return &myJwt, nil
}

func (j *JwtVerifier) GetDiscovery() discovery.Discovery {
	return j.Discovery
}

func (j *JwtVerifier) GetAdaptor() adaptors.Adaptor {
	return j.Adaptor
}

func (j *JwtVerifier) validateClaims(claims map[string]interface{}) error {
	var allErrors []string

	err := j.validateNonce(claims["nonce"])
	if err != nil {
		allErrors = append(allErrors, err.Error())
	}

	err = j.validateAudience(claims["aud"])
	if err != nil {
		allErrors = append(allErrors, err.Error())
	}

	err = j.validateClientId(claims["cid"])
	if err != nil {
		allErrors = append(allErrors, err.Error())
	}

	err = j.validateExp(claims["exp"])
	if err != nil {
		allErrors = append(allErrors, err.Error())
	}

	err = j.validateIat(claims["iat"])
	if err != nil {
		allErrors = append(allErrors, err.Error())
	}

	if allErrors != nil {
		return fmt.Errorf("validation of claims failed:\n  %s", strings.Join(allErrors, "\n"))
	}

	return nil
}

func (j *JwtVerifier) validateNonce(nonce interface{}) error {
	if j.ClaimsToValidate["nonce"] == "" {
		return nil
	}
	if nonce != j.ClaimsToValidate["nonce"] {
		return fmt.Errorf("nonce: %s does not match %s", nonce, j.ClaimsToValidate["nonce"])
	}
	return nil
}

func (j *JwtVerifier) validateAudience(audience interface{}) error {
	if j.ClaimsToValidate["aud"] == "" {
		return nil
	}
	if audience != j.ClaimsToValidate["aud"] {
		return fmt.Errorf("aud: %s does not match %s", audience, j.ClaimsToValidate["aud"])
	}
	return nil
}

func (j *JwtVerifier) validateClientId(clientId interface{}) error {
	if j.ClaimsToValidate["cid"] == "" {
		return nil
	}

	if clientId != j.ClaimsToValidate["cid"] {
		return fmt.Errorf("clientId: %s does not match %s", clientId, j.ClaimsToValidate["cid"])
	}
	return nil
}

func (j *JwtVerifier) validateExp(exp interface{}) error {
	if float64(time.Now().Unix()) > exp.(float64) {
		return fmt.Errorf("the token is expired")
	}
	return nil
}

func (j *JwtVerifier) validateIat(iat interface{}) error {
	if float64(time.Now().Unix()) < iat.(float64) {
		return fmt.Errorf("the token was issued in the future")
	}
	return nil
}

func (j *JwtVerifier) getMetaData() map[string]interface{} {
	metaDataUrl := j.Issuer + j.Discovery.GetWellKnownUrl()

	resp, err := http.Get(metaDataUrl)

	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	md := make(map[string]interface{})
	json.NewDecoder(resp.Body).Decode(&md)

	return md
}
