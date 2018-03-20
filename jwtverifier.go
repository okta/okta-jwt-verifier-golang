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
	"github.com/okta/okta-jwt-verifier-golang/adaptors/squareGoJose"
)

type JwtVerifier struct {
	Issuer string

	ClientId string

	Audience string

	Nonce string

	Discovery discovery.Discovery

	Adaptor adaptors.Adaptor
}

type Jwt struct {}


func (j *JwtVerifier) Verify(jwt string) (*Jwt, error) {
	// Default to OIDC discovery if none is defined
	if j.Discovery == nil {
		discovery := oidc.Oidc{}
		j.Discovery = discovery.New()
	}

	// Default to SquareGoJose Adaptor if none is defined
	if j.Adaptor == nil {
		adaptor := squareGoJose.SquareGoJose{}
		j.Adaptor = adaptor.New()
	}

	if jwt == "" {
		return nil, fmt.Errorf("JWT could not be verified.  The error returned was: %s", "")
	}

	metaData := j.getMetaData()



	return &Jwt{}, nil
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
