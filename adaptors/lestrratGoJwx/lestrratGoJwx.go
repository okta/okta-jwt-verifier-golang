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

package lestrratGoJwx

import (
	"github.com/okta/okta-jwt-verifier-golang/adaptors"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"encoding/json"
)

type LestrratGoJwx struct {
	JWKSet jwk.Set
}

func (lgj LestrratGoJwx) New() adaptors.Adaptor {
	return lgj
}

func (lgj LestrratGoJwx) GetKey(jwkUri string) {
	return
}

func (lgj LestrratGoJwx) Decode(jwt string, jwkUri string) (interface{}, error) {

	token, err := jws.VerifyWithJKU([]byte(jwt), jwkUri)

	if err != nil {
		return nil, err
	}

	var claims interface{}

	json.Unmarshal(token, &claims)

	return claims, nil

}
