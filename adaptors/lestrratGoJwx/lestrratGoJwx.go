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
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/karrick/goswarm"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/okta/okta-jwt-verifier-golang/adaptors"
)

type LestrratGoJwx struct {
	JWKSet jwk.Set
	cache  *goswarm.Simple
}

func (lgj LestrratGoJwx) New() adaptors.Adaptor {
	return lgj
}

func (lgj LestrratGoJwx) GetKey(jwkUri string) {
}

func (lgj LestrratGoJwx) Decode(jwt string, jwkUri string) (interface{}, error) {
	if lgj.cache == nil {
		cache, err := goswarm.NewSimple(&goswarm.Config{
			GoodStaleDuration:  5 * time.Minute,
			GoodExpiryDuration: 10 * time.Minute,
			Lookup: func(url string) (interface{}, error) {
				return jwk.Fetch(context.Background(), url)
			},
		})
		if err != nil {
			return nil, err
		}
		lgj.cache = cache
	}

	value, err := lgj.cache.Query(jwkUri)
	if err != nil {
		return nil, err
	}

	jwkSet, ok := value.(jwk.Set)
	if !ok {
		return nil, errors.New("unable to fetch JWK Set")
	}

	token, err := jws.VerifySet([]byte(jwt), jwkSet)
	if err != nil {
		return nil, err
	}

	var claims interface{}

	if err := json.Unmarshal(token, &claims); err != nil {
		return nil, err
	}

	return claims, nil
}
