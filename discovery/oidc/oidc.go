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

package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"

	"github.com/okta/okta-jwt-verifier-golang/discovery"
)

var metaDataCache *cache.Cache = cache.New(5*time.Minute, 10*time.Minute)
var metaDataMu = &sync.Mutex{}

type Oidc struct {
	wellKnownUrl string
}

func (d Oidc) New() discovery.Discovery {
	d.wellKnownUrl = "/.well-known/openid-configuration"
	return d
}

func (d Oidc) GetJWKSUri(issuer string) (string, error) {
	// https://developer.okta.com/docs/reference/api/oidc/#keys
	// "Okta strongly recommends retrieving keys dynamically with the JWKS published in the discovery document"
	metaDataUrl := issuer + d.wellKnownUrl

	metaDataMu.Lock()
	defer metaDataMu.Unlock()

	if x, found := metaDataCache.Get(metaDataUrl); found {
		return x.(map[string]interface{})["jwks_uri"].(string), nil
	}

	resp, err := http.Get(metaDataUrl)

	if err != nil {
		return "", fmt.Errorf("request for metadata was not successful: %s", err.Error())
	}

	defer resp.Body.Close()

	md := make(map[string]interface{})
	json.NewDecoder(resp.Body).Decode(&md)

	metaDataCache.SetDefault(metaDataUrl, md)

	return md["jwks_uri"].(string), nil
}
