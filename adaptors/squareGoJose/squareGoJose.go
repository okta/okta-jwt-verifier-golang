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

package squareGoJose

import (
	"net/http"
	"log"
	"encoding/json"
	"github.com/okta/okta-jwt-verifier-golang/adaptors"
)

type SquareGoJose struct {}

func (sqj *SquareGoJose) New() adaptors.Adaptor {
	return sqj
}

func (sqj *SquareGoJose) GetKeys(jwkUri string) map[int]interface{} {
	resp, err := http.Get(jwkUri)

	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	keys := make(map[int]interface{})
	json.NewDecoder(resp.Body).Decode(&keys)

	return keys
}

func (sqj *SquareGoJose) Decode(jwt string, keys map[string]interface{}) {

}
