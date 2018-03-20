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
	"testing"
	"fmt"
)

func TestTryingToVerifyWithNoJwtReturnsError(t *testing.T) {
	verifier := JwtVerifier{
		 issuer: "https://samples-test.oktapreview.com/oauth2/default",
		clientId: "0oae1yonf1hmdREQ80h7",
		audience: "api://default",
		nonce: "nonce",
	}
	_, err := verifier.Verify("")

	if err == nil {
		t.Errorf("An error was not returned when not providing a jwt to the Verify method")
	}
}

func TestIfNoDiscoveryIsProvidedItDefaultsToOauth(t *testing.T) {
	verifier := JwtVerifier{
		issuer: "https://samples-test.oktapreview.com/oauth2/default",
		clientId: "0oae1yonf1hmdREQ80h7",
		audience: "api://default",
		nonce: "nonce",
	}

	fmt.Println(verifier.GetDiscovery())
}

