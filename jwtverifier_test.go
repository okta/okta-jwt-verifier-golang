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
	"reflect"
	"github.com/okta/okta-jwt-verifier-golang/discovery/oidc"
	"github.com/okta/okta-jwt-verifier-golang/adaptors/lestrratGoJwx"
	"github.com/okta/okta-jwt-verifier-golang/errors"
	"strings"
)

func Test_the_verifier_defaults_to_oidc_if_nothing_is_provided_for_discovery(t *testing.T) {
	jvs := JwtVerifier{
		Issuer: "issuer",
		ClientId: "clientId",
	}

	jv := jvs.New()

	if reflect.TypeOf(jv.GetDiscovery()) != reflect.TypeOf(oidc.Oidc{}) {
		t.Errorf("discovery did not set to oidc by default.  Was set to: %s",
			reflect.TypeOf(jv.GetDiscovery()))
	}
}

func Test_the_verifier_defaults_to_lestrratGoJwx_if_nothing_is_provided_for_adaptor(t *testing.T) {
	jvs := JwtVerifier{
		Issuer: "issuer",
		ClientId: "clientId",
	}

	jv := jvs.New()

	if reflect.TypeOf(jv.GetAdaptor()) != reflect.TypeOf(lestrratGoJwx.LestrratGoJwx{}) {
		t.Errorf("adaptor did not set to lestrratGoJwx by default.  Was set to: %s",
			reflect.TypeOf(jv.GetAdaptor()))
	}
}

func Test_an_error_is_set_if_jwt_is_empty_string_when_verifying(t *testing.T) {
	jvs := JwtVerifier{
		Issuer: "https://samples-test.oktapreview.com",
		ClientId: "clientId",
	}

	jv := jvs.New()

	_, err := jv.Verify("")

	if err == nil || err.Error() != errors.JwtEmptyStringError().Error() {
		t.Errorf("an error was not thrown for an empty jwt string")
	}

}

func Test_an_error_is_set_if_jwt_is_in_an_invalid_format(t *testing.T) {
	jvs := JwtVerifier{
		Issuer: "https://samples-test.oktapreview.com",
		ClientId: "clientId",
	}

	jv := jvs.New()

	_, err := jv.Verify("aa.bb.cc")

	if err == nil {
		t.Errorf("an error was not thrown for an invalid jwt string")
	}
	if !strings.Contains(err.Error(), "token is not valid") {
		t.Errorf("an error was not thrown when it should have: " + err.Error())
	}

	_, err = jv.Verify("aa.bb")

	if err == nil {
		t.Errorf("an error was not thrown for an incomplete jwt string")
	}
	if !strings.Contains(err.Error(), "token is not valid") {
		t.Errorf("an error was not thrown when it should have: " + err.Error())
	}

	_, err = jv.Verify("aa")

	if err == nil {
		t.Errorf("an error was not thrown for a string only")
	}

	if !strings.Contains(err.Error(), "token is not valid") {
		t.Errorf("an error was not thrown when it should have: " + err.Error())
	}

}
