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
	"time"

	"github.com/stretchr/testify/suite"
)

type VerifierTestSuite struct {
	suite.Suite

	jv *JwtVerifier
}

func TestVerifierTestSuite(t *testing.T) {
	jv, err := New(testIssuer)
	if err != nil {
		t.Errorf("Failed to initialize test verifier: %s", err)
		t.FailNow()
	}

	suite.Run(t, &VerifierTestSuite{
		jv: jv,
	})
}

const testIssuer = "https://golang.oktapreview.com"

func (s *VerifierTestSuite) Test_the_verifier_defaults_to_oidc_if_nothing_is_provided_for_discovery() {
	_, ok := s.jv.discovery.(*OIDC)
	s.True(ok)
}

func (s *VerifierTestSuite) Test_the_verifier_defaults_to_lestrratGoJwx_if_nothing_is_provided_for_adaptor() {
	_, ok := s.jv.adaptor.(*JWXAdaptor)
	s.True(ok)
}

func (s *VerifierTestSuite) Test_can_validate_iss_from_issuer_provided() {
	s.NotNil(s.jv.validateIss("test"))
}

func (s *VerifierTestSuite) Test_can_validate_nonce() {
	err := s.jv.validateNonce("test", VerificationOpts{
		Leeway: nil,
		Claims: map[string]string{
			"nonce": "abc123",
		},
	})
	s.NotNil(err)
}

func (s *VerifierTestSuite) Test_can_validate_aud() {
	err := s.jv.validateAudience("test", VerificationOpts{
		Leeway: nil,
		Claims: map[string]string{
			"aud": "abc123",
		},
	})
	s.NotNil(err)
}

func (s *VerifierTestSuite) Test_can_validate_cid() {
	err := s.jv.validateClientId("test", VerificationOpts{
		Leeway: nil,
		Claims: map[string]string{
			"cid": "abc123",
		},
	})
	s.NotNil(err)
}

func (s *VerifierTestSuite) Test_can_validate_iat() {
	// token issued in future triggers error
	s.NotNil(s.jv.validateIat(float64(time.Now().Unix()+300), VerificationOpts{}))

	// token within leeway does not trigger error
	s.Nil(s.jv.validateIat(float64(time.Now().Unix()), VerificationOpts{}))
}

// TODO: Test default vs supplied expiration
func (s *VerifierTestSuite) Test_can_validate_exp() {
	// expired token triggers error
	s.NotNil(s.jv.validateExp(float64(time.Now().Unix()-300), VerificationOpts{}))

	// token within leeway does not trigger error
	s.Nil(s.jv.validateExp(float64(time.Now().Unix()), VerificationOpts{}))
}

// ID TOKEN TESTS
func (s *VerifierTestSuite) Test_invalid_formatting_of_id_token_throws_an_error() {
	_, err := s.jv.VerifyIdToken("aa")
	s.NotNil(err)
	s.Contains(err.Error(), "token must contain at least 1 period ('.')")
}

func (s *VerifierTestSuite) Test_an_id_token_header_that_is_improperly_formatted_throws_an_error() {
	_, err := s.jv.VerifyIdToken("123456789.aa.aa")
	s.NotNil(err)
	s.Contains(err.Error(), "does not appear to be a base64 encoded string")
}

func (s *VerifierTestSuite) Test_an_id_token_header_that_is_not_decoded_into_json_throws_an_error() {
	_, err := s.jv.VerifyIdToken("aa.aa.aa")
	s.NotNil(err)
	s.Contains(err.Error(), "not a json object")
}

func (s *VerifierTestSuite) Test_an_id_token_header_that_is_not_contain_the_correct_parts_throws_an_error() {
	_, err := s.jv.VerifyIdToken("at.aa.aa")
	s.NotNil(err)
	s.Contains(err.Error(), "the tokens header is not a json object")

	_, err = s.jv.VerifyIdToken("ew0KICAidGVzdCI6ICJ0aGlzIiwNCiAgImFuZCI6ICJ0aGlzIiwNCiAgImhlbGxvIjogIndvcmxkIg0KfQ.aa.aa")
	s.NotNil(err)
	s.Contains(err.Error(), "header contains too many properties")

	_, err = s.jv.VerifyIdToken("ew0KICAia2lkIjogImFiYzEyMyIsDQogICJhbmQiOiAidGhpcyINCn0.aa.aa")
	s.NotNil(err)
	s.Contains(err.Error(), "header must contain an 'alg'")

	_, err = s.jv.VerifyIdToken("ew0KICAiYWxnIjogIlJTMjU2IiwNCiAgImFuZCI6ICJ0aGlzIg0KfQ.aa.aa")
	s.Contains(err.Error(), "header must contain a 'kid'")
}

func (s *VerifierTestSuite) Test_an_id_token_header_that_is_not_rs256_throws_an_error() {
	_, err := s.jv.VerifyIdToken("ew0KICAia2lkIjogImFiYzEyMyIsDQogICJhbGciOiAiSFMyNTYiDQp9.aa.aa")
	s.NotNil(err)
	s.Contains(err.Error(), "only supported alg is RS256")
}

// ACCESS TOKEN TESTS
func (s *VerifierTestSuite) Test_invalid_formatting_of_access_token_throws_an_error() {
	_, err := s.jv.VerifyAccessToken("aa")
	s.NotNil(err)
	s.Contains(err.Error(), "token must contain at least 1 period ('.')")
}

func (s *VerifierTestSuite) Test_an_access_token_header_that_is_improperly_formatted_throws_an_error() {
	_, err := s.jv.VerifyAccessToken("123456789.aa.aa")
	s.NotNil(err)
	s.Contains(err.Error(), "does not appear to be a base64 encoded string")
}

func (s *VerifierTestSuite) Test_an_access_token_header_that_is_not_decoded_into_json_throws_an_error() {
	_, err := s.jv.VerifyAccessToken("aa.aa.aa")
	s.NotNil(err)
	s.Contains(err.Error(), "not a json object")
}

func (s *VerifierTestSuite) Test_an_access_token_header_that_is_not_contain_the_correct_parts_throws_an_error() {
	_, err := s.jv.VerifyAccessToken("ew0KICAidGVzdCI6ICJ0aGlzIg0KfQ.aa.aa")
	s.NotNil(err)
	s.Contains(err.Error(), "header does not contain enough properties")

	_, err = s.jv.VerifyAccessToken("ew0KICAidGVzdCI6ICJ0aGlzIiwNCiAgImFuZCI6ICJ0aGlzIiwNCiAgImhlbGxvIjogIndvcmxkIg0KfQ.aa.aa")
	s.NotNil(err)
	s.Contains(err.Error(), "header contains too many properties")

	_, err = s.jv.VerifyAccessToken("ew0KICAia2lkIjogImFiYzEyMyIsDQogICJhbmQiOiAidGhpcyINCn0.aa.aa")
	s.NotNil(err)
	s.Contains(err.Error(), "header must contain an 'alg'")

	_, err = s.jv.VerifyAccessToken("ew0KICAiYWxnIjogIlJTMjU2IiwNCiAgImFuZCI6ICJ0aGlzIg0KfQ.aa.aa")
	s.NotNil(err)
	s.Contains(err.Error(), "header must contain a 'kid'")
}

func (s *VerifierTestSuite) Test_an_access_token_header_that_is_not_rs256_throws_an_error() {
	_, err := s.jv.VerifyAccessToken("ew0KICAia2lkIjogImFiYzEyMyIsDQogICJhbGciOiAiSFMyNTYiDQp9.aa.aa")
	s.NotNil(err)
	s.Contains(err.Error(), "only supported alg is RS256")
}
