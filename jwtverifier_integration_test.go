// +build integration

package jwtverifier

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/suite"
)

type VerifierIntegrationTestSuite struct {
	suite.Suite
}

func TestVerifierIntegrationTestSuite(t *testing.T) {
	suite.Run(t, &VerifierIntegrationTestSuite{})
}

func (s *VerifierIntegrationTestSuite) Test_a_successful_authentication_can_have_its_tokens_parsed() {
	ParseEnvironment()

	if os.Getenv("ISSUER") == "" ||
		os.Getenv("CLIENT_ID") == "" ||
		os.Getenv("USERNAME") == "" ||
		os.Getenv("PASSWORD") == "" {

		s.FailNow("appears that environment variables are not set, skipping the integration test for now.")
		return
	}

	type AuthnResponse struct {
		SessionToken string `json:"sessionToken"`
	}

	nonce, err := GenerateNonce()
	s.Nil(err)

	// Get Session Token
	issuerParts, _ := url.Parse(os.Getenv("ISSUER"))
	baseUrl := issuerParts.Scheme + "://" + issuerParts.Hostname()
	requestUri := baseUrl + "/api/v1/authn"
	postValues := map[string]string{"username": os.Getenv("USERNAME"), "password": os.Getenv("PASSWORD")}
	postJsonValues, err := json.Marshal(postValues)
	s.Nil(err)
	resp, err := http.Post(requestUri, "application/json", bytes.NewReader(postJsonValues))
	s.Nil(err)

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	s.Nil(err)

	var authn AuthnResponse
	s.Nil(json.Unmarshal(body, &authn))

	// Issue get request with session token to get id/access tokens
	authzUri := os.Getenv("ISSUER") + "/v1/authorize?client_id=" + os.Getenv(
		"CLIENT_ID") + "&nonce=" + nonce + "&redirect_uri=http://localhost:8080/implicit/callback" +
		"&response_type=token%20id_token&scope=openid&state" +
		"=ApplicationState&sessionToken=" + authn.SessionToken

	client := &http.Client{
		CheckRedirect: func(req *http.Request, with []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err = client.Get(authzUri)
	s.Nil(err)

	defer resp.Body.Close()
	location := resp.Header.Get("Location")
	locParts, err := url.Parse(location)
	s.Nil(err)
	fragmentParts, err := url.ParseQuery(locParts.Fragment)
	s.Nil(err)

	s.NotNil(fragmentParts["access_token"])
	s.NotNil(fragmentParts["id_token"])

	accessToken := fragmentParts["access_token"][0]
	idToken := fragmentParts["id_token"][0]

	// Test verifying access token

	jv, err := New(os.Getenv("ISSUER"))
	s.Nil(err)

	claims, err := jv.VerifyIdTokenWithOpts(idToken, VerificationOpts{
		Leeway: nil,
		Claims: map[string]string{
			"aud":   os.Getenv("CLIENT_ID"),
			"nonce": nonce,
		},
	})
	s.Nil(err)
	s.NotNil(claims.Claims["iss"])

	// Test verifying access token
	claims, err = jv.VerifyAccessTokenWithOpts(accessToken, VerificationOpts{
		Leeway: nil,
		Claims: map[string]string{
			"aud": "api://default",
			"cid": os.Getenv("CLIENT_ID"),
		},
	})
	s.Nil(err)
	s.NotNil(claims.Claims["iss"])

	claims, err = jv.VerifyAccessTokenWithOpts(accessToken, VerificationOpts{
		Claims: map[string]string{
			"aud": "api://default",
		},
	})
	s.Nil(err)
	s.NotNil(claims.Claims["iss"])
}
