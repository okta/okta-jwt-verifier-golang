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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	ErrJWTEmptyString = errors.New("you must provide a jwt to verify")
	ErrJWKNotFound    = errors.New("jwk not found for kid")
)

type ConfigFunc = func(v *JwtVerifier)

func New(issuer string, configs ...ConfigFunc) (*JwtVerifier, error) {
	discovery := NewOIDCDiscovery()

	metaDataUrl := issuer + discovery.GetWellKnownUrl()

	adaptor, err := NewJWXAdaptor(metaDataUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize jwx adaptor: %w", err)
	}

	v := &JwtVerifier{
		issuer:        issuer,
		adaptor:       adaptor,
		discovery:     discovery,
		defaultLeeway: 0,
	}
	for _, fn := range configs {
		fn(v)
	}

	return v, nil
}

func WithDiscovery(discovery Discovery) ConfigFunc {
	return func(v *JwtVerifier) {
		v.discovery = discovery
	}
}

func WithAdaptor(adaptor Adaptor) ConfigFunc {
	return func(v *JwtVerifier) {
		v.adaptor = adaptor
	}
}

func WithDefaultLeeway(leeway int64) ConfigFunc {
	return func(v *JwtVerifier) {
		v.defaultLeeway = leeway
	}
}

// JwtVerifier verifies jwt tokens.
// It is thread safe and therefore you should always have one instance of the verifier per application.
// It is important to pass around a single instance to utilize RS256 key caching and the http thread pool
// for its client.
type JwtVerifier struct {
	issuer    string
	discovery Discovery
	adaptor   Adaptor
	// defaultLeeway is the leeway in seconds.
	defaultLeeway int64
}

type VerificationOpts struct {
	// Leeway is the leeway in seconds.
	Leeway *int64
	// Claims are the claims you want to validate on an individual token.
	Claims map[string]string
}

type Jwt struct {
	Claims map[string]interface{}
}

func (j *JwtVerifier) VerifyAccessToken(jwt string) (*Jwt, error) {
	return j.VerifyAccessTokenWithOpts(jwt, VerificationOpts{})
}

func (j *JwtVerifier) VerifyAccessTokenWithOpts(jwt string, opts VerificationOpts) (*Jwt, error) {
	validJwt, err := j.isValidJwt(jwt)
	if validJwt == false {
		return nil, fmt.Errorf("token is not valid: %w", err)
	}

	resp, err := j.decodeJwt(jwt)
	if err != nil {
		return nil, err
	}

	token := resp.(map[string]interface{})

	myJwt := Jwt{
		Claims: token,
	}

	err = j.validateIss(token["iss"])
	if err != nil {
		return &myJwt, fmt.Errorf("the `issuer` was not able to be validated. %w", err)
	}

	err = j.validateAudience(token["aud"], opts)
	if err != nil {
		return &myJwt, fmt.Errorf("the `Audience` was not able to be validated. %w", err)
	}

	err = j.validateClientId(token["cid"], opts)
	if err != nil {
		return &myJwt, fmt.Errorf("the `Client Id` was not able to be validated. %w", err)
	}

	err = j.validateExp(token["exp"], opts)
	if err != nil {
		return &myJwt, fmt.Errorf("the `Expiration` was not able to be validated. %w", err)
	}

	err = j.validateIat(token["iat"], opts)
	if err != nil {
		return &myJwt, fmt.Errorf("the `Issued At` was not able to be validated. %w", err)
	}

	return &myJwt, nil
}

func (j *JwtVerifier) decodeJwt(jwt string) (interface{}, error) {
	resp, err := j.adaptor.Decode(jwt)
	if err != nil {
		return nil, fmt.Errorf("could not decode token: %w", err)
	}

	return resp, nil
}

func (j *JwtVerifier) VerifyIdToken(jwt string) (*Jwt, error) {
	return j.VerifyIdTokenWithOpts(jwt, VerificationOpts{})
}

func (j *JwtVerifier) VerifyIdTokenWithOpts(jwt string, opts VerificationOpts) (*Jwt, error) {
	validJwt, err := j.isValidJwt(jwt)
	if validJwt == false {
		return nil, fmt.Errorf("token is not valid: %w", err)
	}

	resp, err := j.decodeJwt(jwt)
	if err != nil {
		return nil, err
	}

	token := resp.(map[string]interface{})

	myJwt := Jwt{
		Claims: token,
	}

	err = j.validateIss(token["iss"])
	if err != nil {
		return &myJwt, fmt.Errorf("the `issuer` was not able to be validated. %w", err)
	}

	err = j.validateAudience(token["aud"], opts)
	if err != nil {
		return &myJwt, fmt.Errorf("the `Audience` was not able to be validated. %w", err)
	}

	err = j.validateExp(token["exp"], opts)
	if err != nil {
		return &myJwt, fmt.Errorf("the `Expiration` was not able to be validated. %w", err)
	}

	err = j.validateIat(token["iat"], opts)
	if err != nil {
		return &myJwt, fmt.Errorf("the `Issued At` was not able to be validated. %w", err)
	}

	err = j.validateNonce(token["nonce"], opts)
	if err != nil {
		return &myJwt, fmt.Errorf("the `Nonce` was not able to be validated. %w", err)
	}

	return &myJwt, nil
}

func (j *JwtVerifier) validateNonce(nonce interface{}, opts VerificationOpts) error {
	if nonce != opts.Claims["nonce"] {
		return fmt.Errorf("nonce: %s does not match %s", nonce, opts.Claims["nonce"])
	}
	return nil
}

func (j *JwtVerifier) validateAudience(audience interface{}, opts VerificationOpts) error {
	if audience != opts.Claims["aud"] {
		return fmt.Errorf("aud: %s does not match %s", audience, opts.Claims["aud"])
	}
	return nil
}

func (j *JwtVerifier) validateClientId(clientId interface{}, opts VerificationOpts) error {
	// Client Id can be optional, it will be validated if it is present in the ClaimsToValidate array
	if cid, exists := opts.Claims["cid"]; exists && clientId != cid {
		return fmt.Errorf("clientId: %s does not match %s", clientId, cid)
	}
	return nil
}

func (j *JwtVerifier) getLeeway(opts VerificationOpts) (int64, error) {
	l := j.defaultLeeway

	// Override default with opts leeway
	if opts.Leeway != nil {
		l = *opts.Leeway
	}

	return l, nil
}

func (j *JwtVerifier) validateExp(exp interface{}, opts VerificationOpts) error {
	l, err := j.getLeeway(opts)
	if err != nil {
		return err
	}

	if float64(time.Now().Unix()-l) > exp.(float64) {
		return fmt.Errorf("the token is expired")
	}
	return nil
}

func (j *JwtVerifier) validateIat(iat interface{}, opts VerificationOpts) error {
	l, err := j.getLeeway(opts)
	if err != nil {
		return err
	}

	if float64(time.Now().Unix()+l) < iat.(float64) {
		return fmt.Errorf("the token was issued in the future")
	}
	return nil
}

func (j *JwtVerifier) validateIss(issuer interface{}) error {
	if issuer != j.issuer {
		return fmt.Errorf("iss: %s does not match %s", issuer, j.issuer)
	}
	return nil
}

func (j *JwtVerifier) isValidJwt(jwt string) (bool, error) {
	if jwt == "" {
		return false, ErrJWTEmptyString
	}

	// Verify that the JWT contains at least one period ('.') character.
	var jwtRegex = regexp.MustCompile(`[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.?([a-zA-Z0-9-_]+)[/a-zA-Z0-9-_]+?$`).MatchString
	if !jwtRegex(jwt) {
		return false, fmt.Errorf("token must contain at least 1 period ('.') and only characters 'a-Z 0-9 _'")
	}

	parts := strings.Split(jwt, ".")
	header := parts[0]
	header = padHeader(header)
	headerDecoded, err := base64.StdEncoding.DecodeString(header)

	if err != nil {
		return false, fmt.Errorf("the tokens header does not appear to be a base64 encoded string")
	}

	var jsonObject map[string]interface{}
	isHeaderJson := json.Unmarshal(headerDecoded, &jsonObject) == nil
	if isHeaderJson == false {
		return false, fmt.Errorf("the tokens header is not a json object")
	}

	if len(jsonObject) < 2 {
		return false, fmt.Errorf("the tokens header does not contain enough properties. " +
			"Should contain `alg` and `kid`")
	}

	if len(jsonObject) > 2 {
		return false, fmt.Errorf("the tokens header contains too many properties. " +
			"Should only contain `alg` and `kid`")
	}

	_, algExists := jsonObject["alg"]
	_, kidExists := jsonObject["kid"]

	if algExists == false {
		return false, errors.New("the tokens header must contain an 'alg'")
	}

	if kidExists == false {
		return false, errors.New("the tokens header must contain a 'kid'")
	}

	if jsonObject["alg"] != "RS256" {
		return false, errors.New("the only supported alg is RS256")
	}

	return true, nil
}

func padHeader(header string) string {
	if i := len(header) % 4; i != 0 {
		header += strings.Repeat("=", 4-i)
	}
	return header
}
