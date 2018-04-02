# Okta JWT Verifier for Golang

This library helps you verify tokens that have been issued by Okta. To learn more about verification cases and Okta's tokens please read [Working With OAuth 2.0 Tokens](https://developer.okta.com/authentication-guide/tokens/)


## Installation
```sh
go get -u github.com/okta/okta-jwt-verifier-golang
```

## Usage

This library was built to keep configuration to a minimum. To get it running at its most basic form, all you need to provide is the the following information:

- **Issuer** - This is the URL of the authorization server that will perform authentication.  All Developer Accounts have a "default" authorization server.  The issuer is a combination of your Org URL (found in the upper right of the console home page) and `/oauth2/default`. For example, `https://dev-1234.oktapreview.com/oauth2/default`.
- **Client ID**- These can be found on the "General" tab of the Web application that you created earlier in the Okta Developer Console.

```go
import github.com/okta/okta-jwt-verifier-golang

jwtVerifierSetup := jwtverifier.JwtVerifier{
        Issuer: {{ISSUER}},
        ClientId: {{CLIENT_ID}},
}

verifier := jwtVerifierSetup.New()
```

Once you have the `verifier` set up, you can then issue the `Verify` command.

```go
token, err := verifier.Verify({JWT})
```

This will either provide you with the token which gives you access to all the claims, or an error. The token struct contains a `Claims` property that will give you a `map[string]interface{}` of all the claims in the token.

```go
//Geting the sub from the token
sub := token["sub"]
```

### Extended Usage
This library also gives you a way to verify the `nonce` and `audience` claims. To do this, during the verifier setup, you need to pass it a `claimsToValidate` property.

```go
toValidate := map[string]string{}
toValidate["nonce"] = {{NONCE}}
toValidate["aud"] = {{AUDIENCE}}

jwtVerifierSetup := JwtVerifier{
        Issuer: {{ISSUER}},
        ClientId: {{CLIENT_ID}},
        ClaimsToValidate: toValidate,
}

```
