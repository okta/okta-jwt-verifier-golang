# Changelog

## v1.1.2

### Updates

- Only `alg` and `kid` claims in a JWT header are considered during verification.

## v1.1.3

### Updates

- Fixed edge cause with `aud` claim that would not find Auth0 being JWTs valid (thank you @awrenn).
- Updated readme with testing notes.
- Ran `gofumpt` on code for clean up.