package jwtverifier

type Discovery interface {
	GetWellKnownUrl() string
}

type OIDC struct {
	wellKnownUrl string
}

func NewOIDCDiscovery() Discovery {
	return &OIDC{wellKnownUrl: "/.well-known/openid-configuration"}
}

func (d *OIDC) GetWellKnownUrl() string {
	return d.wellKnownUrl
}
