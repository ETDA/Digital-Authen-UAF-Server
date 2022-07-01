package model

import (
	"github.com/etda-uaf/uaf-server/app"
)

type OidcClient struct {
	ClientID         string
	ClientSecretHash string
	Name             string
	PublicKey        string
}
type OidcRedirectUri struct {
	ID           string
	Uri          string
	OidcClientId string
}

func FindOidcClient(clientId string) *OidcClient {
	var oidcClient OidcClient
	res := app.Db.First(&oidcClient, "client_id = ?", clientId)
	if res.Error != nil {
		return nil
	}
	return &oidcClient
}

func CheckRedirectUri(client OidcClient, redirectUri string) bool {
	var redirectUris []OidcRedirectUri
	res := app.Db.Find(&redirectUris, "oidc_client_id = ?", client.ClientID)
	if res.Error != nil {
		return false
	}
	for _, u := range redirectUris {
		if u.Uri == redirectUri {
			return true
		}
	}
	return false
}
