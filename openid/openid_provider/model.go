package openid_provider

import "github.com/dgrijalva/jwt-go"

type AuthorizeRequest struct {
	ClientId     string `json:"client_id" form:"client_id"`
	RedirectUri  string `json:"redirect_uri" form:"redirect_uri"`
	ResponseType string `json:"response_type" form:"response_type"`
	Scope        string `json:"scope" form:"scope"`
	State        string `json:"state" form:"state"`
	Transaction  string `json:"transaction" form:"transaction"`
}
type AuthorizeResponse struct {
	Code      string `json:"code"`
	TokenType string `json:"token_type"`
	State     string `json:"state"`
}

type PostAuthorizeRequest struct {
	QrToken string `json:"qr_token" form:"qr_token"`
}

type AuthorizationCodeClaim struct {
	jwt.StandardClaims
	QrCodeId    string `json:"qr_code_id"`
	Transaction string `json:"transaction"`
	ClientId    string `json:"client_id"`
}

type TokenRequest struct {
	Code        string `json:"code" form:"code"`
	GrantType   string `json:"grant_type" form:"grant_type"`
	RedirectUri string `json:"redirect_uri" form:"redirect_uri"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	//RefreshToken string `json:"refresh_token"`
	TokenType string `json:"token_type"`
	ExpiresIn int64  `json:"expires_in"`
	Scope     string `json:"scope"`
	IdToken   string `json:"id_token"`
}

type TokenClaim struct {
	jwt.StandardClaims
	Id          string `json:"id"`
	Identity    string `json:"identity"`
	Transaction string `json:"transaction"`
	ClientId    string `json:"client_id"`
}

type TokenInfoRequest struct {
	Token         string `json:"token"`
	TokenTypeHint string `json:"token_type_hint"`
}

type UserInfoResponse struct {
	Identity        string `json:"identity"`
	Username        string `json:"username"`
	Transaction     string `json:"transaction"`
	AuthenticatorId string `json:"authenticator_id"`
	ClientId        string `json:"client_id"`
}
