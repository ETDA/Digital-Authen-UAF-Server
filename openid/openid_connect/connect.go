package openid_connect

import (
	"context"
	"errors"
	"github.com/etda-uaf/uaf-server/openid"
	"github.com/google/uuid"
	"github.com/thedevsaddam/gojsonq/v2"
	"golang.org/x/oauth2"
	"gopkg.in/h2non/gentleman.v2"
	"gopkg.in/h2non/gentleman.v2/plugins/auth"
	"log"
	"os"
	"strings"
)

var oauth2Config *oauth2.Config
var config openid.Configuration
var client *gentleman.Client

func Init() {

	client = gentleman.New()

	configUrl := os.Getenv("OIDP_CONFIG")
	resp, err := client.Get().BaseURL(configUrl).Do()
	if err != nil {
		log.Fatalln("Failed to get OIDC configuration")
	}
	err = resp.JSON(&config)
	if err != nil {
		log.Fatalln("Failed to parse OIDC configuration")
	}

	oauth2Config = &oauth2.Config{
		ClientSecret: os.Getenv("OIDP_CLIENT_SECRET"),
		ClientID:     os.Getenv("OIDP_CLIENT_ID"),
		RedirectURL:  os.Getenv("OIDP_REDIRECT_URL"),
		Scopes:       strings.Split(os.Getenv("OIDP_SCOPE"), ","),
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.AuthorizationEndpoint,
			TokenURL: config.TokenEndpoint,
		},
	}

	log.Println("OIDC config loaded")
}

func GetLoginUrl() (string, string) {
	state := uuid.NewString()
	return oauth2Config.AuthCodeURL(state), state
}

func Exchange(code string) (*string, *string, error) {
	t, err := oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		return nil, nil, err
	}
	return &t.AccessToken, &t.RefreshToken, nil
}

func GetUserInfo(token string) (*string, *string, error) {
	resp, err := client.Get().Use(auth.Bearer(token)).BaseURL(config.UserinfoEndpoint).Do()
	if err != nil {
		return nil, nil, err
	}

	jq := gojsonq.New().FromString(resp.String())
	identity := jq.Find(os.Getenv("OIDP_IDENTITY_FIELD"))
	if identity == nil {
		return nil, nil, errors.New("no identity field found")
	}

	name := jq.Reset().Find(os.Getenv("OIDP_USERNAME_FIELD"))
	if name == nil {
		return nil, nil, errors.New("no name field found")
	}
	i := identity.(string)
	n := name.(string)
	return &i, &n, nil
}
