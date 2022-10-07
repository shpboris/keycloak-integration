package oauth2_infra

import (
	"golang.org/x/oauth2"
	"os"
)

var config oauth2.Config

type Oauth2ConfigProvider interface {
	GetConfig() oauth2.Config
}

type service struct{}

func NewOauth2ConfigProvider() Oauth2ConfigProvider {
	return &service{}
}

func (s *service) GetConfig() oauth2.Config {
	return config
}

func InitOauth2ConfigProvider() {
	config = oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		RedirectURL:  os.Getenv("REDIRECT_URL"),
		Endpoint: oauth2.Endpoint{
			AuthURL:  os.Getenv("AUTH_URL"),
			TokenURL: os.Getenv("TOKEN_URL"),
		},
	}
}
