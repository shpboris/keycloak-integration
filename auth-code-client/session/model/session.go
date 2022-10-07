package model

import "golang.org/x/oauth2"

type Session struct {
	Token *oauth2.Token
}
