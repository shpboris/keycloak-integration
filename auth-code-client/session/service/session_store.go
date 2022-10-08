package service

import (
	"shpboris/keycloak-integration/auth-code-client/session/model"
)

var idToTokenMap = make(map[string]*model.Session)

type SessionStoreService interface {
	StoreSession(sessionId string, session *model.Session)
	GetSession(sessionId string) *model.Session
}

type service struct{}

func GetSessionStoreService() SessionStoreService {
	return &service{}
}

func (s *service) StoreSession(sessionId string, session *model.Session) {
	idToTokenMap[sessionId] = session
}

func (s *service) GetSession(sessionId string) *model.Session {
	return idToTokenMap[sessionId]
}
