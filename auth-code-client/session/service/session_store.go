package service

import (
	"shpboris/auth-code-client/session/model"
)

var idToTokenMap = make(map[string]*model.Session)

type SessionStoreService interface {
	StoreSession(sessionId string, session *model.Session)
	GetSession(sessionId string) *model.Session
	DeleteSession(sessionId string)
}

type service struct{}

func (s *service) DeleteSession(sessionId string) {
	delete(idToTokenMap, sessionId)
}

func GetSessionStoreService() SessionStoreService {
	return &service{}
}

func (s *service) StoreSession(sessionId string, session *model.Session) {
	idToTokenMap[sessionId] = session
}

func (s *service) GetSession(sessionId string) *model.Session {
	return idToTokenMap[sessionId]
}
