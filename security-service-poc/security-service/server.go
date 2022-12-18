package main

import (
	"github.com/gorilla/mux"
	"github.com/shpboris/logger"
	"log"
	"net/http"
	"shpboris/security-service/oauth2_infra"
)

func main() {
	err := initAuth()
	if err != nil {
		return
	}
	r := mux.NewRouter()
	r.HandleFunc("/security/oauth2", oauth2_infra.Authorize)
	r.HandleFunc("/security/introspect", oauth2_infra.Introspect)
	logger.Log.Info("Server is running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

func initAuth() error {
	oauth2_infra.GetOauth2ConfigProvider().Init()
	return nil
}
