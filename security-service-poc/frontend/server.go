package main

import (
	_ "embed"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/shpboris/logger"
	"log"
	"net/http"
	"shpboris/frontend/common/constants"
	"shpboris/frontend/common/utils"
)

//go:embed static/home.html
var home_resource string

//go:embed static/nested.html
var nested_resource string

func main() {
	r := mux.NewRouter()
	r.HandleFunc(constants.HomePagePath, homePage)
	r.HandleFunc(constants.NestedPagePath, nestedPage)
	logger.Log.Info("Server is running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

func homePage(w http.ResponseWriter, r *http.Request) {
	loadPage(w, r, constants.HomePagePath)
}

func nestedPage(w http.ResponseWriter, r *http.Request) {
	loadPage(w, r, constants.NestedPagePath)
}

func loadPage(w http.ResponseWriter, r *http.Request, path string) {
	msg := fmt.Sprintf("Handling request: %s, received token : %s", r.RequestURI, r.Header.Get("token"))
	logger.Log.Info(msg)
	w.Header().Set("Content-type", "text/html")
	var resourceBytes []byte
	if path == constants.HomePagePath {
		resourceBytes = []byte(home_resource)
	} else {
		resourceBytes = []byte(nested_resource)
	}
	_, err := w.Write(resourceBytes)
	utils.HandlePossibleError(w, err)
}
