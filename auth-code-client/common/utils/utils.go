package utils

import (
	"github.com/pkg/errors"
	"github.com/shpboris/logger"
	"net/http"
)

func HandlePossibleError(w http.ResponseWriter, err error) bool {
	if err != nil {
		logger.Log.Error(err.Error())
		http.Error(w, "Unexpected sever error", http.StatusInternalServerError)
		return true
	}
	return false
}

func HandleSpecificError(w http.ResponseWriter, msg string, statusCode int) bool {
	http.Error(w, msg, statusCode)
	logger.Log.Error(errors.New(msg))
	return false
}
