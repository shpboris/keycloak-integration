package oauth2_infra

import (
	"encoding/json"
	"github.com/shpboris/logger"
	"net/http"
	"os"
	"shpboris/security-service/common/constants"
	"shpboris/security-service/common/utils"
	"strings"
)

func GetUserInfo(w http.ResponseWriter, r *http.Request) {
	logger.Log.Info("Started GetUserInfo")
	token := r.Header.Get(constants.TokenHeaderName)
	if len(strings.TrimSpace(token)) == 0 {
		utils.HandleSpecificError(w, "Token is empty", 400)
		return
	}
	realm := os.Getenv(constants.RealmEnvKey)
	client := utils.GetKeyCloakClient()
	userInfo, err := client.GetUserInfo(r.Context(), token, realm)
	if utils.HandlePossibleError(w, err) {
		return
	}
	err = json.NewEncoder(w).Encode(userInfo)
	if utils.HandlePossibleError(w, err) {
		return
	}
	logger.Log.Info("Completed GetUserInfo")
}
