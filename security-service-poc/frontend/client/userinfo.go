package client

import (
	"encoding/json"
	"github.com/Nerzal/gocloak/v11"
	"github.com/shpboris/logger"
	"io/ioutil"
	"net/http"
	"os"
)

const (
	tokenHeader           = "token"
	GET                   = "GET"
	securityServiceUrlKey = "SECURITY_SERVICE_URL_KEY"
	userInfoUrlSuffix     = "/security/user-info"
)

func GetUserInfo(accessToken string) (*gocloak.UserInfo, error) {
	logger.Log.Info("Started GetUserInfo")
	client := http.Client{}
	securityServiceUrl, _ := os.LookupEnv(securityServiceUrlKey)
	userInfoUrl := securityServiceUrl + userInfoUrlSuffix
	req, err := http.NewRequest(GET, userInfoUrl, nil)
	if err != nil {
		return nil, err
	}
	req.Header = http.Header{
		tokenHeader: {accessToken},
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	responseData, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var userInfo gocloak.UserInfo
	err = json.Unmarshal(responseData, &userInfo)
	if err != nil {
		return nil, err
	}
	logger.Log.Info("Completed GetUserInfo")
	return &userInfo, nil
}
