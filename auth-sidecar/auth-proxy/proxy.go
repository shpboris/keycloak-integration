package main

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/open-policy-agent/opa/rego"
	"github.com/pkg/errors"
	"github.com/shpboris/logger"
	"gopkg.in/square/go-jose.v2/jwt"
	"io"
	"net/http"
	"strings"
)

const (
	proxyPort   = 8080
	servicePort = 8000
)

//go:embed policies/users_policy.rego
var policy string

func main() {
	http.ListenAndServe(fmt.Sprintf(":%d", proxyPort), &Proxy{})
}

type Proxy struct{}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	logger.Log.Info("Started ServeHTTP")
	if !p.isAuthorized(w, req) {
		return
	}
	res, err := p.forwardRequest(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	p.writeResponse(w, res)
	logger.Log.Info("Completed ServeHTTP")
}

func (p *Proxy) forwardRequest(req *http.Request) (*http.Response, error) {
	logger.Log.Info("Started forwardRequest")
	proxyUrl := fmt.Sprintf("http://127.0.0.1:%v%v", servicePort, req.RequestURI)
	origUri := fmt.Sprintf("http://%v%v", req.Host, req.RequestURI)
	logger.Log.Info("Proxy URL: " + proxyUrl)
	logger.Log.Info("Original URL: " + origUri)

	httpClient := http.Client{}
	proxyReq, err := http.NewRequest(req.Method, proxyUrl, req.Body)
	for name, values := range req.Header {
		proxyReq.Header[name] = values
	}
	res, err := httpClient.Do(proxyReq)
	logger.Log.Info("Completed forwardRequest")
	return res, err
}

func (p *Proxy) writeResponse(w http.ResponseWriter, res *http.Response) {
	logger.Log.Info("Started writeResponse")
	for name, values := range res.Header {
		w.Header()[name] = values
	}
	w.WriteHeader(res.StatusCode)
	io.Copy(w, res.Body)
	res.Body.Close()
	logger.Log.Info("Completed writeResponse")
}

func (p *Proxy) isAuthorized(w http.ResponseWriter, req *http.Request) bool {
	logger.Log.Info("Started isAuthorized")
	ctx := context.Background()
	authHeaderValue := req.Header.Get("Authorization")
	if len(strings.TrimSpace(authHeaderValue)) == 0 {
		msg := "Token not exist"
		http.Error(w, msg, http.StatusUnauthorized)
		logger.Log.Error(errors.New(msg))
		return false
	}

	tokenStr := strings.Split(authHeaderValue, " ")[1]
	token, err := jwt.ParseSigned(tokenStr)
	if err != nil {
		msg := "Token is invalid"
		http.Error(w, msg, http.StatusUnauthorized)
		logger.Log.Error(errors.New(msg))
		return false
	}
	var claims map[string]interface{}
	err = token.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		msg := "Token is invalid"
		http.Error(w, msg, http.StatusUnauthorized)
		logger.Log.Error(errors.New(msg))
		return false
	}

	data := make(map[string]interface{})
	data["url"] = req.URL
	data["method"] = req.Method
	data["claims"] = claims

	rego := rego.New(
		rego.Query("data.auth.allow"),
		rego.Module("policy.eval", policy),
		rego.Input(data),
	)

	rs, err := rego.Eval(ctx)
	if err != nil {
		msg := "Failed to evaluate request"
		http.Error(w, msg, http.StatusInternalServerError)
		logger.Log.Error(errors.New(msg))
		return false
	}

	res := rs.Allowed()
	logger.Log.Info(fmt.Sprintf("Authorization result: %v", res))
	if !res {
		msg := "Action is forbidden"
		http.Error(w, msg, http.StatusForbidden)
		logger.Log.Error(errors.New(msg))
		return false
	}
	logger.Log.Info("Completed isAuthorized")
	return rs.Allowed()
}
