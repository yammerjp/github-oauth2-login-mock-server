package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
)

func hello(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	fmt.Fprintf(w, "hello\n")
}

func authorize(w http.ResponseWriter, req *http.Request) {
	// curl "https://github.com/login/oauth/authorize/?client_id=${OAUTH_CLIENT_ID}&redirect_uri=${OAUTH_REDIRECT_URI}&state=this-is-a-random-state"
	if req.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	clientId := req.URL.Query().Get("client_id")
	state := req.URL.Query().Get("state")
	redirectUri := req.URL.Query().Get("redirect_uri")

	if clientId != oauthClientKey {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if redirectUri != oauthRedirectUri {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	u, err := url.Parse(redirectUri)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("state", state)
	q.Set("code", oauthCode)
	u.RawQuery = q.Encode()
	w.Header().Set("Location", u.String())
	w.WriteHeader(http.StatusFound)
}

func accessToken(w http.ResponseWriter, req *http.Request) {
	//  curl -X POST -H 'Accept: application/json' "https://github.com/login/oauth/access_token?client_id=${OAUTH_CLIENT_ID}&client_secret=${OAUTH_CLIENT_SECRET}&code=this-is-a-random-code"
	if req.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	clientId := req.URL.Query().Get("client_id")
	clientSecret := req.URL.Query().Get("client_secret")
	code := req.URL.Query().Get("code")

	if clientId != oauthClientKey {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if clientSecret != oauthClientSecret {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if code != oauthCode {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf(`{"access_token": "%s"}`, oauthAccessToken)))
}

func user(w http.ResponseWriter, req *http.Request) {
	//  curl -H "Authorization: Bearer this-is-a-random-access-token' -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' https://api.github.com/user
	if req.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if req.Header.Get("Authorization") != "Bearer "+oauthAccessToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if req.Header.Get("Accept") != "application/vnd.github+json" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if req.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"login": "%s", "id": %d}`, oauthUsername, oauthUserId)))
}

var oauthClientKey = os.Getenv("OAUTH_CLIENT_KEY")
var oauthClientSecret = os.Getenv("OAUTH_CLIENT_SECRET")
var oauthRedirectUri = os.Getenv("OAUTH_REDIRECT_URI")
var oauthUsername = "awkhan"
var oauthUserId = 123456
var oauthCode = "this-is-a-random-code"
var oauthAccessToken = "this-is-a-random-access-token"
var port = os.Getenv("PORT")

func main() {
	if oauthClientKey == "" {
		panic("OAUTH_CLIENT_KEY is empty")
	}
	if oauthRedirectUri == "" {
		panic("OAUTH_REDIRECT_URI is empty")
	}
	if port == "" {
		port = "8090"
	}
	http.HandleFunc("/hello", hello)
	http.HandleFunc("/login/oauth/authorize", authorize)
	http.HandleFunc("/login/oauth/authorize/", authorize) // TODO: remove this
	http.HandleFunc("/login/oauth/access_token", accessToken)
	http.HandleFunc("/user", user)

	fmt.Fprintf(os.Stderr, "Listening on port %s\n", port)
	http.ListenAndServe(fmt.Sprintf(":%s", port), nil)
}
