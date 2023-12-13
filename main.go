package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
)

func hello(w http.ResponseWriter, req *http.Request) {
  fmt.Println("hello")
	if req.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	fmt.Fprintf(w, "hello\n")
}

func authorize(w http.ResponseWriter, req *http.Request) {
  fmt.Println("authorize")
	// curl "https://github.com/login/oauth/authorize/?client_id=${OAUTH_CLIENT_ID}&redirect_uri=${OAUTH_CALLBACK_URI}&state=this-is-a-random-state"
	if req.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	clientId := req.URL.Query().Get("client_id")
	state := req.URL.Query().Get("state")
	redirectUri := req.URL.Query().Get("redirect_uri")

	if clientId != oauthClientId {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if redirectUri != oauthCallbackUri {
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
  fmt.Println("accessToken")
	//  curl -X POST -H 'Accept: application/json' "https://github.com/login/oauth/access_token?client_id=${OAUTH_CLIENT_ID}&client_secret=${OAUTH_CLIENT_SECRET}&code=this-is-a-random-code"
	if req.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	clientId := req.URL.Query().Get("client_id")
	clientSecret := req.URL.Query().Get("client_secret")
	code := req.URL.Query().Get("code")

	if clientId != oauthClientId {
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
  fmt.Println("user")
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
	w.Write([]byte(fmt.Sprintf(`{"login": "%s", "id": %s}`, oauthUsername, oauthUserId)))
}

var oauthClientId = os.Getenv("OAUTH_CLIENT_ID")
var oauthClientSecret = os.Getenv("OAUTH_CLIENT_SECRET")
var oauthCallbackUri = os.Getenv("OAUTH_CALLBACK_URI")
var oauthUsername = os.Getenv("OAUTH_USERNAME")
var oauthUserId = os.Getenv("OAUTH_USERID")
var oauthCode = RandomString(32)
var oauthAccessToken = RandomString(32)
var port = os.Getenv("PORT")

func main() {
	if oauthClientId == "" {
		panic("OAUTH_CLIENT_ID is empty")
	}
	if oauthClientSecret == "" {
		panic("OAUTH_CLIENT_SECRET is empty")
	}
	if oauthCallbackUri == "" {
		panic("OAUTH_CALLBACK_URI is empty")
	}
	if port == "" {
		port = "8090"
	}
	if oauthUsername == "" {
		oauthUsername = "github-oauth2-login-mock-server-dummy-user"
	}
	if oauthUserId == "" {
		oauthUserId = "9999"
	}

	http.HandleFunc("/hello", hello)
	http.HandleFunc("/login/oauth/authorize", authorize)
	http.HandleFunc("/login/oauth/access_token", accessToken)
	http.HandleFunc("/user", user)

	fmt.Fprintf(os.Stderr, "Listening on port %s\n", port)
	http.ListenAndServe(fmt.Sprintf(":%s", port), nil)
}

func RandomString(n int) string {
  var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

    b := make([]rune, n)
    for i := range b {
      b[i] = letterRunes[rand.Intn(len(letterRunes))]
    }
  return string(b)
}
