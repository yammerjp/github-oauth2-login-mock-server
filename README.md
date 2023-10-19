# github-oauth2-login-mock-server

This is a HTTP mock server of GitHub login for E2E test.

## run

```sh
OAUTH_CLIENT_ID=clientkey OAUTH_CLIENT_SECRET=clientsecret OAUTH_CALLBACK_URI="http://localhost:8080/hello" PORT=8080 go run main.go
```

```sh
export OAUTH_CLIENT_ID=clientkey
export OAUTH_CLIENT_SECRET=clientsecret
export OAUTH_CALLBACK_URI=http://localhost:8080/hello
export GITHUB_LOGIN_SERVER=http://localhost:8080 # https://github.com
export GITHUB_API_SERVER=http://localhost:8080 # https://api.github.com
curl --verbose "${GITHUB_LOGIN_SERVER}/login/oauth/authorize/?client_id=${OAUTH_CLIENT_ID}&redirect_uri=${OAUTH_CALLBACK_URI}&state=this-is-a-random-state"
curl --verbose -X POST -H 'Accept: application/json' "${GITHUB_LOGIN_SERVER}/login/oauth/access_token?client_id=${OAUTH_CLIENT_ID}&client_secret=${OAUTH_CLIENT_SECRET}&code=this-is-a-random-code"
curl --verbose -H 'Authorization: Bearer this-is-a-random-access-token' -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' "${GITHUB_API_SERVER}/user"
```
