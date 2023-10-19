FROM golang:1.20-alpine AS builder

WORKDIR /app

COPY . .
RUN go build -o github-oauth2-login-mock-server /app/main.go

FROM alpine
WORKDIR /app
COPY --from=builder /app/github-oauth2-login-mock-server /github-oauth2-login-mock-server

EXPOSE 8080
CMD [ "/github-oauth2-login-mock-server" ]
