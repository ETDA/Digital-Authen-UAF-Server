FROM golang:1.16.2-alpine
RUN apk update && apk upgrade && apk add --no-cache bash git openssh
WORKDIR /app

COPY . /app


