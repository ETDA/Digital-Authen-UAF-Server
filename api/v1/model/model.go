package model

import (
	"github.com/dgrijalva/jwt-go"
	db "github.com/etda-uaf/uaf-server/db/model"
)

type ApiResponse struct {
	Err     string      `json:"error,omitempty"`
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
}

type GetSessionResponse struct {
	Id       string `json:"id"`
	Status   string `json:"status"`
	Username string `json:"username"`
}

type AccountInfo struct {
	Account        db.Account
	Authenticators []db.Authenticator
}

type TransactRequest struct {
	Identity    string `json:"identity"`
	Transaction string `json:"transaction"`
}

type TransactResponse struct {
	Token    string `json:"token"`
	Request  string `json:"request"`
	QrCodeId string `json:"qr_code_id"`
}

type TokenClaim struct {
	UserId   string `json:"user_id"`
	ClientId string `json:"client_id"`
	QrCodeId string `json:"qr_code_id"`
	jwt.StandardClaims
}

func GetErrorResponse(msg string) ApiResponse {
	return ApiResponse{
		Err:     msg,
		Success: false,
	}
}

func GetSuccessResponse(data interface{}) ApiResponse {
	return ApiResponse{
		Success: true,
		Data:    data,
	}
}
