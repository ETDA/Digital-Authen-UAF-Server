package model

type RegistrationContext struct {
	UserName string `json:"username"`
}

type AuthenticationContext struct {
	UserName    string  `json:"username"`
	Transaction *string `json:"transaction"`
}

type DeregistrationContext struct {
	UserName       string `json:"username"`
	DeregisterAAID string `json:"deregisterAAID"`
	DeregisterAll  bool   `json:"deregisterAll"`
}
