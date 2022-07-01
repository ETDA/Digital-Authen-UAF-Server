package model

type ServerData struct {
	ServiceName string
	ServiceURL  string
	Id          string
	Challenge   string
}

type UserInfo struct {
	Identity string `json:"identity"`
	Name     string `json:"name"`
}
