package app

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/etda-uaf/uaf-server/fido/model"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"

	"github.com/joho/godotenv"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type AppConfig struct {
	MySQLHost         string
	MySQLPort         int64
	MySQLUsername     string
	MySQLPassword     string
	MySQLDatabase     string
	UAFEndpoint       string
	QR_ENDPOINT       string
	ServiceName       string
	ServiceUrl        string
	JwtSignKey        *ecdsa.PrivateKey
	JwtPublicKey      *ecdsa.PublicKey
	JwtExpireTime     time.Duration
	IdTokenExpireTime time.Duration
	SessionIdLength   int64
	ChallengeLength   int64
	Policy            model.Policy
	ConformanceMode   bool
	TrustedFacets     []model.TrustedFacets
	SessionStore      sessions.Store
}

var Config AppConfig
var Db *gorm.DB

func ParseConfig() {
	err := godotenv.Load()

	Config.MySQLHost = os.Getenv("MYSQL_HOST")
	Config.MySQLPort, err = strconv.ParseInt(os.Getenv("MYSQL_PORT"), 10, 32)
	if err != nil {
		log.Panicln("MySQL Port must be 1-65535")
	}
	Config.MySQLUsername = os.Getenv("MYSQL_USERNAME")
	Config.MySQLPassword = os.Getenv("MYSQL_PASSWORD")
	Config.MySQLDatabase = os.Getenv("MYSQL_DATABASE")
	Config.UAFEndpoint = os.Getenv("UAF_ENDPOINT")
	Config.QR_ENDPOINT = os.Getenv("QR_ENDPOINT")
	Config.ServiceName = os.Getenv("SERVICE_NAME")
	Config.ServiceUrl = os.Getenv("SERVICE_URL")

	p, err := hex.DecodeString(os.Getenv("JWT_SIGN_KEY"))
	if err != nil {
		log.Panicln("JWT sign key must be in hex format")
	}
	Config.JwtSignKey, err = ToECDSA(p, true)
	if err != nil {
		log.Panicln("JWT sign key cannot be parsed to ECDSA private key err = " + err.Error())
	}

	Config.ConformanceMode, err = strconv.ParseBool(os.Getenv("CONFORMANCE_MODE"))
	if err != nil {
		log.Panicln("conformance mode must be boolean")
	}

	Config.JwtPublicKey = Config.JwtSignKey.Public().(*ecdsa.PublicKey)

	Config.JwtExpireTime, err = time.ParseDuration(os.Getenv("JWT_EXPIRE_TIME") + "s")
	if err != nil {
		log.Panicln("JWT expire time must be integer")
	}

	Config.IdTokenExpireTime, err = time.ParseDuration(os.Getenv("OIDC_TOKEN_EXPIRE_TIME") + "s")
	if err != nil {
		log.Panicln("idtoken expire time must be integer")
	}

	Config.SessionIdLength, err = strconv.ParseInt(os.Getenv("SESSION_ID_LENGTH"), 10, 32)
	if err != nil {
		log.Panicln("session id length must be integer")
	}
	Config.ChallengeLength, err = strconv.ParseInt(os.Getenv("CHALLENGE_LENGTH"), 10, 32)
	if err != nil {
		log.Panicln("JWT expire time must be integer")
	}
	policy, err := ioutil.ReadFile("policy.json")
	if err != nil {
		log.Panicln("failed to read policy.json")
	}
	err = json.Unmarshal(policy, &Config.Policy)
	if err != nil {
		log.Panicln("failed to parse policy.json")
	}

	facets, err := ioutil.ReadFile("trusted_facets.json")
	if err != nil {
		log.Panicln("failed to read trusted_facets.json")
	}
	err = json.Unmarshal(facets, &Config.TrustedFacets)
	if err != nil {
		log.Panicln("failed to parse trusted_facets.json")
	}

	Db, err = gorm.Open(mysql.Open(fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?allowNativePasswords=true&parseTime=true",
		Config.MySQLUsername,
		Config.MySQLPassword,
		Config.MySQLHost,
		Config.MySQLPort,
		Config.MySQLDatabase)),
		&gorm.Config{})
	if err != nil {
		log.Panicln("failed to openid_connect to database")
	}

	sessionKey := os.Getenv("SESSION_ENCRYPT_KEY")
	if len(sessionKey) < 1 {
		log.Panicln("Session encrypt key must be text")
	}

	Config.SessionStore = cookie.NewStore([]byte(sessionKey))
}
