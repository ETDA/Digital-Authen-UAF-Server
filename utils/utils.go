package utils

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"math/rand"
)

var runes = []byte("0123456789QAZWSXEDCRFVTGBYHNUJMIKOLPqazwsxedcrfvtgbyhnujmikolp")

func Unmarshal(s *string, v interface{}) error {
	return json.Unmarshal([]byte(*s), v)
}

func RandomRune(l int64) string {
	var s = make([]byte, l)
	var i int64 = 0
	for i = 0; i < l; i++ {
		s[i] = runes[rand.Intn(len(runes))]
	}
	return string(s)
}

func DecodeBase64Bytes(data string) []byte {
	var b = make([]byte, base64.RawURLEncoding.DecodedLen(len(data)))
	_, _ = base64.RawURLEncoding.Decode(b, []byte(data))
	return b
}

func Base64Encode(v interface{}) string {
	s, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(s)
}

func Base64Decode(data string, v interface{}) error {

	dec, err := base64.RawURLEncoding.DecodeString(data)

	if err != nil {
		return err
	}
	err = json.Unmarshal(dec, v)
	if err != nil {
		return err
	}
	return nil
}

func Sha256(data ...string) string {
	hash := sha256.New()
	for _, d := range data {
		_, err := hash.Write([]byte(d))
		if err != nil {
			return ""
		}
	}
	h := hex.EncodeToString(hash.Sum(nil))
	return h
}

func Contains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}

func GetSession(c *gin.Context) sessions.Session {
	session := sessions.Default(c)
	session.Options(sessions.Options{
		Path:     "/",
		MaxAge:   3600 * 12,
		Secure:   false,
		HttpOnly: true,
	})
	return session
}
