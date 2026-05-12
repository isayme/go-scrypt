package scrypt

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

type Params struct {
	N      int
	R      int
	P      int
	KeyLen int
}

var DefaultParams = Params{
	N:      16384,
	R:      8,
	P:      1,
	KeyLen: 32,
}

func randomBytes(len int) ([]byte, error) {
	buf := make([]byte, len)
	_, err := rand.Read(buf)
	return buf, err
}

func Hash(password string, params Params) (string, error) {
	salt, err := randomBytes(8)
	if err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(password), salt, params.N, params.R, params.P, params.KeyLen)
	if err != nil {
		return "", err
	}

	b64Salt := base64.StdEncoding.EncodeToString(salt)
	b64Key := base64.StdEncoding.EncodeToString(key)

	hashed := fmt.Sprintf("$scrypt$n=%d,r=%d,p=%d$%s$%s", params.N, params.R, params.P, b64Salt, b64Key)
	return hashed, nil
}

func parseHashed(hashed string) (key, salt []byte, params Params, err error) {
	parts := strings.Split(hashed, "$")
	if len(parts) != 5 {
		err = fmt.Errorf("invalid format")
		return
	}
	if parts[1] != "scrypt" {
		err = fmt.Errorf("invalid format: algorithm")
		return
	}

	paramList := strings.Split(parts[2], ",")
	for _, param := range paramList {
		kv := strings.Split(param, "=")
		if len(kv) != 2 {
			err = fmt.Errorf("invalid format: param")
			return
		}

		val, err1 := strconv.Atoi(kv[1])
		if err1 != nil {
			err = err1
			return
		}

		switch kv[0] {
		case "n":
			params.N = val
		case "r":
			params.R = val
		case "p":
			params.P = val
		}
	}

	salt, err = base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		err = fmt.Errorf("invalid format: salt")
		return
	}

	key, err = base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		err = fmt.Errorf("invalid format: key")
		return
	}
	params.KeyLen = len(key)

	return
}

func Verify(password, hashed string) (bool, error) {
	key, salt, params, err := parseHashed(hashed)
	if err != nil {
		return false, err
	}

	expectKey, err := scrypt.Key([]byte(password), salt, params.N, params.R, params.P, params.KeyLen)
	return subtle.ConstantTimeCompare(key, expectKey) == 1, nil
}
