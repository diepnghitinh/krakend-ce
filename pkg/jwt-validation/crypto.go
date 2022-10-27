package jwtvalidation

import (
	"crypto/hmac"
	"crypto/sha256"
	b64 "encoding/base64"
	"fmt"
	"gopkg.in/square/go-jose.v2"
	"regexp"
	"strings"
)

func HashJwt(alg string, jwt string, key string) error {

	segment := strings.Split(jwt, ".")

	if alg == string(jose.HS256) {
		h := hmac.New(sha256.New, []byte(key))
		h.Write([]byte(fmt.Sprintf("%s.%s", segment[0], segment[1])))
		sha := h.Sum(nil)

		reg, err := regexp.Compile("[^A-Za-z0-9]+")
		if err != nil {
			return ErrInvalidAlgorithm
		}

		base64hmac := reg.ReplaceAllString(b64.StdEncoding.EncodeToString(sha), "")
		hmacSegment := reg.ReplaceAllString(segment[2], "")
		if base64hmac != hmacSegment {
			return ErrInvalidAlgorithm
		}
	}

	return nil

}