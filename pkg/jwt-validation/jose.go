package jwtvalidation

import (
	"errors"
	"fmt"
	"github.com/auth0-community/go-auth0"
	"github.com/luraproject/lura/v2/proxy"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"net/http"
	"strings"
	"time"
)

var (
	// ErrTokenNotFound is returned by the ValidateRequest if the token was not
	// found in the request.
	ErrTokenNotFound      = errors.New("Token not found")
	ErrInvalidContentType = errors.New("should have a JSON content type for JWKS endpoint")
	ErrInvalidAlgorithm   = errors.New("algorithm is invalid")
	ErrTokenExpired       = errors.New("Validation failed, token is expired (exp)")
)

type ExtractorFactory func(string) func(r *http.Request) (*jwt.JSONWebToken, error)

func NewValidator(signatureConfig *SignatureConfig, ef ExtractorFactory) (*auth0.JWTValidator, error) {
	sa, ok := supportedAlgorithms[signatureConfig.Alg]
	if !ok {
		return nil, fmt.Errorf("JOSE: unknown algorithm %s", signatureConfig.Alg)
	}
	te := auth0.FromMultiple(
		auth0.RequestTokenExtractorFunc(auth0.FromHeader),
		auth0.RequestTokenExtractorFunc(ef(signatureConfig.CookieKey)),
	)

	decodedFs, err := DecodeFingerprints(signatureConfig.Fingerprints)
	if err != nil {
		return nil, err
	}

	cfg := SecretProviderConfig{
		URI:           signatureConfig.URI,
		CacheEnabled:  signatureConfig.CacheEnabled,
		Cs:            signatureConfig.CipherSuites,
		Fingerprints:  decodedFs,
		LocalCA:       signatureConfig.LocalCA,
		AllowInsecure: signatureConfig.DisableJWKSecurity,
	}

	sp, err := SecretProvider(cfg, te)
	if err != nil {
		return nil, err
	}

	return auth0.NewValidator(
		auth0.NewConfiguration(
			sp,
			signatureConfig.Audience,
			signatureConfig.Issuer,
			sa,
		),
		te,
	), nil
}

func ValidateRequest(signatureConfig *SignatureConfig, r *http.Request) (*jwt.JSONWebToken, error) {

	token, err := fromHeader(r)
	if err != nil {
		return nil, err
	}

	header := token.Headers[0]
	if header.Algorithm != string(signatureConfig.Alg) {
		return nil, ErrInvalidAlgorithm
	}

	raw, _ := tokenFromHeader(r)
	err = HashJwt(header.Algorithm, raw, signatureConfig.SecretKey)
	if err != nil {
		return nil, err
	}

	claims := jwt.Claims{}
	if err = token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, err
	}

	if claims.Expiry.Time().Before(time.Now()) {
		return nil, ErrTokenExpired
	}

	return token, err
}

func tokenFromHeader(r *http.Request) (string, error) {
	raw := ""
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[0:7], "BEARER ") {
		raw = h[7:]
	}
	if raw == "" {
		return "", ErrTokenNotFound
	}
	return raw, nil
}

func fromHeader(r *http.Request) (*jwt.JSONWebToken, error) {
	raw, _ := tokenFromHeader(r)

	if raw == "" {
		return nil, ErrTokenNotFound
	}
	return jwt.ParseSigned(raw)
}

// FromParams returns the JWT when passed as the URL query param "token".
func fromParams(r *http.Request) (*jwt.JSONWebToken, error) {
	raw := r.URL.Query().Get("token")
	if raw == "" {
		return nil, ErrTokenNotFound
	}
	return jwt.ParseSigned(raw)
}

func CanAccessNested(roleKey string, claims map[string]interface{}, required []string) bool {
	if len(required) == 0 {
		return true
	}

	tmp := claims
	keys := strings.Split(roleKey, ".")

	for _, key := range keys[:len(keys)-1] {
		v, ok := tmp[key]
		if !ok {
			return false
		}
		tmp, ok = v.(map[string]interface{})
		if !ok {
			return false
		}
	}
	return CanAccess(keys[len(keys)-1], tmp, required)
}

func CanAccess(roleKey string, claims map[string]interface{}, required []string) bool {
	if len(required) == 0 {
		return true
	}

	tmp, ok := claims[roleKey]
	if !ok {
		return false
	}

	roles, ok := tmp.([]interface{})
	if !ok {
		return false
	}

	for _, role := range required {
		for _, r := range roles {
			if r.(string) == role {
				return true
			}
		}
	}
	return false
}

func SignFields(keys []string, signer Signer, response *proxy.Response) error {
	for _, key := range keys {
		tmp, ok := response.Data[key]
		if !ok {
			continue
		}
		data, ok := tmp.(map[string]interface{})
		if !ok {
			continue
		}
		token, err := signer(data)
		if err != nil {
			return err
		}
		response.Data[key] = token
	}
	return nil
}

var supportedAlgorithms = map[string]jose.SignatureAlgorithm{
	"EdDSA": jose.EdDSA,
	"HS256": jose.HS256,
	"HS384": jose.HS384,
	"HS512": jose.HS512,
	"RS256": jose.RS256,
	"RS384": jose.RS384,
	"RS512": jose.RS512,
	"ES256": jose.ES256,
	"ES384": jose.ES384,
	"ES512": jose.ES512,
	"PS256": jose.PS256,
	"PS384": jose.PS384,
	"PS512": jose.PS512,
}
