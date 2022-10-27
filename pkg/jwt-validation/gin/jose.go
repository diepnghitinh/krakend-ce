package gin

import (
	"fmt"
	"log"
	"net/http"
	//"strings"

	"github.com/auth0-community/go-auth0"
	"github.com/gin-gonic/gin"
	krakendjose "github.com/krakendio/krakend-ce/v2/pkg/jwt-validation"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
	ginkrakend "github.com/luraproject/lura/v2/router/gin"
	"gopkg.in/square/go-jose.v2/jwt"
)

func HandlerFactory(hf ginkrakend.HandlerFactory, logger logging.Logger) ginkrakend.HandlerFactory {
	return TokenSignatureValidator(hf, logger)
}

func TokenSignatureValidator(hf ginkrakend.HandlerFactory, logger logging.Logger) ginkrakend.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
		handler := hf(cfg, prxy)
		scfg, err := krakendjose.GetSignatureConfig(cfg)
		if err == krakendjose.ErrNoValidatorCfg {
			logger.Info("JOSE: validator disabled for the endpoint", cfg.Endpoint)
			return handler
		}
		if err != nil {
			logger.Warning(fmt.Sprintf("JOSE: validator for %s: %s", cfg.Endpoint, err.Error()))
			return handler
		}

		_, err = krakendjose.NewValidator(scfg, FromCookie)
		if err != nil {
			log.Fatalf("%s: %s", cfg.Endpoint, err.Error())
		}

		//var aclCheck func(string, map[string]interface{}, []string) bool

		//if strings.Contains(scfg.RolesKey, ".") {
		//	aclCheck = krakendjose.CanAccessNested
		//} else {
		//	aclCheck = krakendjose.CanAccess
		//}

		logger.Info("JOSE: validator enabled for the endpoint", cfg.Endpoint)

		return func(c *gin.Context) {
			_, err := krakendjose.ValidateRequest(scfg, c.Request)
			fmt.Sprintln("testing")
			if err != nil {
				c.AbortWithError(http.StatusUnauthorized, err)
				return
			}

			//Check HMAC
			//claims := map[string]interface{}{}
			//err = validator.Claims(c.Request, token, &claims)
			//if err != nil {
			//	c.AbortWithError(http.StatusUnauthorized, err)
			//	return
			//}

			//if rejecter.Reject(claims) {
			//			//	c.AbortWithStatus(http.StatusUnauthorized)
			//			//	return
			//			//}

			//if !aclCheck(scfg.RolesKey, claims, scfg.Roles) {
			//	c.AbortWithStatus(http.StatusForbidden)
			//	return
			//}

			handler(c)
		}
	}
}

func FromCookie(key string) func(r *http.Request) (*jwt.JSONWebToken, error) {
	if key == "" {
		key = "access_token"
	}
	return func(r *http.Request) (*jwt.JSONWebToken, error) {
		cookie, err := r.Cookie(key)
		if err != nil {
			return nil, auth0.ErrTokenNotFound
		}
		return jwt.ParseSigned(cookie.Value)
	}
}
