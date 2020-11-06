package deteco

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/karlseguin/ccache"
	"github.com/pkg/errors"

	jwt "github.com/dgrijalva/jwt-go"
	"go.uber.org/zap"
)

// Handler handlers
type Handler struct {
	logger    *zap.Logger
	freshness time.Duration
	conf      *Conf
	cache     *ccache.Cache
	cacheSize int64
}

// NewHandler :
func NewHandler(conf *Conf, freshness time.Duration, cache *ccache.Cache, cacheSize int64, logger *zap.Logger) (*Handler, error) {
	return &Handler{
		conf:      conf,
		freshness: freshness,
		logger:    logger,
		cache:     cache,
		cacheSize: cacheSize,
	}, nil
}

// Hello : hello handler
func (h *Handler) Hello() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK\n"))
	}
}

// Auth : Auth handler
func (h *Handler) Auth() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		service, err := h.VerifyAuthHeader(r.Header.Get("Authorization"))
		if err != nil {
			h.logger.Warn("Failed to authorize JWT", zap.Error(err))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		err = h.VerifyOriginURI(r.Header.Get("X-Original-URI"), service)
		if err != nil {
			h.logger.Warn("Not allowed access", zap.Error(err))
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		h.logger.Info("Authorized",
			zap.String("service", service.id),
			zap.String("path", r.Header.Get("X-Original-URI")),
		)
		w.Header().Add("X-Deteco-User", service.id)
		w.Write([]byte("OK\n"))
	}
}

// VerifyOriginURI :
func (h *Handler) VerifyOriginURI(path string, service *Service) error {
	if path == "" {
		return errors.New("No Origin URI header")
	}
	paths := strings.Split(path, "?")
	path = paths[0]
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if !strings.HasSuffix(path, "/") {
		path = path + "/"
	}
	for _, try := range service.paths {
		if strings.Index(path, try) == 0 {
			return nil
		}
	}
	return errors.New("Not matches path")
}

// VerifyAuthHeader verify auth header
func (h *Handler) VerifyAuthHeader(t string) (*Service, error) {
	if t == "" {
		return nil, fmt.Errorf("no tokenString")
	}
	t = strings.TrimPrefix(t, "Bearer ")

	if h.cacheSize > 0 {
		item := h.cache.Get(t)
		if item != nil && !item.Expired() {
			cachedService := item.Value().(*Service)
			return cachedService, nil
		}
	}

	service, err := h.GetService(t)
	if err != nil {
		return nil, err
	}
	for _, pk := range service.publicKeys {
		verifyClaims, verifyErr := h.TryVerifyJWT(t, pk)
		if verifyErr == nil {
			if h.cacheSize > 0 {
				h.cache.Set(t, service, time.Unix(verifyClaims.ExpiresAt, 0).Sub(time.Now()))
			}
			return service, nil
		}
		err = verifyErr
	}
	return nil, err
}

// GetService :
func (h *Handler) GetService(t string) (*Service, error) {
	claims := &jwt.StandardClaims{}
	jwp := &jwt.Parser{
		ValidMethods:         []string{"RS256", "RS384", "RS512"},
		SkipClaimsValidation: true,
	}
	_, _, err := jwp.ParseUnverified(t, claims)
	if err != nil {
		return nil, err
	}
	if claims.Subject == "" {
		return nil, errors.New("No Sub in payload")
	}
	service, err := h.conf.GetService(claims.Subject)
	if err != nil {
		return nil, err
	}
	return service, nil
}

// TryVerifyJWT :
func (h *Handler) TryVerifyJWT(t string, pk *PublicKey) (*jwt.StandardClaims, error) {
	claims := &jwt.StandardClaims{}
	jwp := &jwt.Parser{
		ValidMethods:         []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"},
		SkipClaimsValidation: false,
	}
	_, err := jwp.ParseWithClaims(t, claims, func(token *jwt.Token) (interface{}, error) {
		return pk.GetKey(), nil
	})

	if err != nil {
		return nil, errors.Wrap(err, "Token is invalid")
	}

	now := time.Now()
	iat := now.Add(-h.freshness)
	if claims.ExpiresAt == 0 || claims.ExpiresAt < now.Unix() {
		return nil, errors.New("Token is expired")
	}
	if claims.IssuedAt == 0 || claims.IssuedAt < iat.Unix() {
		return nil, errors.New("Token is too old")
	}
	return claims, nil
}
