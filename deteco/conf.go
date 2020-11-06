package deteco

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"strings"

	"github.com/BurntSushi/toml"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// Conf :
type Conf struct {
	logger   *zap.Logger
	tomlConf TomlConf
	Services map[string]*Service
}

// TomlConf : root struct
type TomlConf struct {
	Services []TomlService `toml:"services"`
}

// TomlService : services for parse toml
type TomlService struct {
	ID         string   `toml:"id"`
	Paths      []string `toml:"paths"`
	PublicKeys []string `toml:"public_keys"`
}

// Service :
type Service struct {
	id         string
	paths      []string
	publicKeys []*PublicKey
}

// PublicKey :
type PublicKey struct {
	keyType string
	rsa     *rsa.PublicKey
	ecdsa   *ecdsa.PublicKey
}

// NewConf :
func NewConf(confPath string, logger *zap.Logger) (*Conf, error) {
	var tomlConf TomlConf
	_, err := toml.DecodeFile(confPath, &tomlConf)
	if err != nil {
		return nil, err
	}
	conf := &Conf{
		logger:   logger,
		tomlConf: tomlConf,
	}

	err = conf.LoadServices()
	if err != nil {
		return nil, err
	}

	return conf, nil
}

// LoadServices :
func (c *Conf) LoadServices() error {
	if len(c.tomlConf.Services) == 0 {
		return errors.New("No services defined")
	}

	servicesMap := map[string]*Service{}
	for _, service := range c.tomlConf.Services {
		if service.ID == "" {
			return errors.New("id is empty")
		}
		if len(service.Paths) == 0 {
			return errors.Errorf("No Paths in %s", service.ID)
		}
		if len(service.PublicKeys) == 0 {
			return errors.Errorf("No PublicKeys in %s", service.ID)
		}
		if _, ok := servicesMap[service.ID]; ok {
			return errors.Errorf("Service %s is already exists", service.ID)
		}

		var parsedPaths []string
		for _, path := range service.Paths {
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			if !strings.HasSuffix(path, "/") {
				path = path + "/"
			}
			parsedPaths = append(parsedPaths, path)
		}

		var verifyKeys []*PublicKey
		for _, key := range service.PublicKeys {
			verifyKey, err := parsePublicKeyFromPEM([]byte(key))
			if err != nil {
				return errors.WithMessagef(err, "Failed read public key in %s", service.ID)
			}
			verifyKeys = append(verifyKeys, verifyKey)
		}

		servicesMap[service.ID] = &Service{
			id:         service.ID,
			paths:      parsedPaths,
			publicKeys: verifyKeys,
		}
	}
	c.Services = servicesMap
	return nil
}

func parsePublicKeyFromPEM(key []byte) (*PublicKey, error) {
	rsaKey, err := jwt.ParseRSAPublicKeyFromPEM(key)
	if err == nil {
		return &PublicKey{
			keyType: "rsa",
			rsa:     rsaKey,
			ecdsa:   nil,
		}, nil
	}
	ecdsaKey, err := jwt.ParseECPublicKeyFromPEM(key)
	if err == nil {
		return &PublicKey{
			keyType: "ecdsa",
			rsa:     nil,
			ecdsa:   ecdsaKey,
		}, nil
	}
	return nil, errors.New("Could not parse public key")
}

// GetService :
func (c *Conf) GetService(id string) (*Service, error) {
	if service, ok := c.Services[id]; ok {
		return service, nil
	}
	return nil, errors.Errorf("Could not find service %s", id)
}

// GetKey for PublicKey
func (pk *PublicKey) GetKey() interface{} {
	if pk.keyType == "rsa" {
		return pk.rsa
	}
	return pk.ecdsa
}
