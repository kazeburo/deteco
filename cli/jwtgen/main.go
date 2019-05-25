package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	flags "github.com/jessevdk/go-flags"
	"go.uber.org/zap"
)

type cmdOpts struct {
	PrivateKeyFile string        `long:"private-key" description:"private key for signing JWT auth header" required:"true"`
	PrivateKeyUser string        `long:"private-key-user" default:"private-key-user" description:"user id which is used as Subject in JWT payload"`
	MaxAge         time.Duration `long:"max-age" default:"1h" description:"max-age of JWT token"`
}

func readKeyFromPEM(key []byte) (interface{}, string, error) {
	rsaKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err == nil {
		return rsaKey, "RSA256", nil
	}
	ecKey, err := jwt.ParseECPrivateKeyFromPEM(key)
	if err == nil {
		return ecKey, "ES256", nil
	}
	return nil, "", err
}

func main() {
	opts := cmdOpts{}
	psr := flags.NewParser(&opts, flags.Default)
	_, err := psr.Parse()
	if err != nil {
		os.Exit(1)
	}
	logger, _ := zap.NewProduction()

	signBytes, err := ioutil.ReadFile(opts.PrivateKeyFile)
	if err != nil {
		logger.Fatal("", zap.Error(err))
	}

	signKey, signMethod, err := readKeyFromPEM(signBytes)
	if err != nil {
		logger.Fatal("", zap.Error(err))
	}

	iat := time.Now()
	exp := iat.Add(opts.MaxAge)
	t := jwt.NewWithClaims(jwt.GetSigningMethod(signMethod), jwt.StandardClaims{
		IssuedAt:  iat.Unix(),
		ExpiresAt: exp.Unix(),
		Issuer:    "deteco-jwtgen",
		Subject:   opts.PrivateKeyUser,
	})
	tokenString, err := t.SignedString(signKey)
	if err != nil {
		logger.Fatal("", zap.Error(err))
	}
	fmt.Printf("Authorization: Bearer %s\n", tokenString)
}
