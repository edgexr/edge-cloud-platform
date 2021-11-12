package ormutil

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"golang.org/x/crypto/pbkdf2"
)

// As computing power grows, we should increase iter and salt bytes
var PasshashIter = 10000
var PasshashKeyBytes = 32
var PasshashSaltBytes = 8

func Passhash(pw, salt []byte, iter int) []byte {
	return pbkdf2.Key(pw, salt, iter, PasshashKeyBytes, sha256.New)
}

func NewPasshash(password string) (passhash, salt string, iter int) {
	saltb := make([]byte, PasshashSaltBytes)
	rand.Read(saltb)
	pass := Passhash([]byte(password), saltb, PasshashIter)
	return base64.StdEncoding.EncodeToString(pass),
		base64.StdEncoding.EncodeToString(saltb), PasshashIter
}

func PasswordMatches(password, passhash, salt string, iter int) (bool, error) {
	sa, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return false, err
	}
	ph := Passhash([]byte(password), sa, iter)
	phenc := base64.StdEncoding.EncodeToString(ph)
	return phenc == passhash, nil
}
