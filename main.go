package main

// security.go
import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

func main() {
	psd := "123123"
	psdHash, _ := GeneratePasswordHash(psd)
	fmt.Println(psdHash)
	re := CheckPasswordHash(psdHash, psd)
	fmt.Println(re)
}

//生成盐
func _gen_salt(length int) string {
	BASE_STR := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	salt := ""
	rand.Seed(time.Now().Unix())
	for i := 0; i < length; i++ {
		salt += string(BASE_STR[rand.Intn(len(BASE_STR))])
	}
	return salt
}

//解析已存储的密码
func _parse(data string) (method string, salt string, h string) {

	r := strings.Split(data, "$")
	// fmt.Println(data)
	// fmt.Println(r[0], r[1], r[2])
	if (len(r)) < 3 {
		return "", "", ""
	}
	return r[0], r[1], r[2]
}

func _hash_internal(password string, salt string, iter int) (string, error) {
	t := pbkdf2.Key([]byte(password), []byte(salt), iter, 32, sha256.New)
	// newHashedPassword := pbkdf2.Key([]byte(password), []byte(salt), 600000, 32, sha256.New)
	// base64.StdEncoding.EncodeToString(newHashedPassword)

	// return fmt.Sprintf("pbkdf2_sha256$%s$%s$%s", strconv.Itoa(iter), salt, hex.EncodeToString(t)), nil
	return fmt.Sprintf("pbkdf2_sha256$%s$%s$%s", strconv.Itoa(iter), salt, base64.StdEncoding.EncodeToString(t)), nil
}

func GeneratePasswordHash(password string) (string, error) {
	salt := _gen_salt(22)
	if len(salt) <= 0 {
		return "", errors.New("gen salt error")
	}
	return _hash_internal(password, salt, 600000)
}

func CheckPasswordHash(pwhash string, password string) bool {
	_, _, salt := _parse(pwhash)
	fmt.Printf("salt is %s\n", salt)
	t, err := _hash_internal(password, salt, 600000)
	fmt.Printf("%s\n", t)
	if err != nil {
		return false
	}
	return strings.EqualFold(t, pwhash)
}
