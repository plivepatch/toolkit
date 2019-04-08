package file

import (
	"bufio"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/plivepatch/go-utils/rsa"
)

func ToBytes(filePath string) ([]byte, error) {
	return ioutil.ReadFile(filePath)
}

func ToString(filePath string) (string, error) {
	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func ToTrimString(filePath string) (string, error) {
	str, err := ToString(filePath)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(str), nil
}

func ToTrimDecryptString(publicKey string, filePath string) (string, error) {
	brsa, err := ToBytes(filePath)
	if err != nil {
		return "", err
	}

	if err := rsa.RSA.SetPublicKey(publicKey); err != nil {
		return "", err
	}

	pubdecrypt, err := rsa.RSA.PubKeyDECRYPT(brsa)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(pubdecrypt)), nil
}

func ToTrimDecryptStringByString(filePath string, pubkey string) ([]byte, error) {
	brsa, err := ToBytes(filePath)
	if err != nil {
		return nil, err
	}

	if err := rsa.RSA.SetPublicKey(pubkey); err != nil {
		return nil, err
	}

	pubdecrypt, err := rsa.RSA.PubKeyDECRYPT(brsa)
	if err != nil {
		return nil, err
	}

	return pubdecrypt, nil
}

func ToTrimDecryptStringByPem(filePath string, pemPath string) (string, error) {
	brsa, err := ToBytes(filePath)
	if err != nil {
		return "", err
	}

	Pubkey, err := ToString(pemPath)
	if err != nil {
		return "", err
	}

	if err := rsa.RSA.SetPublicKey(Pubkey); err != nil {
		return "", err
	}

	pubdecrypt, err := rsa.RSA.PubKeyDECRYPT(brsa)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(pubdecrypt)), nil
}

func ToUint64(filePath string) (uint64, error) {
	content, err := ToTrimString(filePath)
	if err != nil {
		return 0, err
	}

	var ret uint64
	if ret, err = strconv.ParseUint(content, 10, 64); err != nil {
		return 0, err
	}
	return ret, nil
}

func ToInt64(filePath string) (int64, error) {
	content, err := ToTrimString(filePath)
	if err != nil {
		return 0, err
	}

	var ret int64
	if ret, err = strconv.ParseInt(content, 10, 64); err != nil {
		return 0, err
	}
	return ret, nil
}

func ReadLine(r *bufio.Reader) ([]byte, error) {
	line, isPrefix, err := r.ReadLine()
	for isPrefix && err == nil {
		var bs []byte
		bs, isPrefix, err = r.ReadLine()
		line = append(line, bs...)
	}

	return line, err
}
