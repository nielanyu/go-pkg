package helper

import (
	"fmt"
	"testing"
)

func TestRsaStore_Write(t *testing.T) {
	pu, pr, err := RSA{}.GenerateRSAKey(2048)
	fmt.Println(err)
	message := []byte("hello world")
	//加密
	cipherText, err := RSA{}.RSAEncrypt(message, pu)
	fmt.Println("加密后为：", string(cipherText))
	fmt.Println(err)
	//解密
	plainText, err := RSA{}.RSADecrypt(cipherText, pr)
	fmt.Println("解密后为：", string(plainText))
	fmt.Println(err)
}
