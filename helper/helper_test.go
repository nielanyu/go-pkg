package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestBcrypt_ComparePasswords(t *testing.T) {
	s, e := HashAndSalt([]byte("a123456"))
	fmt.Println(e)
	fmt.Println(s)
	//$2a$04$B1y3Nb.3VFcdxFT3M3PdsuNXHUXyxb1jn/SgGx69DGBY1s2i3QLUW
	//$2a$04$fXs6Dr1oaVgQknzBNiioP.CN90iyGOBUvU4kObGWchPTFBLIGGf7e
	i := ComparePasswords(`$2a$04$fXs6Dr1oaVgQknzBNiioP.CN90iyGOBUvU4kObGWchPTFBLIGGf7e`, []byte("a123456"))
	fmt.Println(i)
}

func TestCheck_CheckPassWord620(t *testing.T) {
	fmt.Println(len(strings.TrimSpace("xx你好x")))
	fmt.Println(utf8.RuneCountInString(strings.TrimSpace("xx你好x")))

}

func TestGetFileAndDir(t *testing.T) {
	List, err := GetFileAndDir("")
	fmt.Println("list:", List, "::err::", err)
}

func TestGetFileAndDirRecursion(t *testing.T) {
	List, err := GetFileAndDirRecursion("")
	fmt.Println("list:", List, "::err::", err)
}

func TestConvert_StructToMap(t *testing.T) {
	var str = struct {
		Name string `json:"alias"`
		Age  int32  `json:"age"`
	}{
		Name: "Lily",
		Age:  18,
	}
	jsons, err := StructToMap(str)
	t.Log(jsons, err) //map[age:18 alias:Lily]  nil
}

// func TestRsa(t *testing.T) {

// 	//生成密钥对，保存到文件
// 	GenerateRSAKey(2048, "", "")
// 	message := []byte("hello world")
// 	//加密
// 	cipherText := RSAEncrypt(message, "public.pem")
// 	fmt.Println("加密后为:", string(cipherText))
// 	//解密
// 	plainText := RSAEncrypt(cipherText, "private.pem")
// 	fmt.Println("解密后为:", string(plainText))
// 	// AES加密
// 	aesKey := []byte("00000000000000000000000000000000")
// 	aesEncryptText, _ := AesEncrypt([]byte("hello world"), aesKey)
// 	fmt.Println("加密后为:", base64.StdEncoding.EncodeToString(aesEncryptText))
// 	// AES解密
// 	aesDecryptText, _ := AesDecrypt(aesEncryptText, aesKey)
// 	fmt.Println("解密后为:", string(aesDecryptText))
// }

func TestSendEmail(t *testing.T) {
	receiveList := []string{"x@qq.com"} //收件人邮箱地址

	info := &EmailInfo{

		receiveList,
		nil,
	}
	conf := EmailConfig{
		"smtp.exmail.qq.com",
		465,
		"x", //发件人邮箱地址
		"x",
	}
	t.Log(SendEmail("网页测试信息", "<h1>测试信息:</h1><p>mm~~~~~~~~</p>", info, conf))
}

func TestWGS84toGCJ02(t *testing.T) {
	var long, late float64
	long = 114.02597366
	late = 22.54605355
	GCJLong, GCJLate := WGS84toGCJ02(long, late)
	t.Logf("%f,%f", GCJLong, GCJLate)
}

func TestGCJ02toWGS84(t *testing.T) {
	var long, late float64
	long = 114.031032
	late = 22.543263
	WGSLong, WGSLate := GCJ02toWGS84(long, late)
	t.Logf("%f,%f", WGSLong, WGSLate)
}
func TestRandInt64(t *testing.T) {
	t.Log(RandInt64(42, 12)) //output:
}
func TestBasicOperator(t *testing.T) {
	t.Log(BasicOperation("32+12*1.8")) //output:
}

func TestPostFormUrlencoded(t *testing.T) {
	url := "https://cloud.satlic.com:9090/api/login.ashx"
	var Params = "username=username&password=password"
	//加密
	result, err := PostFormUrlencoded(context.Background(), url, Params, map[string]string{}, 1*time.Second)
	fmt.Println("result:", string(result))
	fmt.Println(err)
}

func TestSms_SendAliMessage(t *testing.T) {
	template, _ := json.Marshal(map[string]interface{}{
		"code": "9527",
	})
	//阿里短信配置参数
	aliConfig := AliSms{
		Key:          "key",
		Secret:       "secret",
		SignName:     "signname",
		TemplateCode: "alitemplatecode",
	}
	t.Log(SendAliMessage("15952624158", 1, template, aliConfig))
}

func TestFormDateToUnit(t *testing.T) {
	t.Log(FormDateToUnit("20190214")) //output: 1550073600
}
