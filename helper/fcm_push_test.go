package helper

import "testing"

func TestFcmPush(t *testing.T) {
	var data = struct {
		Name string `json:"name"`
	}{
		Name: "Lawrence",
	}
	var Config = FcmConfig{
		ApiAccessKey: "api access key",
		MessageApi:   "http://soa-api.dev.nongbotech.cn/base/auth/code/get-captcha",
	}
	res := FCMPush(Config, data)
	t.Log("res:", res)
}
