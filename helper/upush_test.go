package helper

import "testing"

func TestPushAndroid(t *testing.T) {
	var Config = UmengConfig{
		HostUrl:                 "host_url",
		PostUri:                 "post_uri",
		PushProductionMode:      "push_production_mode",
		PushAndroidActivityChat: "push_android_activity_chat",
		PushAndroidActivityWeb:  "push_android_activity_web",
		AndroidConfig: AppKeySecretStruct{
			AppKey:       "android app key",
			MasterSecret: "android secret",
		},
		IOSConfig: AppKeySecretStruct{
			AppKey:       "ios app key",
			MasterSecret: "ios secret",
		},
	}
	MsgTicker := "MsgTicker"
	MsgTitle := "MsgTitle"
	MsgContext := "MsgContext"
	DeviceToken := "DeviceToken"
	extraData := map[string]string{
		"userId": "user ID",
	}
	//Android推送
	res, err := PushAndroid(Config, MsgTicker, MsgTitle, MsgContext, DeviceToken, extraData)
	if err != nil {
		t.Log("umeng push err :", err)
	}
	t.Log("umeng push res:", res)
}

func TestPushIOS(t *testing.T) {
	var Config = UmengConfig{
		HostUrl:                 "host_url",
		PostUri:                 "post_uri",
		PushProductionMode:      "push_production_mode",
		PushAndroidActivityChat: "push_android_activity_chat",
		PushAndroidActivityWeb:  "push_android_activity_web",
		AndroidConfig: AppKeySecretStruct{
			AppKey:       "android app key",
			MasterSecret: "android secret",
		},
		IOSConfig: AppKeySecretStruct{
			AppKey:       "ios app key",
			MasterSecret: "ios secret",
		},
	}
	Alert := "alert"
	MsgContext := "MsgContext"
	DeviceToken := "DeviceToken"
	//ios推送
	res, err := PushIOS(Config, Alert, MsgContext, DeviceToken, PushIOSTypeAdd, "")
	if err != nil {
		t.Log("umeng push err :", err)
	}
	t.Log("umeng push res:", res)
}
