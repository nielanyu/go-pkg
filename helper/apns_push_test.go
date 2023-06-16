package helper

import "testing"

func TestApnsPush(t *testing.T) {
	var Config = ApnsConfig{
		PemFile:  "../../cert/test.pem",
		Password: "",
	}
	DeviceToken := "device token"
	Topic := "topic"
	Payload := `{"aps":{"alert":"Hello!"}}`
	res, err := ApnsPush(Config, DeviceToken, Topic, Payload)
	if err != nil {
		t.Log("apns push err: ", err)
	}
	t.Log("apns push res: ", res)
}
