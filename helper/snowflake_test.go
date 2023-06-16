package helper

import (
	"testing"
	"time"
)

func TestNewID(t *testing.T) {
	Snowflake{}.Init()
	_ = Snowflake{}.SetSnowflakeNode(1, 0)

	for i := 0; i <= 100; i++ {
		t.Log(Snowflake{}.NewID())
	}

	time.Sleep(10 * time.Second)
}
