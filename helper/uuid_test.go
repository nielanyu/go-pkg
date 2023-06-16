package helper

import (
	"testing"

	"github.com/nielanyu/go-pkg/redisx"
)

func TestUUID(t *testing.T) {
	config := redisx.Config{
		Cluster: false,
		Host:    "172.16.1.207",
		Port:    "16380",
		// Password: "",
		Protocol: "tcp",
	}
	UUID{}.Init(config)
	id, err := UUID{}.GetUniqueKey()
	t.Logf("%s,%s", id, err)
}
