package errorx

import (
	"fmt"
	"testing"
)

func TestNewException(t *testing.T) {
	err := New(101, "error error!")
	fmt.Println(err)
}
