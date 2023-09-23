package errorx

import (
	"fmt"
	"testing"
)

func TestNewException(t *testing.T) {
	err := New("error error!", -1)
	fmt.Println(err)
}
