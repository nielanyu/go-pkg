package response

import (
	"testing"

	"github.com/nielanyu/go-pkg/errorx"
	"github.com/nielanyu/go-pkg/i18n"

	"github.com/gin-gonic/gin"
)

func TestRes(t *testing.T) {
	//ctx := &gin.Context{}
	//JSON(ctx, []struct{}{}, errors.Exception(111, "sdfsdf", nil))

	var langPack1 = make(map[string]map[interface{}]interface{})
	i18n.LoadLangPack(langPack1)
	errorx.CodePrefix = 100

	e := errorx.New("", 200000)

	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		/*中间件 加trace_id*/
		ctx := c.Request.Context()
		c.Request = c.Request.WithContext(ctx)

		JSON(c, nil, e)
	})
	r.Run() // listen and serve on 0.0.0.0:8080

}
