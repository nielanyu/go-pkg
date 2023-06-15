package response

import (
	"net/http"

	"github.com/nielanyu/go-pkg/errorx"
	"github.com/nielanyu/go-pkg/i18n"
	"github.com/nielanyu/go-pkg/logger"

	"github.com/gin-gonic/gin"
)

type res struct {
	Code int64
	Msg  string
	Data interface{}
}

// JSON http json格式response响应
func JSON(c *gin.Context, v interface{}, err error) {
	spanCtx := logger.Start(c.Request.Context(), "ResponseJson")
	defer logger.End(spanCtx)

	lang := c.GetHeader("Accept-Language")

	r := &res{
		Code: 0,
		Msg:  "",
		Data: nil,
	}
	if err == nil {
		r.Code = 0
		r.Msg = i18n.T(lang, "success")
		if v != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": r.Code,
				"msg":  r.Msg,
				"data": v,
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"code": r.Code,
			"msg":  r.Msg,
		})
	} else {
		var m string
		iErr, ok := err.(*errorx.Error)
		if ok {
			r.Code = iErr.Code
			m = iErr.Msg
		} else {
			r.Code = 100000
		}
		//日志记录
		if m == "" {
			// 判断错误码类型
			// 屏蔽系统异常错误信息
			if r.Code%1000000 < 200000 {
				r.Msg = i18n.T(lang, 100000)
			} else {
				r.Msg = i18n.T(lang, int(r.Code%1000000))
			}
		} else {
			r.Msg = m
		}
		logger.Error(spanCtx, "response error", logger.Int64("code", r.Code), logger.String("msg", r.Msg))

		if v != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": r.Code,
				"msg":  r.Msg,
				"data": v,
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"code": r.Code,
			"msg":  r.Msg,
		})
	}
}
