#### logger

log and trace

#### Feature

- [x] 支持日志及切分
- [x] 支持追踪（基于 `opentelemetry`）
- [x] 支持 Debug,Info,Warn,Error,Fatal 日志等级
- [x] 支持异常自动恢复 `defer logger.End(ctx)`


#### Usage

- 配置项

  ```go
  type Config struct {
      Debug              bool    `yaml:"debug" mapstructure:"debug"`               // 调试模式，默认仅记录错误
      Output             bool    `yaml:"output" mapstructure:"output"`             // 日志打印方式。none不打印日志，console打印到控制台，file输出到文件。默认为console
      File               string  `yaml:"file" mapstructure:"file"`                 // 日志文件路径
      MaxSize            int     `yaml:"max_size" mapstructure:"max_size"`         // 单个日志文件的大小限制，单位MB
      MaxBackups         int     `yaml:"max_backups" mapstructure:"max_backups"`   // 日志文件数据的限制
      MaxAge             int     `yaml:"max_age" mapstructure:"max_age"`           // 日志文件的保存天数
      Compress           bool    `yaml:"compress" mapstructure:"compress"`         // 日志文件压缩开关
      Rotate             string  `yaml:"rotate" mapstructure:"rotate"`             // 日志切分的时间，参考linux定时任务0 0 0  * * *，精确到秒
      EnableTrace        bool    `yaml:"enable_trace" mapstructure:"enable_trace"` // 日志追踪开关
      TracerProviderType string  `yaml:"tracer_provider_type" mapstructure:"tracer_provider_type"`// 追踪内容导出类型，默认为jaeger
      TraceSampleRatio   float64 `yaml:"trace_sample_ratio" mapstructure:"trace_sample_ratio"` // 追踪采样的频率, 0.0-1
      JaegerServer       string  `yaml:"jaeger_server" mapstructure:"jaeger_server"`// jaeger的URI地址
      JaegerUsername     string  `yaml:"jaeger_username" mapstructure:"jaeger_username"`// jaeger用户名
      JaegerPassword     string  `yaml:"jaeger_password" mapstructure:"jaeger_password"`// jaeger密码
  }
  ```

#### 初始化

  ```go
  // 初始化,配置参考logger.Config
  // service.name为服务的名字
  // service.version为版本
  // logger.Init(config,attrs...logger.Field),更多的logger.Type参考logger下filed.go
  logger.Init(conf,logger.String("service.name","service1"),logger.String("service.version","version"))
  ```

#### 基础使用

  ```go
  // 在一个函数中启动一个span
  // 并注册一个延迟结束（！！切记，缺少可能会导致内存泄露）
  func foo(){
      // logger.Start(ctx,spanName,attrs...logger.Field)
      // 可以为一个span指定spanName以及额外的属性信息
      // attr支持logger.String("key","value") 形式,更多的logger.Type参考logger下filed.go
      ctx:=logger.Start(context,spanName,logger.String("key","value"))
      defer logger.End(ctx)
      // 正常记录日志
      // logger.Info(ctx,msg,attrs...logger.Field)
      // 记录msg信息及额外的信息
      // attr支持logger.String("key","value") 形式
      // 支持Debug,Info,Warn,Error,Fatal
      logger.Info(ctx,msg,logger.String("key","value"))
  }
  ```

#### 追踪传递，就是传递 traceID 和 spanID

  > gin 框架实例

  ```go
  // 请求方
  //
  // 请求方调用request时，注入context trace信息
  // post为封装的一个请求函数
  func post(ctx context.Context){
      …… // request的请求
      // 注入context追踪信息
      // request类型为*http.Request
      logger.HttpInject(ctx,request)
      …… // 发送请求
  }
  ```

#### 中间件解析追踪信息
  ```go
  // gin举例，初始化gin时，注册中间件
  router.Use(GinMiddleware("service"))
  ```
#### 控制器获取追踪信息
> 注意使用时，ctx要通过c.Request.Context()获取，不能用 *gin.Context(),因为gin.Context().Done()永远返回nil
  ```go
  // 使用
  func foo(c *gin.Context){
      ctx:=logger.Start(c.Request.Context(),spanName,logger.String("key","value"))
      defer logger.End(ctx)
      // 正常记录日志
      logger.Info(ctx,msg,logger.String("key","value"))
  }
  ```

#### 手动传递
  ```go
  // 对于不能通过函数或请求传递的，则需要手动传递
  // 通过 指定traceID和spanID生成一个context
  //
  // 然后，logger.Start(ctx,"spanName"),其生成的span就为childspan
  //
  // 其中traceID和spanID可以利用logger.GenTraceID()和logger.GenSpanID()生成
  // 也可以通过上个start返回的spanCtx中获得,logger.TraceID(spanCtx),logger.SpanID(spanCtx)
  ctx, err := NewRootContext(traceID, spanID)
  ```
