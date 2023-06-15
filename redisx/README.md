
# rdbcli

封装了 go-redis，支持单机和集群

配置

```go
type Config struct {
    // 是否为集群模式
    Cluster  bool   `mapstructure:"cluster" `
    // 主机
    Host     string `mapstructure:"host" `
    // 端口
    Port     string `mapstructure:"port" `
    // 密码
    Password string `mapstructure:"password"`
    // 连接协议
    Protocol string `mapstructure:"protocol"`
    // 初始连接的数据库
    Database int    `mapstructure:"database"`
    // 最小空闲连接
    MinIdleConns int `mapstructure:"min_idle_conns"`
    // 空闲时间
    IdleTimeout int `mapstructure:"idle_timeout"`
    // 连接池大小
    PoolSize int `mapstructure:"pool_size"`
    // 连接最大可用时间
    MaxConnAge int `mapstructure:"max_conn_age"`
}
```

#### 使用


#### 例子
> 特别注意事项
redisx与gin配置使用时，context不要使用 c(*gin.Context),而应该使用c.Request.Context()
因为传入的context用来判断超时用，即会读取context.Done(),而gin.Context.Done()永远返回nil
```
	// 实例变量
	var cli redisx.Client
	// 配置
	config := redisx.Config{
		Host:     "172.16.1.207",
		Port:     "16380",
		Protocol: "tcp",
	}
	// 新建实例
	cli = redisx.New(config)

	// 命令测试
	// SetEx
	{
		fmt.Println("----Set----")
		r, err := cli.SetEX(context.Background(), "key", "123", time.Second*10).Result()
		fmt.Println("result", r)
		fmt.Println("err", err)
	}

	// Get
	{
		fmt.Println("----Get----")
		r, err := cli.Get(context.Background(), "key").Result()
		fmt.Println("result", r)
		fmt.Println("err", err)
	}

	// Ping
	{
		fmt.Println("----Ping----")
		r, err := cli.Ping(context.Background()).Result()
		fmt.Println(r, err)
	}

	// HSet
	{
		fmt.Println("----HSet----")
		r, err := cli.HSet(context.Background(), "hset-key", "field", "1").Result()
		fmt.Println("result:", r)
		fmt.Println("err:", err)
	}

	// HGet
	{
		fmt.Println("----HGet----")
		r, err := cli.HGet(context.Background(), "hset-key", "field").Result()
		fmt.Println("result:", r)
		fmt.Println("err:", err)
	}

参考 redix_test.go，详细请查看 github: https://github.com/go-redis/redis
