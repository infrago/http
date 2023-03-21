package http

import (
	"net/http"

	. "github.com/infrago/base"
)

type (
	// Driver 数据驱动
	Driver interface {
		Connect(config Config) (Connect, error)
	}

	// Connect 连接
	Connect interface {
		// Open 打开连接
		Open() error
		// Health 运行状态
		// 返回驱动的运行状态信息，用于监控
		Health() (Health, error)
		//Close 关闭连接
		Close() error

		// Accept 委托
		Accept(Delegate) error
		// Register 注册路由
		Register(name string, info Info) error

		// Start 启动HTTP
		Start() error
		// StartTLS 以TLS的方式启动HTTP
		StartTLS(certFile, keyFile string) error
	}

	Delegate interface {
		// Serve 响应请求
		Serve(name string, params Map, res http.ResponseWriter, req *http.Request)
	}

	Health struct {
		// Workload 当前负载数
		Workload int64
	}

	Info struct {
		// Method 请求的METHOD
		// GET, POST 这些
		Method string
		// Uri 请求的Uri
		Uri string
		// Route 路由名
		Route string
		// Site 对应的站点
		Site string
		// Hosts 绑定的域名
		Hosts []string

		// for url.Route
		socket bool
		args   Vars
	}
)
