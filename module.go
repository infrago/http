package http

import (
	"sync"
	"time"

	. "github.com/infrago/base"
	"github.com/infrago/infra"
)

func init() {
	infra.Mount(module)
}

var (
	module = &Module{
		config: Config{
			Driver: infra.DEFAULT, Charset: infra.UTF8,
		},
		cross: Cross{
			Allow: true,
		},

		sites: make(map[string]Site),

		drivers: make(map[string]Driver, 0),

		routers:  make(map[string]Router, 0),
		filters:  make(map[string]Filter, 0),
		handlers: make(map[string]Handler, 0),
		helpers:  make(map[string]Helper, 0),

		hosts: make(map[string]string, 0),

		url: &httpUrl{},
	}
)

type (
	Module struct {
		mutex    sync.Mutex
		instance Instance
		url      *httpUrl

		connected, initialized, launched bool

		drivers map[string]Driver

		routers  map[string]Router
		filters  map[string]Filter
		handlers map[string]Handler
		helpers  map[string]Helper

		routerInfos map[string]Info

		serveFilters    map[string][]ctxFunc
		requestFilters  map[string][]ctxFunc
		executeFilters  map[string][]ctxFunc
		responseFilters map[string][]ctxFunc

		foundHandlers  map[string][]ctxFunc
		errorHandlers  map[string][]ctxFunc
		failedHandlers map[string][]ctxFunc
		deniedHandlers map[string][]ctxFunc

		helperActions Map

		config Config
		cross  Cross

		sites map[string]Site
		hosts map[string]string
	}

	Config struct {
		// Driver 驱动
		Driver string
		// Port 监听端口
		Port int

		// Host 绑定的IP，默认绑定所有IP
		Host string

		// CertFile SSL证书cert文件
		CertFile string
		// Key SSL证书key文件
		KeyFile string

		// Domain 主域，不是子域名，如 infrago.org
		Domain string

		// Charset 默认字符集
		// 默认值 utf-8
		Charset string

		// Cookie 默认cookie名称
		// 用于token或sessionid的浏览器cookie名
		// 如果不为空，则表示，token写入cookie
		Cookie string

		// Token 是否自动生成TOKEN
		// 当cookie不为空，且token=true的时候，会自动生成空token
		Token bool
		// Expiry 下发token的有效期，
		// 默认使用token本身的有效期设置
		Expiry time.Duration

		// Crypto 表示cookie是否加密
		Crypto bool
		// MaxAge cookie的超时时间
		// 0  表示不过时
		MaxAge time.Duration
		// HttpOnly COOKIE设置是否httponly
		HttpOnly bool

		// Upload 上传文件临时目录
		// 默认 os.TempDir()
		Upload string
		// Static 静态文件目录
		// 默认 asset/statics
		Static string
		// Shared 默认共享目录
		// 静态文件搜索的共享目录名
		// 默认值 shared
		Shared string

		// Defaults 默认文件名
		// 当访问静态文件时，如果目录的是目录，默认搜索的文件名
		// 默认 index.html default.html
		Defaults []string

		// Validate 请求验证是否开启
		// 开启的话，所有接口请求要验证后才能正常请求
		Validate string
		// Format 请求验证时候的内容格式
		Format string
		// Timeout 请求超时
		Timeout time.Duration

		// Confuse api输出时候内容混淆
		// 使用Codec定义，比如，text, string, rsa, aes 啥的
		// 留空表示不混淆
		Confuse string

		// Setting 设置
		Setting Map
	}

	Sites map[string]Site
	Site  struct {
		// Name 名称
		Name string

		// Ssl 是否开启SSL
		Ssl bool

		// Domain 主域
		// 为空则从 http.Config 中继承
		Domain string

		// Hosts 绑定的域名列表
		// 如果为空，为自动设置为当前站点的 key + Domain
		// 如果Hosts中带主域名，比如，只设置为 ["aaa", "bbb"]
		// 系统会自动将 aaa,bbb 加上 主域名，如 aaa.infrago.org
		Hosts []string

		// Charset 字符集
		// 为空则从 http.Config 中继承，默认 utf-8
		Charset string

		// Cookie 默认cookie名称
		// 用于token或sessionid的浏览器cookie名
		Cookie string

		// Token 是否自动生成
		Token bool
		// Expiry 下发token的有效期，
		// 默认使用token本身的有效期设置
		Expiry time.Duration

		// Crypto 表示cookie是否加密
		Crypto bool
		// MaxAge cookie的超时时间
		// 0  表示不过时
		MaxAge time.Duration
		// HttpOnly COOKIE设置是否httponly
		HttpOnly bool

		// Validate 请求验证是否开启
		// 开启的话，所有接口请求要验证后才能正常请求
		Validate string
		// Format 请求验证时候的内容格式
		Format string
		// Timeout 请求超时
		Timeout time.Duration

		// Confuse api输出时候内容混淆
		// 使用Codec定义，比如，text, string, rsa, aes 啥的
		// 留空表示不混淆
		Confuse string

		// Setting 设置
		Setting Map
	}

	Cross struct {
		Allow   bool
		Method  string
		Methods []string
		Origin  string
		Origins []string
		Header  string
		Headers []string
	}

	Instance struct {
		module  *Module
		config  Config
		connect Connect
	}
)

// Driver 注册驱动
func (module *Module) Driver(name string, driver Driver) {
	module.mutex.Lock()
	defer module.mutex.Unlock()

	if driver == nil {
		panic("Invalid http driver: " + name)
	}

	if infra.Override() {
		module.drivers[name] = driver
	} else {
		if module.drivers[name] == nil {
			module.drivers[name] = driver
		}
	}
}

func (this *Module) Config(name string, config Config) {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	this.config = config
}

func (this *Module) Site(name string, site Site) {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	if name == "" {
		name = infra.DEFAULT
	}

	if infra.Override() {
		this.sites[name] = site
	} else {
		if _, ok := this.sites[name]; ok == false {
			this.sites[name] = site
		}
	}
}
func (this *Module) Sites(name string, site Sites) {
	for key, val := range site {
		this.Site(key, val)
	}
}
