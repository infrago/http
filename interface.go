package http

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	. "github.com/infrago/base"
	"github.com/infrago/infra"
	"github.com/infrago/util"
)

func (this *Module) Register(name string, value Any) {
	switch config := value.(type) {
	case Driver:
		this.Driver(name, config)
	case Config:
		this.Config(name, config)
	case Site:
		this.Site(name, config)
	case Sites:
		this.Sites(name, config)
	case Route:
		this.Route(name, config)
	case Filter:
		this.Filter(name, config)
	case Handler:
		this.Handler(name, config)
	}
}

// configure sites config
func (this *Module) httpConfigure(config Map) {

	// 驱动
	if vv, ok := config["driver"].(string); ok {
		this.config.Driver = vv
	}
	// 端口
	if vv, ok := config["port"].(int); ok {
		this.config.Port = vv
	}
	if vv, ok := config["port"].(int64); ok {
		this.config.Port = int(vv)
	}
	if vv, ok := config["host"].(string); ok {
		this.config.Host = vv
	}
	if vv, ok := config["bind"].(string); ok {
		this.config.Host = vv
	}

	if vv, ok := config["domain"].(string); ok {
		this.config.Domain = vv
	}
	if vv, ok := config["keyfile"].(string); ok {
		this.config.KeyFile = vv
	}
	if vv, ok := config["certfile"].(string); ok {
		this.config.CertFile = vv
	}

	// charset
	if vv, ok := config["charset"].(string); ok {
		this.config.Charset = vv
	}

	// Token
	if vv, ok := config["token"].(bool); ok {
		this.config.Token = vv
	}
	if vv, ok := config["token"].(string); ok && (vv == "true" || vv == "t" || vv == "1") {
		this.config.Token = true
	}

	//Expiry
	expiry := util.ParseDurationConfig(config, "expiry")
	if expiry != util.NoDuration {
		this.config.Expiry = expiry
	}
	expires := util.ParseDurationConfig(config, "expires")
	if expires != util.NoDuration {
		this.config.Expiry = expires
	}

	// cookie
	if vv, ok := config["cookie"].(string); ok {
		this.config.Cookie = vv
	}
	// Crypto
	if vv, ok := config["crypto"].(bool); ok {
		this.config.Crypto = vv
	}
	if vv, ok := config["crypto"].(string); ok && (vv == "true" || vv == "t" || vv == "1") {
		this.config.Crypto = true
	}

	//MaxAge
	maxage := util.ParseDurationConfig(config, "maxage")
	if maxage != util.NoDuration {
		this.config.MaxAge = maxage
	}

	// httponly
	if vv, ok := config["httponly"].(bool); ok {
		this.config.HttpOnly = vv
	}

	// upload
	if vv, ok := config["upload"].(string); ok {
		this.config.Upload = vv
	}

	// static
	if vv, ok := config["static"].(string); ok {
		this.config.Static = vv
	}

	// shared
	if vv, ok := config["shared"].(string); ok {
		this.config.Shared = vv
	}

	// defaults
	if vvs, ok := config["default"].(string); ok {
		this.config.Defaults = []string{vvs}
	}
	if vvs, ok := config["defaults"].([]string); ok {
		this.config.Defaults = vvs
	}

	//validate 请求验证
	if vv, ok := config["validate"].(string); ok {
		this.config.Validate = vv
	}
	if vv, ok := config["format"].(string); ok {
		this.config.Format = vv
	}
	// Confuse 响应混淆
	if vv, ok := config["confuse"].(string); ok {
		this.config.Confuse = vv
	}
	//MaxAge
	timeout := util.ParseDurationConfig(config, "timeout")
	if timeout != util.NoDuration {
		this.config.Timeout = timeout
	}

	//setting
	if vv, ok := config["setting"].(Map); ok {
		this.config.Setting = vv
	}

	// 如果http下面，有 cross配置
	if vvs, ok := config["cross"].(Map); ok {
		this.crossConfigure(vvs)
	}
	if vvs, ok := config["site"].(Map); ok {
		this.sitesConfigure(vvs)
	}
	if vvs, ok := config["sites"].(Map); ok {
		this.sitesConfigure(vvs)
	}

}

// configure cross config
func (this *Module) crossConfigure(config Map) {
	if vv, ok := config["allow"].(bool); ok {
		this.cross.Allow = vv
	}

	if vv, ok := config["method"].(string); ok {
		this.cross.Method = vv
	}
	if vvs, ok := config["methods"].([]string); ok {
		this.cross.Methods = vvs
	}

	if vv, ok := config["origin"].(string); ok {
		this.cross.Origin = vv
	}
	if vvs, ok := config["origins"].([]string); ok {
		this.cross.Origins = vvs
	}

	if vv, ok := config["header"].(string); ok {
		this.cross.Header = vv
	}
	if vvs, ok := config["headers"].([]string); ok {
		this.cross.Headers = vvs
	}
}

func (this *Module) siteConfigure(name string, config Map) {
	site := Site{Name: name, HttpOnly: this.config.HttpOnly}
	if vv, ok := this.sites[name]; ok {
		site = vv //如果已经存在了，用现成的改写
	}

	// 是否开启ssl
	if vv, ok := config["ssl"].(bool); ok {
		site.Ssl = vv
	}

	if vv, ok := config["host"].(string); ok {
		site.Hosts = append(site.Hosts, vv)
	}
	if vvs, ok := config["host"].([]string); ok {
		site.Hosts = append(site.Hosts, vvs...)
	}
	if vvs, ok := config["hosts"].([]string); ok {
		site.Hosts = append(site.Hosts, vvs...)
	}

	if vv, ok := config["domain"].(string); ok {
		site.Domain = vv
	}

	// charset
	if vv, ok := config["charset"].(string); ok {
		site.Charset = vv
	}

	// Token
	if vv, ok := config["token"].(bool); ok {
		site.Token = vv
	} else if vv, ok := config["token"].(string); ok && (vv == "true" || vv == "t" || vv == "1") {
		site.Token = true
	} else {
		site.Token = this.config.Token
	}

	//Expiry
	expiry := util.ParseDurationConfig(config, "expiry")
	if expiry != util.NoDuration {
		site.Expiry = expiry
	}
	// cookie
	if vv, ok := config["cookie"].(string); ok {
		site.Cookie = vv
	}
	// Crypto
	if vv, ok := config["crypto"].(bool); ok {
		site.Crypto = vv
	}
	if vv, ok := config["crypto"].(string); ok && (vv == "true" || vv == "t" || vv == "1") {
		site.Crypto = true
	}
	//MaxAge
	maxage := util.ParseDurationConfig(config, "maxage")
	if maxage != util.NoDuration {
		site.MaxAge = maxage
	}
	// httponly
	if vv, ok := config["httponly"].(bool); ok {
		site.HttpOnly = vv
	}

	//validate 请求验证
	if vv, ok := config["validate"].(string); ok {
		site.Validate = vv
	}
	if vv, ok := config["format"].(string); ok {
		site.Format = vv
	}
	// Confuse 响应混淆
	if vv, ok := config["confuse"].(string); ok {
		site.Confuse = vv
	}
	timeout := util.ParseDurationConfig(config, "timeout")
	if maxage != util.NoDuration {
		site.Timeout = timeout
	}

	if setting, ok := config["setting"].(Map); ok {
		site.Setting = setting
	}

	//保存配置
	this.sites[name] = site
}

func (this *Module) sitesConfigure(config Map) {
	root := Map{}
	for key, val := range config {
		if conf, ok := val.(Map); ok {
			this.siteConfigure(key, conf)
		} else {
			//记录上一层的配置，如果有的话
			root[key] = val
		}
	}

	if len(root) > 0 {
		this.siteConfigure(WWW, root)
	}

}

func (this *Module) Configure(global Map) {
	if vvv, ok := global["http"].(Map); ok {
		this.httpConfigure(vvv)
	}
	if vvv, ok := global["cross"].(Map); ok {
		this.crossConfigure(vvv)
	}
	if vvs, ok := global["site"].(Map); ok {
		this.sitesConfigure(vvs)
	}
	if vvs, ok := global["sites"].(Map); ok {
		this.sitesConfigure(vvs)
	}
}
func (this *Module) routeInitialize(orgKey, siteName, siteKey string, route Route) {
	hosts := make([]string, 0)
	if site, ok := this.sites[siteName]; ok {
		hosts = append(hosts, site.Hosts...)
	}

	for i, uri := range route.Uris {
		// infoKey := fmt.Sprintf("%s.%s.%d", siteName, siteKey, i)
		infoKey := fmt.Sprintf("%s.%d", siteKey, i)
		if siteName == "" {
			infoKey = fmt.Sprintf("%s.%d", siteKey, i)
		}
		this.routeInfos[infoKey] = Info{
			route.Method, uri, orgKey, siteName, hosts, route.Socket, route.Args,
		}
	}
}

func (this *Module) filterInitialize(site string, filter Filter) {
	if this.serveFilters[site] == nil {
		this.serveFilters[site] = make([]ctxFunc, 0)
	}
	if this.requestFilters[site] == nil {
		this.requestFilters[site] = make([]ctxFunc, 0)
	}
	if this.executeFilters[site] == nil {
		this.executeFilters[site] = make([]ctxFunc, 0)
	}
	if this.responseFilters[site] == nil {
		this.responseFilters[site] = make([]ctxFunc, 0)
	}

	if filter.Serve != nil {
		this.serveFilters[site] = append(this.serveFilters[site], filter.Serve)
	}
	if filter.Request != nil {
		this.requestFilters[site] = append(this.requestFilters[site], filter.Request)
	}
	if filter.Execute != nil {
		this.executeFilters[site] = append(this.executeFilters[site], filter.Execute)
	}
	if filter.Response != nil {
		this.responseFilters[site] = append(this.responseFilters[site], filter.Response)
	}
}

func (this *Module) handlerInitialize(site string, handler Handler) {
	if this.foundHandlers[site] == nil {
		this.foundHandlers[site] = make([]ctxFunc, 0)
	}
	if this.errorHandlers[site] == nil {
		this.errorHandlers[site] = make([]ctxFunc, 0)
	}
	if this.failedHandlers[site] == nil {
		this.failedHandlers[site] = make([]ctxFunc, 0)
	}
	if this.deniedHandlers[site] == nil {
		this.deniedHandlers[site] = make([]ctxFunc, 0)
	}

	if handler.Found != nil {
		this.foundHandlers[site] = append(this.foundHandlers[site], handler.Found)
	}
	if handler.Error != nil {
		this.errorHandlers[site] = append(this.errorHandlers[site], handler.Error)
	}
	if handler.Failed != nil {
		this.failedHandlers[site] = append(this.failedHandlers[site], handler.Failed)
	}
	if handler.Denied != nil {
		this.deniedHandlers[site] = append(this.deniedHandlers[site], handler.Denied)
	}
}

func (this *Module) Initialize() {
	if this.initialized {
		return
	}

	//默认配置
	if this.config.Port <= 0 || this.config.Port > 65535 {
		this.config.Port = 0 //默认为0，就不开HTTP
		// if this.config.CertFile != "" && this.config.KeyFile != "" {
		// 	this.config.Port = 8443
		// } else {
		// 	this.config.Port = 8754
		// }
	}

	if this.config.Charset == "" {
		this.config.Charset = infra.UTF8
	}

	// 不自动设置，因为
	// 如果不为空，则token写入cookie
	// if this.config.Cookie == "" {
	// 	this.config.Cookie = "token"
	// }

	//cookie 暂时不处理，待优化
	if this.config.Upload == "" {
		this.config.Upload = os.TempDir()
	}
	if this.config.Static == "" {
		this.config.Static = "asset/statics"
	}
	if this.config.Shared == "" {
		this.config.Shared = "shared"
	}
	if this.config.Defaults == nil || len(this.config.Defaults) == 0 {
		this.config.Defaults = []string{
			"index.html", "default.html", "index.htm", "default.html",
		}
	}

	// 过期时间，和，MaxAge 默认30天，小于0，才表示随浏览器
	if this.config.Expiry == 0 {
		this.config.Expiry = time.Hour * 24 * 30
	} else if this.config.Expiry < 0 {
		this.config.Expiry = 0
	}
	if this.config.MaxAge == 0 {
		this.config.MaxAge = time.Hour * 24 * 30
	} else if this.config.MaxAge < 0 {
		this.config.MaxAge = 0
	}

	if this.config.Format == "" {
		this.config.Format = `device|system|version|client|release|timestamp|path`
	}

	// sites 列表为下面的整理准备
	// 自带空站点，要不然空站点的拦截器，处理器，会无效
	sites := []string{""}

	//这个域名列表清空，保存所有域名集合
	this.hosts = make(map[string]string, 0)
	for key, site := range this.sites {
		if site.Charset == "" {
			site.Charset = this.config.Charset
		}
		if site.Domain == "" {
			site.Domain = this.config.Domain
		}

		if site.Cookie == "" {
			site.Cookie = this.config.Cookie
		}

		if site.Expiry == 0 {
			site.Expiry = this.config.Expiry
		}
		if site.MaxAge <= 0 {
			site.MaxAge = this.config.MaxAge
		}

		if site.Validate == "" {
			site.Validate = this.config.Validate
		}
		if site.Timeout <= 0 {
			site.Timeout = this.config.Timeout
		}
		if site.Format == "" {
			site.Format = this.config.Format
		}
		if site.Confuse == "" {
			site.Confuse = this.config.Confuse
		}

		if site.Hosts == nil {
			site.Hosts = make([]string, 0)
		}

		//如果没有域名，把站点的key加上，做为子域名
		if len(site.Hosts) == 0 {
			site.Hosts = append(site.Hosts, key)
		}

		//加上主域名
		for i, host := range site.Hosts {
			if strings.HasSuffix(host, site.Domain) == false {
				site.Hosts[i] = host + "." + site.Domain
			}
		}

		//记录http的所有域名
		for _, host := range site.Hosts {
			this.hosts[host] = key
		}

		this.sites[key] = site

		//为下面的整理做准备
		sites = append(sites, key)
	}

	//空站点
	if _, ok := this.sites[""]; ok == false {
		this.sites[""] = Site{
			Name: "空站点", Charset: this.config.Charset,
			Token: this.config.Token, Expiry: this.config.Expiry,
			Cookie: this.config.Cookie, Crypto: this.config.Crypto,
			MaxAge: this.config.MaxAge, HttpOnly: this.config.HttpOnly,
		}
	}

	// 处理 RouteInfos

	// 整理route, filter, handler
	// 加上站点前缀，主要是处理 *
	this.routeInfos = make(map[string]Info, 0)
	for key, route := range this.routes {
		if strings.HasPrefix(key, "*.") {
			for _, site := range sites {
				siteKey := strings.Replace(key, "*.", site+".", 1)
				if _, ok := this.routes[siteKey]; ok == false {
					this.routeInitialize(key, site, siteKey, route)
				}
			}
		} else {
			//设置站点，以前空站点处理
			names := strings.Split(key, ".")
			if len(names) > 0 {
				siteKey := key
				this.routeInitialize(key, names[0], siteKey, route)
			} else {
				siteKey := "." + key
				this.routeInitialize(key, "", siteKey, route)
			}
		}
	}

	this.serveFilters = make(map[string][]ctxFunc, 0)
	this.requestFilters = make(map[string][]ctxFunc, 0)
	this.executeFilters = make(map[string][]ctxFunc, 0)
	this.responseFilters = make(map[string][]ctxFunc, 0)
	for key, filter := range this.filters {
		if strings.HasPrefix(key, "*.") {
			for _, site := range sites {
				siteKey := strings.Replace(key, "*.", site+".", 1)
				if _, ok := this.filters[siteKey]; ok == false {
					this.filterInitialize(site, filter)
				}
			}
		} else {
			//设置站点，以前空站点处理
			names := strings.Split(key, ".")
			if len(names) > 0 {
				this.filterInitialize(names[0], filter)
			} else {
				this.filterInitialize("", filter)
			}
		}
	}

	this.foundHandlers = make(map[string][]ctxFunc, 0)
	this.errorHandlers = make(map[string][]ctxFunc, 0)
	this.failedHandlers = make(map[string][]ctxFunc, 0)
	this.deniedHandlers = make(map[string][]ctxFunc, 0)
	for key, handler := range this.handlers {
		if strings.HasPrefix(key, "*.") {
			for _, site := range sites {
				siteKey := strings.Replace(key, "*.", site+".", 1)
				if _, ok := this.handlers[siteKey]; ok == false {
					this.handlerInitialize(site, handler)
				}
			}
		} else {
			//设置站点，以前空站点处理
			names := strings.Split(key, ".")
			if len(names) > 0 {
				this.handlerInitialize(names[0], handler)
			} else {
				this.handlerInitialize("", handler)
			}
		}
	}

	this.helperActions = Map{}
	for key, helper := range this.helpers {
		if helper.Action != nil {
			this.helperActions[key] = helper.Action
		}
	}

	this.initialized = true
}
func (this *Module) Connect() {
	if this.connected {
		return
	}

	driver, ok := this.drivers[this.config.Driver]
	if ok == false {
		panic("Invalid http driver: " + this.config.Driver)
	}

	// 建立连接
	connect, err := driver.Connect(this.config)
	if err != nil {
		panic("Failed to connect to http: " + err.Error())
	}

	// 打开连接
	err = connect.Open()
	if err != nil {
		panic("Failed to open http connect: " + err.Error())
	}

	//待处理，config不用复制
	inst := Instance{
		this, this.config, connect,
	}

	// 指定委托
	connect.Accept(&inst)

	//注册HTTP
	for name, info := range this.routeInfos {
		if info.Site != "" && len(info.Hosts) > 0 {
			// 站点的hosts必须大于0，因为有可能定义了路由
			// 但是没有配置站点，这时候就匹配不到域名
			// 空域名有可能会接管同一uri的所有请求
			if err := connect.Register(name, info); err != nil {
				panic("Failed to register http: " + err.Error())
			}
		}
	}
	// 分开注册，把空站点的路由后注册
	// 要不然，当有相同的uri匹配的时候，如果空站先被注册（由于map的key是顺序的）
	// 就会先匹配路由，导致正常站点uri无法被匹配到
	for name, info := range this.routeInfos {
		if info.Site == "" {
			if err := connect.Register(name, info); err != nil {
				panic("Failed to register http: " + err.Error())
			}
		}
	}

	//注册站点级所有请求，来接404
	for name, site := range this.sites {
		if name == "" {
			continue //空站点跳过
		}
		info := Info{}
		info.Site = name
		info.Hosts = site.Hosts
		info.Uri = "/{uri:.*}"

		if err := connect.Register(name, info); err != nil {
			panic("Failed to register http: " + err.Error())
		}

		this.routeInfos[name] = info
	}

	//保存实例
	this.instance = inst

	this.connected = true
}
func (this *Module) Launch() {
	if this.launched {
		return
	}

	// 没设置端口，就不开HTTP服务
	if this.config.Port > 0 && this.config.Port < 65535 {
		var err error
		if this.config.CertFile != "" && this.config.KeyFile != "" {
			err = this.instance.connect.StartTLS(this.config.CertFile, this.config.KeyFile)
		} else {
			err = this.instance.connect.Start()
		}
		if err != nil {
			panic("Failed to start http: " + err.Error())
		}
		log.Println(fmt.Sprintf("infra.Go HTTP is running at %d", this.config.Port))
	}

	this.launched = true
}
func (this *Module) Terminate() {
	this.instance.connect.Close()

	this.launched = false
	this.connected = false
	this.initialized = false
}
