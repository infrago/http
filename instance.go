package http

import (
	"net"
	"net/http"
	"os"
	"strings"

	. "github.com/infrago/base"
	"github.com/infrago/infra"
)

func (this *Instance) newContext() *Context {
	return &Context{
		inst: this, charset: infra.UTF8, uploadfiles: make([]string, 0),
		headers: make(map[string]string, 0), cookies: make(map[string]http.Cookie, 0),
		Params: Map{}, Query: Map{}, Form: Map{}, Upload: Map{},
		Value: Map{}, Args: Map{}, Locals: Map{}, Data: Map{}, Setting: Map{},
	}
}

// ctx 收尾工作
func (this *Instance) close(ctx *Context) {
	for _, file := range ctx.uploadfiles {
		os.Remove(file)
	}
}

// 收到消息
// 待优化，加入协程池，限制单个HTTP的并发
func (this *Instance) Serve(name string, params Map, res http.ResponseWriter, req *http.Request) {
	ctx := this.newContext()
	ctx.Metadata(infra.Metadata{Name: name, Payload: params})

	ctx.reader = req
	ctx.writer = res

	//名称和别名
	if info, ok := this.module.routerInfos[name]; ok {
		ctx.Name = info.Router
		ctx.Site = info.Site
		if cfg, ok := this.module.routers[ctx.Name]; ok {
			ctx.Config = cfg
			ctx.Setting = cfg.Setting
		}
		if cfg, ok := this.module.sites[ctx.Site]; ok {
			ctx.site = cfg
			ctx.charset = ctx.site.Charset
		}
	}

	ctx.Params = params

	ctx.Method = strings.ToUpper(ctx.reader.Method)
	ctx.Uri = ctx.reader.RequestURI
	ctx.Path = ctx.reader.URL.Path

	//去掉端口
	if strings.Contains(ctx.reader.Host, ":") {
		host, _, err := net.SplitHostPort(ctx.reader.Host)
		if err == nil {
			ctx.Host = host
		}
	} else {
		ctx.Host = ctx.reader.Host
	}

	// 获取根域名，如果IP直接访问，这里会有问题
	// 所以需要先判断，是不是直接IP访问，不是IP才解析根域
	ip := net.ParseIP(ctx.Host)
	if ip == nil {
		parts := strings.Split(ctx.Host, ".")
		if len(parts) >= 2 {
			l := len(parts)
			ctx.Domain = parts[l-2] + "." + parts[l-1]
		}
	}

	ctx.Url = httpUrl{ctx}

	//开始执行
	this.open(ctx)
	infra.CloseMeta(&ctx.Meta)
	this.close(ctx)
}
func (this *Instance) open(ctx *Context) {
	ctx.clear()

	//预处理
	ctx.next(this.preprocessing)

	//serve拦截器
	ctx.next(this.module.serveFilters[ctx.Site]...)
	ctx.next(this.serve)

	//开始执行
	ctx.Next()
}

func (this *Instance) serve(ctx *Context) {
	ctx.clear()

	//静态文件先处理
	ctx.next(this.finding) //静态文件在这处理

	//request拦截器
	ctx.next(this.module.requestFilters[ctx.Site]...)
	ctx.next(this.request)

	//开始执行
	ctx.Next()

	//在这里直接执行
	this.response(ctx)
}

// request 请求处理
func (this *Instance) request(ctx *Context) {
	//清理执行线
	ctx.clear()

	//request拦截器
	ctx.next(this.crossing)    //跨域处理
	ctx.next(this.validating)  //请求验证
	ctx.next(this.parsing)     //表单解析
	ctx.next(this.authorizing) //身份验证
	ctx.next(this.arguing)     //参数处理
	ctx.next(this.iteming)     //查找数据
	ctx.next(this.execute)

	//开始执行
	ctx.Next()
}

// execute 执行线
func (this *Instance) execute(ctx *Context) {
	//清理执行线
	ctx.clear()

	//execute拦截器
	ctx.next(this.module.executeFilters[ctx.Site]...)
	if ctx.Config.Actions != nil || len(ctx.Config.Actions) > 0 {
		ctx.next(ctx.Config.Actions...)
	}
	if ctx.Config.Action != nil {
		ctx.next(ctx.Config.Action)
	}

	//开始执行
	ctx.Next()
}

// response 响应线
func (this *Instance) response(ctx *Context) {
	ctx.clear() //清理

	//response拦截器
	ctx.next(this.module.responseFilters[ctx.Site]...)

	//开始执行
	ctx.Next()

	//这样保证body一定会执行，要不然response不next就没法弄了
	this.body(ctx)
}

func (this *Instance) found(ctx *Context) {
	ctx.clear()

	if ctx.Code <= 0 {
		ctx.Code = StatusNotFound
	}

	//把处理器加入调用列表
	if ctx.Config.Found != nil {
		ctx.next(ctx.Config.Found)
	}
	ctx.next(this.module.foundHandlers[ctx.Site]...)
	ctx.next(this.foundDefault)

	ctx.Next()
}
func (this *Instance) foundDefault(ctx *Context) {
	found := resFound
	if res := ctx.Result(); res.Fail() {
		found = res
	}

	ctx.Text(found, StatusNotFound)
}

func (this *Instance) error(ctx *Context) {
	ctx.clear()

	if ctx.Code <= 0 {
		ctx.Code = StatusInternalServerError
	}

	//把处理器加入调用列表
	if ctx.Config.Error != nil {
		ctx.next(ctx.Config.Error)
	}
	ctx.next(this.module.errorHandlers[ctx.Site]...)
	ctx.next(this.errorDefault)

	ctx.Next()
}
func (this *Instance) errorDefault(ctx *Context) {
	err := resError
	if res := ctx.Result(); res.Fail() {
		err = res
	}
	ctx.Text(err, StatusInternalServerError)
}

func (this *Instance) failed(ctx *Context) {
	ctx.clear()

	if ctx.Code <= 0 {
		ctx.Code = StatusBadRequest
	}

	//把处理器加入调用列表
	if ctx.Config.Failed != nil {
		ctx.next(ctx.Config.Failed)
	}
	ctx.next(this.module.failedHandlers[ctx.Site]...)
	ctx.next(this.failedDefault)

	ctx.Next()
}
func (this *Instance) failedDefault(ctx *Context) {
	failed := resFailed
	if res := ctx.Result(); res.Fail() {
		failed = res
	}
	ctx.Text(failed, StatusBadRequest)
}

func (this *Instance) denied(ctx *Context) {
	ctx.clear()

	if ctx.Code <= 0 {
		ctx.Code = StatusUnauthorized
	}

	//把处理器加入调用列表
	if ctx.Config.Denied != nil {
		ctx.next(ctx.Config.Denied)
	}
	ctx.next(this.module.deniedHandlers[ctx.Site]...)
	ctx.next(this.deniedDefault)

	ctx.Next()
}

func (this *Instance) deniedDefault(ctx *Context) {
	denied := resDenied
	if res := ctx.Result(); res.Fail() {
		denied = res
	}
	ctx.Text(denied, StatusUnauthorized)
}
