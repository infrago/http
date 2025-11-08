package http

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	. "github.com/infrago/base"
	"github.com/infrago/infra"
	"github.com/infrago/util"
)

type (
	Context struct {
		inst *Instance
		infra.Meta
		issue bool

		uploadfiles []string

		index int       //下一个索引
		nexts []ctxFunc //方法列表

		reader *http.Request
		writer http.ResponseWriter

		// 以下几个字段必须独立
		// 要不然，Invoke的时候，会被修改掉
		Name    string
		Config  Router
		Setting Map

		Site string
		site Site

		charset string
		headers map[string]string
		cookies map[string]http.Cookie

		Method    string
		Host      string
		Domain    string
		Subdomain string
		Path      string
		Uri       string

		Ajax bool

		Params Map
		Query  Map
		Form   Map
		Upload Map

		Value  Map
		Args   Map
		Locals Map

		Code int
		Type string
		Data Map
		Body Any

		Url httpUrl
	}
	ctxFunc func(*Context)

	//重试
	retryBody = struct{}
)

func (ctx *Context) clear() {
	ctx.index = 0
	ctx.nexts = make([]ctxFunc, 0)
}
func (ctx *Context) next(nexts ...ctxFunc) {
	ctx.nexts = append(ctx.nexts, nexts...)
}

func (ctx *Context) Next() {
	if len(ctx.nexts) > ctx.index {
		next := ctx.nexts[ctx.index]
		ctx.index++
		if next != nil {
			next(ctx)
		} else {
			ctx.Next()
		}
	}
}

func (ctx *Context) Found() {
	ctx.inst.found(ctx)
}
func (ctx *Context) Error(res Res) {
	ctx.Result(res)
	ctx.inst.error(ctx)
}
func (ctx *Context) Failed(res Res) {
	ctx.Result(res)
	ctx.inst.failed(ctx)
}
func (ctx *Context) Denied(res Res) {
	ctx.Result(res)
	ctx.inst.denied(ctx)
}

// Sign 不会生成新的ID
func (ctx *Context) Sign(auth bool, payload Map, expires time.Duration, roles ...string) string {
	//加入HTTP的默认过期时间
	if ctx.site.Expire > 0 && expires < 0 {
		expires = ctx.site.Expire
	}
	token := ctx.Meta.Sign(auth, payload, expires, roles...)
	// 如果 cookie 配置不为空，则将token写入cookie
	ctx.issue = ctx.site.Cookie != ""
	return token
}

// NewSign 会生成新的ID
func (ctx *Context) NewSign(auth bool, payload Map, expires time.Duration, roles ...string) string {
	//加入HTTP的默认过期时间
	if ctx.site.Expire > 0 && expires < 0 {
		expires = ctx.site.Expire
	}
	token := ctx.Meta.NewSign(auth, payload, expires, roles...)
	// 如果 cookie 配置不为空，则将token写入cookie
	ctx.issue = ctx.site.Cookie != ""
	return token
}

func (ctx *Context) Charset(charsets ...string) string {
	if ctx == nil {
		return infra.UTF8
	}
	if len(charsets) > 0 && charsets[0] != "" {
		ctx.charset = charsets[0]
	}

	if ctx.charset == "" {
		ctx.charset = infra.UTF8
	}

	return ctx.charset
}
func (ctx *Context) Header(key string, vals ...string) string {
	if len(vals) > 0 {
		ctx.headers[key] = vals[0]
		return vals[0]
	} else {
		//读header
		return ctx.reader.Header.Get(key)
	}
}
func (ctx *Context) Cookie(key string, vals ...Any) string {
	if len(vals) > 0 {
		// response 的时候统一加密
		vvv := vals[0]
		if vvv == nil {
			// 此处为删除Cookie
			cookie := http.Cookie{Name: key, HttpOnly: true}
			cookie.MaxAge = -1
			ctx.cookies[key] = cookie
			return ""
		} else {
			switch val := vvv.(type) {
			case http.Cookie:
				ctx.cookies[key] = val
			case string:
				cookie := http.Cookie{Name: key, Value: val}
				ctx.cookies[key] = cookie
			default:
				return ""
			}
		}
	} else {
		//读cookie
		c, e := ctx.reader.Cookie(key)
		if e == nil {
			//这里是直接读的，所以要解密
			if ctx.site.Crypto {
				if vvv, err := infra.DecryptTEXT(c.Value); err == nil {
					return fmt.Sprintf("%v", vvv)
				}
			}
			return c.Value
		}
	}
	return ""
}

func (ctx *Context) uploadFile(patterns ...string) (*os.File, error) {

	if dir := module.config.Upload; dir != "" {
		pattern := ""
		if len(patterns) > 0 {
			pattern = patterns[0]
		}

		file, err := ioutil.TempFile(dir, pattern)
		ctx.uploadfiles = append(ctx.uploadfiles, file.Name())

		return file, err
	}

	return ctx.TempFile(patterns...)
}

//通用方法

// User-Agent
func (ctx *Context) Agent() string {
	return ctx.Header("User-Agent")
}
func (ctx *Context) UserAgent() string {
	return ctx.Header("User-Agent")
}

func (ctx *Context) Ip() string {
	return ctx.IP()
}
func (ctx *Context) IP() string {
	ip := "127.0.0.1"

	if forwarded := ctx.reader.Header.Get("x-forwarded-for"); forwarded != "" {
		ip = forwarded
	} else if realIp := ctx.reader.Header.Get("X-Real-IP"); realIp != "" {
		ip = realIp
	} else {
		ip = ctx.reader.RemoteAddr
	}

	newip, _, err := net.SplitHostPort(ip)
	if err == nil {
		ip = newip
	}

	//处理ip，可能有多个
	ips := strings.Split(ip, ", ")
	if len(ips) > 0 {
		return ips[len(ips)-1]
	}
	return ip
}

// clearBody 在设置新的body前，需要统一做些清理的工作
// 比如，httpBufferBody，因为上游不会再buffer.Close，因为要等HTTP响应后才Close
// 所以，在设置新的body前做些清理工作，以防内存泄漏
// 当然，还有个问题， 就是， ctx.Body 现在是开放的，
// 如果在外部被修改，就没办法处理，所以要考虑一下，Body转为非公开变量
// 这样些失去一些灵活性，但是安全保险，而且，可以用对应的方法，照顾Body的灵活性
// 待优化
func (ctx *Context) clearBody() {
	if vv, ok := ctx.Body.(httpBufferBody); ok {
		vv.buffer.Close()
	}
}
func (ctx *Context) codingTyping(def string, args ...Any) {
	code := 0
	tttt := ""
	for _, arg := range args {
		if vv, ok := arg.(int); ok {
			code = vv
		}
		if vv, ok := arg.(string); ok {
			tttt = vv
		}
	}
	if code > 0 {
		ctx.Code = code
	}
	if ctx.Type == "" {
		if tttt != "" {
			ctx.Type = tttt
		} else {
			ctx.Type = def
		}
	} else {
		if tttt != "" {
			ctx.Type = tttt
		}
	}
}

func (ctx *Context) Goto(url string) {
	ctx.clearBody()

	ctx.Body = httpGotoBody{url}
}

func (ctx *Context) Redirect(url string) {
	ctx.Goto(url)
}
func (ctx *Context) Route(name string, values ...Map) {
	url := ctx.Url.Route(name, values...)
	ctx.Redirect(url)
}

func (ctx *Context) Text(text Any, args ...Any) {
	ctx.clearBody()
	ctx.codingTyping("text", args...)

	real := ""
	if res, ok := text.(Res); ok {
		real = ctx.String(res.State(), res.Args()...)
	} else if vv, ok := text.(string); ok {
		real = vv
	} else {
		real = fmt.Sprintf("%v", text)
	}

	ctx.Body = httpTextBody{real}
}

func (ctx *Context) Html(html Any, args ...Any) {
	ctx.HTML(html, args...)
}
func (ctx *Context) HTML(html Any, args ...Any) {
	ctx.clearBody()
	ctx.codingTyping("html", args...)

	if vv, ok := html.(string); ok {
		ctx.Body = httpHtmlBody{vv}
	} else {
		ctx.Body = httpHtmlBody{fmt.Sprintf("%v", html)}
	}
}

func (ctx *Context) Script(script string, args ...Any) {
	ctx.clearBody()
	ctx.codingTyping("html", args...)
	ctx.Body = httpScriptBody{script}
}

func (ctx *Context) Json(json Any, args ...Any) {
	ctx.JSON(json, args...)
}
func (ctx *Context) JSON(json Any, args ...Any) {
	ctx.clearBody()
	ctx.codingTyping("json", args...)
	ctx.Body = httpJsonBody{json}
}

// Jsonp
func (ctx *Context) Jsonp(callback string, json Any, args ...Any) {
	ctx.JSONP(callback, json, args...)
}

// Jsonp
func (ctx *Context) JSONP(callback string, json Any, args ...Any) {
	ctx.clearBody()
	ctx.codingTyping("jsonp", args...)
	ctx.Body = httpJsonpBody{json, callback}
}

func (ctx *Context) Xml(xml Any, args ...Any) {
	ctx.clearBody()
	ctx.codingTyping("xml", args...)
	ctx.Body = httpXmlBody{xml}
}

func (ctx *Context) fileTyping(args ...string) string {

	var mime, name string
	for _, arg := range args {
		if strings.Contains(arg, "/") {
			mime = arg
		} else if strings.Contains(arg, ".") {
			name = arg
		} else {
			//没有点，也没有杠，更像是 文件扩展名
			mime = arg

			// if defNothing == infra.Mimetype(arg, defNothing) {
			// 	name = arg
			// } else {
			// 	mime = arg
			// }
		}
	}

	if mime != "" {
		ctx.Type = mime
	}

	return name
}
func (ctx *Context) File(file string, args ...string) {
	ctx.clearBody()
	name := ctx.fileTyping(args...)

	if ctx.Type == "" {
		ext := util.Extension(file)
		if ext != "" {
			ctx.Type = ext
		}
	}
	ctx.Body = httpFileBody{file, name}
}

func (ctx *Context) Buffer(buffer io.ReadCloser, size int64, args ...string) {
	ctx.clearBody()
	name := ctx.fileTyping(args...)
	ctx.Body = httpBufferBody{buffer, size, name}
}
func (ctx *Context) Stream(stream io.ReadCloser, size int64, args ...string) {
	ctx.Buffer(stream, size, args...)
}
func (ctx *Context) Binary(bytes []byte, args ...string) {
	ctx.clearBody()
	name := ctx.fileTyping(args...)
	ctx.Body = httpBinaryBody{bytes, name}
}

func (ctx *Context) Proxy(url string) {
	ctx.clearBody()
	ctx.Body = httpProxyBody{url}
}

// View
// Map is Model for view
// string is type
func (ctx *Context) View(view string, args ...Any) {
	ctx.clearBody()

	code := 0
	mime := ""
	var model Map
	for _, arg := range args {
		switch vv := arg.(type) {
		case int:
			code = vv
		case string:
			mime = vv
		case Map:
			model = vv
		}
	}

	if code > 0 {
		ctx.Code = code
	}
	if mime != "" {
		ctx.Type = mime
	}
	if ctx.Type == "" {
		ctx.Type = "html"
	}

	ctx.Body = httpViewBody{view, model}
}

// 下面是些扩展的方法

func (ctx *Context) Alert(res Res, urls ...string) {
	text := ctx.String(res.State(), res.Args()...)

	if res == nil || res.OK() {
		ctx.Code = http.StatusOK
	} else {
		ctx.Code = http.StatusInternalServerError
	}

	if len(urls) > 0 {
		text = fmt.Sprintf(`<script type="text/javascript">alert("%s"); location.href="%s";</script>`, text, urls[0])
	} else {
		text = fmt.Sprintf(`<script type="text/javascript">alert("%s"); history.back();</script>`, text)
	}

	ctx.Script(text)
}

// 展示通用的提示页面
func (ctx *Context) Show(res Res, urls ...string) {
	code := res.Code()
	text := ctx.String(res.State(), res.Args()...)

	if res == nil || res.OK() {
		ctx.Code = http.StatusOK
	} else {
		ctx.Code = http.StatusInternalServerError
	}

	m := Map{
		"code": code,
		"text": text,
		"url":  "",
	}
	if len(urls) > 0 {
		m["url"] = urls[0]
	}

	ctx.Data["show"] = m
	ctx.View("show")
}

// Echo 是 Answer的别名
func (ctx *Context) Answer(res Res, args ...Any) {
	ctx.Echo(res, args...)
}

// 接口统一输出方法
// args表示返回给客户端的data
// 也会从 ctx.Data 先读取数据，然后使用args中的覆盖
func (ctx *Context) Echo(res Res, args ...Any) {
	ctx.clearBody()

	code := 0
	text := ""
	if res != nil {
		code = res.Code()
		text = ctx.String(res.State(), res.Args()...)
	}

	if res == nil || res.OK() {
		ctx.Code = http.StatusOK
	} else {
		if ctx.Code <= 0 {
			ctx.Code = http.StatusInternalServerError
		}
	}

	//20211203更新，先使用data，再使用args覆盖
	var secret string
	var data Map
	//had data
	if len(ctx.Data) > 0 {
		data = make(Map)
		for k, v := range ctx.Data {
			data[k] = v
		}
	}

	for _, arg := range args {
		if vv, ok := arg.(string); ok {
			secret = vv
		} else if vvs, ok := arg.(Map); ok {
			if data == nil {
				data = make(Map)
			}
			for k, v := range vvs {
				data[k] = v
			}
		}
	}

	//回写进ctx.Data
	for k, v := range data {
		ctx.Data[k] = v
	}

	ctx.Type = "json"
	ctx.Body = httpEchoBody{code, text, secret, data}
}

func (ctx *Context) Status(code int, texts ...string) {
	ctx.clearBody()
	ctx.Code = code
	if len(texts) > 0 {
		ctx.Body = httpStatusBody(texts[0])
	}
}
