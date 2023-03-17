package http

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	. "github.com/infrago/base"
	"github.com/infrago/infra"
	"github.com/infrago/util"
	"github.com/infrago/view"
)

type (

	//跳转
	httpGotoBody struct {
		url string
	}
	httpTextBody struct {
		text string
	}
	httpHtmlBody struct {
		html string
	}
	httpScriptBody struct {
		script string
	}
	httpJsonBody struct {
		json Any
	}
	httpJsonpBody struct {
		json     Any
		callback string
	}
	httpEchoBody struct {
		code   int
		text   string
		secret string
		data   Map
	}
	httpXmlBody struct {
		xml Any
	}
	httpFileBody struct {
		file string
		name string
	}
	httpBinaryBody struct {
		bytes []byte
		name  string
	}
	httpBufferBody struct {
		buffer io.ReadCloser
		name   string
	}
	httpProxyBody struct {
		url string
	}
	httpViewBody struct {
		view  string
		model Map
	}
	httpStatusBody string
	RawBody        string
)

// 最终的默认body响应
func (this *Instance) body(ctx *Context) {
	if ctx.Code <= 0 {
		ctx.Code = StatusOK
	}

	// 要回写headers
	for k, v := range ctx.headers {
		ctx.writer.Header().Set(k, v)
	}

	// 这里要写cookies
	for _, cookie := range ctx.cookies {
		cookie.Path = "/"
		cookie.HttpOnly = ctx.site.HttpOnly

		if ctx.site.Domain != "" {
			cookie.Domain = ctx.site.Domain
		}
		if ctx.Domain != "" {
			cookie.Domain = ctx.Domain
		}
		if ctx.site.MaxAge > 0 {
			cookie.MaxAge = int(ctx.site.MaxAge.Seconds())
		}

		//这里统一加密
		if ctx.site.Crypto {
			if vvv, err := infra.EncryptTEXT(cookie.Value); err == nil {
				cookie.Value = vvv
			}
		}

		http.SetCookie(ctx.writer, &cookie)
	}

	//最终响应之前，判断是否需要颁发token
	if ctx.issue && ctx.site.Cookie != "" {
		//需要站点配置中指定了cookie的，才把cookie写入cookie
		if token := ctx.Token(); token != "" {
			cookie := http.Cookie{Name: ctx.site.Cookie, Value: token, HttpOnly: ctx.site.HttpOnly}

			if ctx.site.Domain != "" {
				cookie.Domain = ctx.site.Domain
			}
			if ctx.Domain != "" {
				cookie.Domain = ctx.Domain
			}
			if ctx.site.MaxAge > 0 {
				cookie.MaxAge = int(ctx.site.MaxAge.Seconds())
			}

			http.SetCookie(ctx.writer, &cookie)
		}
	}

	switch body := ctx.Body.(type) {
	case string:
		this.bodyText(ctx, httpTextBody{body})
	case Map:
		this.bodyJson(ctx, httpJsonBody{body})

	case httpGotoBody:
		this.bodyGoto(ctx, body)
	case httpTextBody:
		this.bodyText(ctx, body)
	case httpHtmlBody:
		this.bodyHtml(ctx, body)
	case httpScriptBody:
		this.bodyScript(ctx, body)
	case httpJsonBody:
		this.bodyJson(ctx, body)
	case httpJsonpBody:
		this.bodyJsonp(ctx, body)
	case httpEchoBody:
		this.bodyEcho(ctx, body)
	case httpXmlBody:
		this.bodyXml(ctx, body)
	case httpFileBody:
		this.bodyFile(ctx, body)
	case httpBinaryBody:
		this.bodyBinary(ctx, body)
	case httpBufferBody:
		this.bodyBuffer(ctx, body)
	case httpProxyBody:
		this.bodyProxy(ctx, body)
	case httpViewBody:
		this.bodyView(ctx, body)
	case httpStatusBody:
		this.bodyStatus(ctx, body)
	default:
		this.bodyDefault(ctx)
	}
}

// bodyDefault 默认的body处理
func (this *Instance) bodyDefault(ctx *Context) {
	if ctx.Code <= 0 {
		ctx.Code = StatusNotFound
		http.NotFound(ctx.writer, ctx.reader)
	} else {
		ctx.writer.WriteHeader(ctx.Code)
		fmt.Fprint(ctx.writer, StatusText(ctx.Code))
	}
}

func (this *Instance) bodyStatus(ctx *Context, body httpStatusBody) {
	if ctx.Code <= 0 {
		ctx.Code = StatusNotFound
		http.NotFound(ctx.writer, ctx.reader)
	} else {

		if body == "" {
			body = httpStatusBody(StatusText(ctx.Code))
		}

		ctx.writer.WriteHeader(ctx.Code)
		fmt.Fprint(ctx.writer, body)
	}
}

func (this *Instance) bodyGoto(ctx *Context, body httpGotoBody) {
	http.Redirect(ctx.writer, ctx.reader, body.url, StatusFound)
}
func (this *Instance) bodyText(ctx *Context, body httpTextBody) {
	res := ctx.writer

	if ctx.Type == "" {
		ctx.Type = "text"
	}

	mimeType := infra.Mimetype(ctx.Type, "text/explain")
	res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))

	res.WriteHeader(ctx.Code)
	fmt.Fprint(res, body.text)

}
func (this *Instance) bodyHtml(ctx *Context, body httpHtmlBody) {
	res := ctx.writer

	if ctx.Type == "" {
		ctx.Type = "html"
	}

	mimeType := infra.Mimetype(ctx.Type, "text/html")
	res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))

	res.WriteHeader(ctx.Code)
	fmt.Fprint(res, body.html)
}

func (this *Instance) bodyScript(ctx *Context, body httpScriptBody) {
	res := ctx.writer

	if ctx.Type == "" {
		ctx.Type = "script"
	}

	mimeType := infra.Mimetype(ctx.Type, "application/script")
	res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))

	res.WriteHeader(ctx.Code)
	fmt.Fprint(res, body.script)

}
func (this *Instance) bodyJson(ctx *Context, body httpJsonBody) {
	res := ctx.writer

	if ctx.Type == "" {
		ctx.Type = "json"
	}

	bytes, err := infra.MarshalJSON(body.json)
	if err != nil {
		http.Error(res, err.Error(), StatusInternalServerError)
	} else {
		mimeType := infra.Mimetype(ctx.Type, "application/json")
		res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))
		res.WriteHeader(ctx.Code)
		fmt.Fprint(res, string(bytes))
	}
}
func (this *Instance) bodyJsonp(ctx *Context, body httpJsonpBody) {
	res := ctx.writer

	if ctx.Type == "" {
		ctx.Type = "script"
	}
	bytes, err := infra.MarshalJSON(body.json)
	if err != nil {
		//要不要发到统一的错误ctx.Error那里？再走一遍
		http.Error(res, err.Error(), StatusInternalServerError)
	} else {
		mimeType := infra.Mimetype(ctx.Type, "application/script")
		res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))

		res.WriteHeader(ctx.Code)
		fmt.Fprint(res, fmt.Sprintf("%s(%s);", body.callback, string(bytes)))
	}

}
func (this *Instance) bodyXml(ctx *Context, body httpXmlBody) {
	res := ctx.writer

	if ctx.Type == "" {
		ctx.Type = "xml"
	}

	bytes, err := infra.MarshalXML(body.xml)
	if err != nil {
		http.Error(res, err.Error(), StatusInternalServerError)
	} else {
		mimeType := infra.Mimetype(ctx.Type, "text/xml")
		res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))

		res.WriteHeader(ctx.Code)
		fmt.Fprint(res, string(bytes))
	}
}
func (this *Instance) bodyEcho(ctx *Context, body httpEchoBody) {

	json := Map{
		"code": body.code,
		"time": time.Now().Unix(),
	}

	if body.text != "" {
		json["text"] = body.text
	}

	if body.data != nil {
		//否则，传过来什么，就直接输出什么
		codec := ctx.site.Confuse
		if vv, ok := ctx.Setting["codec"].(bool); ok && vv == false {
			codec = ""
		}
		if vv, ok := ctx.Setting["plain"].(bool); ok && vv {
			codec = ""
		}
		if vv := ctx.Header("debug"); vv == infra.Secret() {
			codec = ""
		}

		tempDataVar := Var{
			Type: "json", Required: true, Encode: codec,
		}

		if ctx.Config.Data != nil {
			if ctx.Code == http.StatusOK {
				tempDataVar.Children = ctx.Config.Data
			}
		}

		tempConfig := Vars{
			"data": tempDataVar,
		}
		tempData := Map{
			"data": body.data,
		}

		val := Map{}
		res := infra.Mapping(tempConfig, tempData, val, false, false, ctx.Timezone())

		if res == nil || res.OK() {
			if body.secret != "" {

				//先把data转成string
				bytes, err := infra.MarshalJSON(val["data"])
				if err != nil {
					//原版返回data，处理失败，哈哈
					json["data"] = val["data"]
				} else {

					sign, secret := "", ""
					dataStr := string(bytes)

					if strings.HasPrefix(body.secret, "md5:") {
						secret = strings.TrimPrefix(body.secret, "md5:")
						sign = util.Md5(dataStr + secret)
					} else if strings.HasPrefix(body.secret, "sha1:") {
						secret = strings.TrimPrefix(body.secret, "sha1:")
						sign = util.Sha1(dataStr + secret)
					} else if strings.HasPrefix(body.secret, "sha256:") {
						secret = strings.TrimPrefix(body.secret, "sha256:")
						sign = util.Sha256(dataStr + secret)
					} else {
						secret = body.secret
						sign = util.Sha256(dataStr + secret)
					}

					json["sign"] = sign
					json["data"] = dataStr
				}
			} else {
				json["data"] = val["data"]
			}
		} else {
			json["code"] = infra.StateCode(res.State())
			json["text"] = ctx.String(res.State(), res.Args()...)
		}
	}

	//转到jsonbody去处理
	this.bodyJson(ctx, httpJsonBody{json})
}

func (this *Instance) bodyFile(ctx *Context, body httpFileBody) {
	req, res := ctx.reader, ctx.writer

	//文件类型
	if ctx.Type == "" {
		ctx.Type = "file"
	}

	//处理本地文件
	if strings.HasPrefix(body.file, "file://") {
		body.file = strings.TrimPrefix(body.file, "file://")
	}
	if strings.HasPrefix(body.file, "local://") {
		body.file = strings.TrimPrefix(body.file, "local://")
	}

	mimeType := infra.Mimetype(ctx.Type, "application/octet-stream")
	res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))

	//加入自定义文件名
	if body.name != "" {
		res.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%v;", url.QueryEscape(body.name)))
	}

	http.ServeFile(res, req, body.file)

}
func (this *Instance) bodyBinary(ctx *Context, body httpBinaryBody) {
	res := ctx.writer

	if ctx.Type == "" {
		ctx.Type = "file"
	}

	mimeType := infra.Mimetype(ctx.Type, "application/octet-stream")
	res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))

	//加入自定义文件名
	if body.name != "" {
		res.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%v;", url.QueryEscape(body.name)))
	}

	res.WriteHeader(ctx.Code)
	res.Write(body.bytes)

}
func (this *Instance) bodyBuffer(ctx *Context, body httpBufferBody) {
	res := ctx.writer

	if ctx.Type == "" {
		ctx.Type = "file"
	}

	mimeType := infra.Mimetype(ctx.Type, "application/octet-stream")
	res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))

	//加入自定义文件名
	if body.name != "" {
		res.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%v;", url.QueryEscape(body.name)))
	}

	res.WriteHeader(ctx.Code)
	_, err := io.Copy(res, body.buffer)
	//bytes,err := ioutil.ReadAll(body.buffer)
	if err == nil {
		http.Error(res, "read buffer error", StatusInternalServerError)
	}
	body.buffer.Close()

}

func (this *Instance) bodyProxy(ctx *Context, body httpProxyBody) {
	req := ctx.reader
	res := ctx.writer

	target, e := url.Parse(body.url)
	if e != nil {
		http.Error(res, "XML parsing failure", StatusInternalServerError)
	} else {
		targetQuery := target.RawQuery
		director := func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = target.Path
			if targetQuery == "" || req.URL.RawQuery == "" {
				req.URL.RawQuery = targetQuery + req.URL.RawQuery
			} else {
				req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
			}
			if _, ok := req.Header["User-Agent"]; !ok {
				// explicitly disable User-Agent so it's not set to default value
				req.Header.Set("User-Agent", "")
			}
		}

		proxy := &httputil.ReverseProxy{Director: director}
		proxy.ServeHTTP(res, req)
	}
}

func (this *Instance) bodyView(ctx *Context, body httpViewBody) {
	res := ctx.writer

	viewdata := Map{
		"config": ctx.site, "setting": infra.Setting(),
		"args": ctx.Args, "value": ctx.Value,
		"locals": ctx.Locals, "data": ctx.Data, "model": body.model,
	}

	helpers := this.viewHelpers(ctx)

	html, err := view.Parse(view.Body{
		View: body.view, Site: ctx.Site, Helpers: helpers,
		Language: ctx.Language(), Timezone: ctx.Timezone(),
		Data: viewdata,
	})

	if err != nil {
		// errRes := resViewParsingFailed.With(body.view)
		// errText := ctx.String(errRes.State(), errRes.Args()...)
		http.Error(res, err.Error(), StatusInternalServerError)
	} else {
		mimeType := infra.Mimetype(ctx.Type, "text/html")
		res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))
		res.WriteHeader(ctx.Code)
		fmt.Fprint(res, html)
	}
}
func (this *Instance) viewHelpers(ctx *Context) Map {
	//系统内置的helper

	zone := ctx.Timezone()

	helpers := Map{
		"route": ctx.Url.Route,
		// "browse":   ctx.Url.Browse,
		// "preview":  ctx.Url.Preview,
		// "download": ctx.Url.Download,
		"backurl": ctx.Url.Back,
		"lasturl": ctx.Url.Last,
		"siteurl": func(name string, paths ...string) string {
			path := ""
			if len(paths) > 0 {
				path = paths[0]
			}
			return ctx.Url.Site(name, path)
		},

		"language": func() string {
			return ctx.Language()
		},
		"timezone": func() string {
			return ctx.String(ctx.Timezone().String())
		},
		"format": func(format string, args ...interface{}) string {
			//支持一下显示时间
			if len(args) == 1 {
				if args[0] == nil {
					return format
				} else if ttt, ok := args[0].(time.Time); ok {
					zoneTime := ttt.In(zone)
					return zoneTime.Format(format)
				} else if ttt, ok := args[0].(int64); ok {
					//时间戳是大于1971年是, 千万级, 2016年就是10亿级了
					if ttt >= int64(31507200) && ttt <= int64(31507200000) {
						ttt := time.Unix(ttt, 0)
						zoneTime := ttt.In(zone)
						sss := zoneTime.Format(format)
						if strings.HasPrefix(sss, "%") == false || format != sss {
							return sss
						}
					}
				}
			}
			return fmt.Sprintf(format, args...)
		},
		"string": func(key string, args ...Any) string {
			return ctx.String(key, args...)
		},
		//待处理，暂时不要，自己到router里处理去
		// "option": func(name, field string, v Any) Any {
		// 	value := fmt.Sprintf("%v", v)
		// 	//多语言支持
		// 	//key=enum.name.file.value
		// 	langkey := fmt.Sprintf("option_%s_%s_%s", name, field, value)
		// 	langval := ctx.String(langkey)
		// 	if langkey != langval {
		// 		return langval
		// 	} else {
		// 		return mData.Option(name, field, value)
		// 		// if vv, ok := enums[value].(string); ok {
		// 		// 	return vv
		// 		// }
		// 		// return value
		// 	}
		// },
	}

	// 这里要带上 http 携带的 helpers

	for k, v := range this.module.helperActions {
		if f, ok := v.(func(*Context, ...Any) Any); ok {
			helpers[k] = func(args ...Any) Any {
				return f(ctx, args...)
			}
		} else {
			helpers[k] = v
		}
	}

	return helpers
}
