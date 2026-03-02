package http

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	. "github.com/infrago/base"
	"github.com/infrago/infra"
	"github.com/infrago/view"
)

type (
	httpGotoBody struct {
		url string
	}
	httpTextBody struct {
		text string
	}
	httpHtmlBody struct {
		html string
	}
	httpJsonBody struct {
		json Any
	}
	httpJsonpBody struct {
		json     Any
		callback string
	}
	httpEchoBody struct {
		code int
		text string
		data Map
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
		size   int64
		name   string
	}
	httpViewBody struct {
		view  string
		model Map
	}
	httpStatusBody string
)

func (inst *Instance) bodyFail(ctx *Context, err error) {
	if err == nil {
		return
	}

	ctx.Result(infra.Fail.With(err.Error()))

	if ctx.output != nil && ctx.output.Committed() {
		if ctx.Code <= 0 {
			ctx.Code = ctx.output.Status()
		}
		return
	}

	if ctx.failedBody {
		if ctx.Code <= 0 {
			ctx.Code = StatusInternalServerError
		}
		ctx.writer.Header().Set("Content-Type", "text/plain; charset="+ctx.Charset())
		ctx.writer.WriteHeader(ctx.Code)
		_, _ = fmt.Fprint(ctx.writer, StatusText(ctx.Code))
		return
	}

	ctx.failedBody = true
	if ctx.Code <= 0 || ctx.Code < StatusInternalServerError {
		ctx.Code = StatusInternalServerError
	}
	ctx.handling = "error"
	inst.handle(ctx)
	inst.body(ctx)
}

func (inst *Instance) body(ctx *Context) {
	if ctx.Code <= 0 {
		ctx.Code = StatusOK
	}

	// Write headers
	for k, v := range ctx.headers {
		ctx.writer.Header().Set(k, v)
	}

	// Write cookies
	for _, cookie := range ctx.cookies {
		cookie.Path = "/"
		cookie.HttpOnly = ctx.inst.Config.HttpOnly
		if ctx.inst.Config.MaxAge > 0 {
			cookie.MaxAge = int(ctx.inst.Config.MaxAge.Seconds())
		}
		http.SetCookie(ctx.writer, &cookie)
	}

	switch body := ctx.Body.(type) {
	case string:
		inst.bodyText(ctx, httpTextBody{body})
	case Map:
		inst.bodyJson(ctx, httpJsonBody{body})
	case httpGotoBody:
		inst.bodyGoto(ctx, body)
	case httpTextBody:
		inst.bodyText(ctx, body)
	case httpHtmlBody:
		inst.bodyHtml(ctx, body)
	case httpJsonBody:
		inst.bodyJson(ctx, body)
	case httpJsonpBody:
		inst.bodyJsonp(ctx, body)
	case httpEchoBody:
		inst.bodyEcho(ctx, body)
	case httpFileBody:
		inst.bodyFile(ctx, body)
	case httpBinaryBody:
		inst.bodyBinary(ctx, body)
	case httpBufferBody:
		inst.bodyBuffer(ctx, body)
	case httpViewBody:
		inst.bodyView(ctx, body)
	case httpStatusBody:
		inst.bodyStatus(ctx, body)
	default:
		inst.bodyDefault(ctx)
	}
}

func (inst *Instance) bodyDefault(ctx *Context) {
	if ctx.Code <= 0 {
		ctx.Code = StatusNotFound
		http.NotFound(ctx.writer, ctx.reader)
	} else {
		ctx.writer.WriteHeader(ctx.Code)
		fmt.Fprint(ctx.writer, StatusText(ctx.Code))
	}
}

func (inst *Instance) bodyStatus(ctx *Context, body httpStatusBody) {
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

func (inst *Instance) bodyGoto(ctx *Context, body httpGotoBody) {
	if ctx.Code <= 0 {
		ctx.Code = StatusFound
	}
	http.Redirect(ctx.writer, ctx.reader, body.url, StatusFound)
}

func (inst *Instance) bodyText(ctx *Context, body httpTextBody) {
	res := ctx.writer

	if ctx.Type == "" {
		ctx.Type = "text"
	}

	mimeType := infra.Mimetype(ctx.Type, "text/plain")
	res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))

	res.WriteHeader(ctx.Code)
	if _, err := fmt.Fprint(res, body.text); err != nil {
		inst.bodyFail(ctx, err)
	}
}

func (inst *Instance) bodyHtml(ctx *Context, body httpHtmlBody) {
	res := ctx.writer

	if ctx.Type == "" {
		ctx.Type = "html"
	}

	mimeType := infra.Mimetype(ctx.Type, "text/html")
	res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))

	res.WriteHeader(ctx.Code)
	if _, err := fmt.Fprint(res, body.html); err != nil {
		inst.bodyFail(ctx, err)
	}
}

func (inst *Instance) bodyJson(ctx *Context, body httpJsonBody) {
	res := ctx.writer

	if ctx.Type == "" {
		ctx.Type = "json"
	}

	bytes, err := json.Marshal(body.json)
	if err != nil {
		inst.bodyFail(ctx, err)
		return
	}

	mimeType := infra.Mimetype(ctx.Type, "application/json")
	res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))
	res.WriteHeader(ctx.Code)
	if _, err := fmt.Fprint(res, string(bytes)); err != nil {
		inst.bodyFail(ctx, err)
	}
}

func (inst *Instance) bodyJsonp(ctx *Context, body httpJsonpBody) {
	res := ctx.writer

	if ctx.Type == "" {
		ctx.Type = "script"
	}

	bytes, err := json.Marshal(body.json)
	if err != nil {
		inst.bodyFail(ctx, err)
		return
	}

	mimeType := infra.Mimetype(ctx.Type, "application/javascript")
	res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))

	res.WriteHeader(ctx.Code)
	if _, err := fmt.Fprintf(res, "%s(%s);", body.callback, string(bytes)); err != nil {
		inst.bodyFail(ctx, err)
	}
}

func (inst *Instance) bodyEcho(ctx *Context, body httpEchoBody) {
	result := Map{
		"code": body.code,
		"time": time.Now().Unix(),
	}

	if body.text != "" {
		result["text"] = body.text
	}

	if body.data != nil {
		result["data"] = body.data
	}

	inst.bodyJson(ctx, httpJsonBody{result})
}

func (inst *Instance) bodyFile(ctx *Context, body httpFileBody) {
	req, res := ctx.reader, ctx.writer

	if ctx.Type == "" {
		ctx.Type = "file"
	}

	mimeType := infra.Mimetype(ctx.Type, "application/octet-stream")
	res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))

	if body.name != "" {
		res.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%v;", url.QueryEscape(body.name)))
	}

	http.ServeFile(res, req, body.file)
}

func (inst *Instance) bodyBinary(ctx *Context, body httpBinaryBody) {
	res := ctx.writer

	if ctx.Type == "" {
		ctx.Type = "file"
	}

	mimeType := infra.Mimetype(ctx.Type, "application/octet-stream")
	res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))

	if body.name != "" {
		res.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%v;", url.QueryEscape(body.name)))
	}

	res.WriteHeader(ctx.Code)
	if _, err := res.Write(body.bytes); err != nil {
		inst.bodyFail(ctx, err)
	}
}

func (inst *Instance) bodyBuffer(ctx *Context, body httpBufferBody) {
	res := ctx.writer

	if ctx.Type == "" {
		ctx.Type = "file"
	}

	mimeType := infra.Mimetype(ctx.Type, "application/octet-stream")
	res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))

	if body.name != "" {
		res.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%v;", url.QueryEscape(body.name)))
	}

	if body.size > 0 {
		res.Header().Set("Content-Length", fmt.Sprintf("%d", body.size))
	}

	res.WriteHeader(ctx.Code)
	if _, err := io.Copy(res, body.buffer); err != nil {
		inst.bodyFail(ctx, err)
	}
	body.buffer.Close()
}

func (inst *Instance) bodyView(ctx *Context, body httpViewBody) {
	res := ctx.writer

	viewData := Map{
		"config":  ctx.inst.Config,
		"setting": ctx.inst.Setting,
		"args":    ctx.Args,
		"value":   ctx.Value,
		"locals":  ctx.Locals,
		"data":    ctx.Data,
		"model":   body.model,
	}

	html, err := view.Parse(view.Body{
		View:     body.view,
		Site:     inst.Name,
		Helpers:  inst.viewHelpers(ctx),
		Language: ctx.Language(),
		Timezone: ctx.Timezone(),
		Data:     viewData,
		Model:    body.model,
	})
	if err != nil {
		inst.bodyFail(ctx, err)
		return
	}

	mimeType := infra.Mimetype(ctx.Type, "text/html")
	res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))
	res.WriteHeader(ctx.Code)
	if _, err := fmt.Fprint(res, html); err != nil {
		inst.bodyFail(ctx, err)
	}
}

func (inst *Instance) viewHelpers(ctx *Context) Map {
	zone := ctx.Timezone()
	return Map{
		"language": func() string {
			return ctx.Language()
		},
		"timezone": func() string {
			return zone.String()
		},
		"format": func(format string, args ...interface{}) string {
			if len(args) == 1 {
				switch vv := args[0].(type) {
				case time.Time:
					return vv.In(zone).Format(format)
				case int64:
					// unix seconds range guard
					if vv >= 31507200 && vv <= 31507200000 {
						return time.Unix(vv, 0).In(zone).Format(format)
					}
				}
			}
			return fmt.Sprintf(format, args...)
		},
		"string": func(key string, args ...Any) string {
			return ctx.String(strings.ReplaceAll(key, ".", "_"), args...)
		},
		"ctx": func() *Context {
			return ctx
		},
	}
}
