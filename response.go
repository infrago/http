package http

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/bamgoo/bamgoo"
	. "github.com/bamgoo/base"
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
	httpStatusBody string
)

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
	http.Redirect(ctx.writer, ctx.reader, body.url, StatusFound)
}

func (inst *Instance) bodyText(ctx *Context, body httpTextBody) {
	res := ctx.writer

	if ctx.Type == "" {
		ctx.Type = "text"
	}

	mimeType := bamgoo.Mimetype(ctx.Type, "text/plain")
	res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))

	res.WriteHeader(ctx.Code)
	fmt.Fprint(res, body.text)
}

func (inst *Instance) bodyHtml(ctx *Context, body httpHtmlBody) {
	res := ctx.writer

	if ctx.Type == "" {
		ctx.Type = "html"
	}

	mimeType := bamgoo.Mimetype(ctx.Type, "text/html")
	res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))

	res.WriteHeader(ctx.Code)
	fmt.Fprint(res, body.html)
}

func (inst *Instance) bodyJson(ctx *Context, body httpJsonBody) {
	res := ctx.writer

	if ctx.Type == "" {
		ctx.Type = "json"
	}

	bytes, err := json.Marshal(body.json)
	if err != nil {
		http.Error(res, err.Error(), StatusInternalServerError)
		return
	}

	mimeType := bamgoo.Mimetype(ctx.Type, "application/json")
	res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))
	res.WriteHeader(ctx.Code)
	fmt.Fprint(res, string(bytes))
}

func (inst *Instance) bodyJsonp(ctx *Context, body httpJsonpBody) {
	res := ctx.writer

	if ctx.Type == "" {
		ctx.Type = "script"
	}

	bytes, err := json.Marshal(body.json)
	if err != nil {
		http.Error(res, err.Error(), StatusInternalServerError)
		return
	}

	mimeType := bamgoo.Mimetype(ctx.Type, "application/javascript")
	res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))

	res.WriteHeader(ctx.Code)
	fmt.Fprintf(res, "%s(%s);", body.callback, string(bytes))
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

	mimeType := bamgoo.Mimetype(ctx.Type, "application/octet-stream")
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

	mimeType := bamgoo.Mimetype(ctx.Type, "application/octet-stream")
	res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))

	if body.name != "" {
		res.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%v;", url.QueryEscape(body.name)))
	}

	res.WriteHeader(ctx.Code)
	res.Write(body.bytes)
}

func (inst *Instance) bodyBuffer(ctx *Context, body httpBufferBody) {
	res := ctx.writer

	if ctx.Type == "" {
		ctx.Type = "file"
	}

	mimeType := bamgoo.Mimetype(ctx.Type, "application/octet-stream")
	res.Header().Set("Content-Type", fmt.Sprintf("%v; charset=%v", mimeType, ctx.Charset()))

	if body.name != "" {
		res.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%v;", url.QueryEscape(body.name)))
	}

	if body.size > 0 {
		res.Header().Set("Content-Length", fmt.Sprintf("%d", body.size))
	}

	res.WriteHeader(ctx.Code)
	io.Copy(res, body.buffer)
	body.buffer.Close()
}
