# http

`http` 是 infrago 的模块包。

## 安装

```bash
go get github.com/infrago/http@latest
```

## 最小接入

```go
package main

import (
    _ "github.com/infrago/http"
    "github.com/infrago/infra"
)

func main() {
    infra.Run()
}
```

## 配置示例

```toml
[http]
driver = "default"
```

## 公开 API（摘自源码）

- `func (inst *Instance) Serve(name string, params Map, res http.ResponseWriter, req *http.Request)`
- `func (Router) RegistryComponent() string`
- `func (Routers) RegistryComponent() string`
- `func (ctx *Context) Next()`
- `func (ctx *Context) Found()`
- `func (ctx *Context) Error(res Res)`
- `func (ctx *Context) Failed(res Res)`
- `func (ctx *Context) Denied(res Res)`
- `func (ctx *Context) Charset(charsets ...string) string`
- `func (ctx *Context) Header(key string, vals ...string) string`
- `func (ctx *Context) Cookie(key string, vals ...Any) string`
- `func (ctx *Context) IP() string`
- `func (ctx *Context) Agent() string`
- `func (ctx *Context) Goto(url string)`
- `func (ctx *Context) Redirect(url string)`
- `func (ctx *Context) Text(text Any, args ...Any)`
- `func (ctx *Context) HTML(html Any, args ...Any)`
- `func (ctx *Context) JSON(json Any, args ...Any)`
- `func (ctx *Context) JSONP(callback string, json Any, args ...Any)`
- `func (ctx *Context) File(file string, args ...string)`
- `func (ctx *Context) Binary(bytes []byte, args ...string)`
- `func (ctx *Context) Buffer(buffer io.ReadCloser, size int64, args ...string)`
- `func (ctx *Context) View(view string, args ...Any)`
- `func (ctx *Context) Status(code int, texts ...string)`
- `func (ctx *Context) Echo(res Res, args ...Any)`
- `func (driver *defaultDriver) Connect(inst *Instance) (Connect, error)`
- `func (c *defaultConnect) Open() error`
- `func (c *defaultConnect) Close() error`
- `func (c *defaultConnect) Register(name string, info Info) error`
- `func (c *defaultConnect) Start() error`
- `func (c *defaultConnect) StartTLS(certFile, keyFile string) error`
- `func (c *defaultConnect) ServeHTTP(res http.ResponseWriter, req *http.Request)`
- `func StatusText(code int) string`
- `func (m *Module) RegisterRouter(name string, config Router)`
- `func (m *Module) RegisterFilter(name string, config Filter)`
- `func (m *Module) RegisterHandler(name string, config Handler)`
- `func SetFS(fsys fs.FS)`
- `func (m *Module) Register(name string, value Any)`
- `func (m *Module) RegisterRouters(prefix string, routers Routers)`
- `func (m *Module) RegisterDriver(name string, driver Driver)`

## 排错

- 模块未运行：确认空导入已存在
- driver 无效：确认驱动包已引入
- 配置不生效：检查配置段名是否为 `[http]`
