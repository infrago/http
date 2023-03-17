package http

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	. "github.com/infrago/base"
	"github.com/infrago/util"
)

// starting 前置处理
func (this *Instance) preprocessing(ctx *Context) {
	token := ""
	if ctx.site.Cookie != "" {
		//token直接读，不从Cookie解密读，因为token是直接写的
		if c, e := ctx.reader.Cookie(ctx.site.Cookie); e == nil {
			token = c.Value
		}
	}
	if vv := ctx.Header("Authorization"); vv != "" {
		token = strings.TrimPrefix(vv, "Bearer ")
	}
	if vv := ctx.Header("X-Forwarded-Access-Token"); vv != "" {
		token = strings.TrimPrefix(vv, "Bearer ")
	}

	//验证token
	needSign := false
	if token != "" {
		err := ctx.Verify(token)
		if err != nil {
			//待处理
			//有伪造token的嫌疑，应该预警机制
			needSign = true
		}
	} else {
		needSign = true
	}

	//是否自动生成token
	if needSign && ctx.site.Token {
		if ctx.site.Expiry > 0 {
			ctx.Sign(false, nil, ctx.site.Expiry, ctx.Config.Kind)
		} else {
			ctx.Sign(false, nil, -1, ctx.Config.Kind)
		}
	}

	// 不用了，这年头谁还AJAX
	//是否AJAX请求，可能在拦截器里手动指定为true了，就不处理了
	if ctx.Ajax == false {
		if ctx.Header("Client") != "" {
			ctx.Ajax = true
		} else if ctx.Header("X-Requested-With") != "" {
			ctx.Ajax = true
		} else if ctx.Header("Ajax") != "" {
			ctx.Ajax = true
		} else if ctx.Header("Authorization") != "" {
			ctx.Ajax = true
		} else if ctx.Header("X-Forwarded-Access-Token") != "" {
			ctx.Ajax = true
		} else {
			ctx.Ajax = false
		}
	}

	//客户端的默认语言
	if al := ctx.Header("Accept-Language"); al != "" {
		accepts := strings.Split(al, ",")
		if len(accepts) > 0 {
		llll:
			for _, accept := range accepts {
				if i := strings.Index(accept, ";"); i > 0 {
					accept = accept[0:i]
				}
				//遍历匹配
				for lang, config := range infra.Languages() {
					for _, acccc := range config.Accepts {
						if strings.ToLower(acccc) == strings.ToLower(accept) {
							ctx.Language(lang)
							break llll
						}
					}
				}
			}
		}
	}

	ctx.Next()
}

// finding 判断不
func (this *Instance) finding(ctx *Context) {
	if ctx.Name == "" {
		//不存在，就要找静态文件了

		//静态文件放在这里处理
		isDir := false
		file := ""
		sitePath := path.Join(this.module.config.Static, ctx.Site, ctx.Path)
		if fi, err := os.Stat(sitePath); err == nil {
			isDir = fi.IsDir()
			file = sitePath
		} else {
			sharedPath := path.Join(this.module.config.Static, this.module.config.Shared, ctx.Path)
			if fi, err := os.Stat(sharedPath); err == nil {
				isDir = fi.IsDir()
				file = sharedPath
			}
		}

		//如果是目录，要遍历默认文档
		if isDir {
			tempFile := file
			file = ""
			if len(this.module.config.Defaults) == 0 {
				file = ""
			} else {
				for _, doc := range this.module.config.Defaults {
					docPath := path.Join(tempFile, doc)
					if fi, err := os.Stat(docPath); err == nil && fi.IsDir() == false {
						file = docPath
						break
					}
				}
			}
		}

		if file != "" && strings.Contains(file, "../") == false {
			ctx.File(file)
		} else {
			ctx.Found()
		}
		return
	}

	ctx.Next()
}

// 跨域处理
func (this *Instance) crossing(ctx *Context) {
	cross := this.module.cross

	//允许跨域才处理s
	if cross.Allow {

		//三项校验，全部要通过才放行
		origin := ctx.Header("Origin")
		originPassed := false
		if cross.Origin == "*" || cross.Origin == "" || (len(cross.Origins) > 0 && cross.Origins[0] == "*") {
			originPassed = true
		} else {
			if origin != "" {
				for _, prefix := range cross.Origins {
					if strings.HasPrefix(origin, prefix) {
						originPassed = true
						break
					}
				}
			}
		}
		method := ctx.Header("Access-Control-Request-Method")
		methodPassed := false
		if cross.Method == "*" || cross.Method == "" || (len(cross.Methods) > 0 && cross.Methods[0] == "*") {
			methodPassed = true
		} else {
			if method != "" {
				methods := util.Split(method)
				if util.AllinStrings(methods, cross.Methods) {
					methodPassed = true
				}
			}
		}

		header := ctx.Header("Access-Control-Request-Headers")
		headerPassed := false

		if cross.Header == "*" || cross.Header == "" || (len(cross.Headers) > 0 && cross.Headers[0] == "*") {
			headerPassed = true
		} else {
			if header != "" {
				headers := util.Split(header)
				if util.AllinStrings(headers, cross.Headers) {
					headerPassed = true
				}
			}
		}

		if originPassed && methodPassed && headerPassed {
			ctx.Header("Access-Control-Allow-Credentials", "true")
			if origin != "" {
				ctx.Header("Access-Control-Allow-Origin", origin)
			}
			if method != "" {
				ctx.Header("Access-Control-Allow-Methods", method)
			}
			if header != "" {
				ctx.Header("Access-Control-Allow-Headers", header)
				ctx.Header("Access-Control-Expose-Headers", header)
			}

			if ctx.Method == OPTIONS {
				ctx.Text("cross domain access allowed.", http.StatusOK)
				return //中止执行
			}
		}
	}

	ctx.Next()
}

// 客户端请求校验
// 接口请求校验
// 设备，系统，版本，客户端，版本号，时间戳，签名
// {device}/{system}/{version}/{client}/{number}/{time}/{sign}
func (this *Instance) validating(ctx *Context) {

	checking := false
	validating := "text"
	if ctx.site.Validate != "" {
		checking = true
		validating = ctx.site.Validate
	}

	//个别路由通行
	if vv, ok := ctx.Setting["passport"].(bool); ok && vv == true {
		checking = false
	}
	if vv, ok := ctx.Setting["validate"].(string); ok {
		checking = true
		validating = vv
	}
	if vv, ok := ctx.Setting["validate"].(bool); ok {
		checking = vv
	}
	if vv := ctx.Header("debug"); vv == infra.Secret() {
		checking = false //调试通行证
	}

	cs := ""
	if vv := ctx.Header("client"); vv != "" {
		cs = strings.TrimSpace(vv)
	}

	if checking && cs == "" {
		ctx.Failed(infra.Invalid)
		return
	}

	if cs != "" {
		args := Vars{
			"client": Var{Type: "string", Required: true, Decode: validating},
		}
		data := Map{
			"client": cs,
		}
		value := Map{}

		res := infra.Mapping(args, data, value, false, false, ctx.Timezone())
		if res != nil && res.Fail() {
			ctx.Failed(infra.Invalid)
			return
		}

		client := value["client"].(string)

		//注意，签名{sign}要放在最后一个
		//必须client信息里不需要带path
		clients := util.Split(client)

		//实际传的，path不需要传，是传的签名
		format := `device|system|version|client|release|timestamp|path`
		if ctx.site.Format != "" {
			format = ctx.site.Format
		}

		formats := util.Split(format)

		if checking && len(formats) >= len(clients) {
			ctx.Failed(infra.Invalid)
			return
		}

		if len(formats) < len(clients) {
			cliTime := ""
			cliPath := ""

			//这样弄顺序的意义不大，如果不按这个传，验证能过
			//但是数据就乱了
			for i, key := range formats {
				ctx.Locals[key] = clients[i]
				format = strings.Replace(format, key, clients[i], -1)
				if key == "timestamp" {
					cliTime = clients[i]
				}
				if key == "path" {
					cliPath = clients[i]
				}
			}

			//客户端签名放在最后
			cliSign := clients[len(clients)-1]
			ctx.Locals["sign"] = cliSign

			sign := strings.ToLower(util.Md5(format))

			//签名
			if checking && sign != cliSign {
				ctx.Failed(infra.Invalid)
				return
			}

			//请求的path校验
			if checking && cliPath != ctx.Path {
				ctx.Failed(infra.Invalid)
				return
			}

			//时间对比
			if checking && ctx.site.Timeout > 0 {
				now := time.Now()
				if vvd, err := strconv.ParseInt(cliTime, 10, 64); err != nil {
					//时间有问题
					ctx.Failed(infra.Invalid)
					return
				} else {
					tms := time.Unix(vvd, 0).Add(ctx.site.Timeout)
					if tms.Unix() < now.Unix() {
						//失败时间比当前时间小，失败
						ctx.Failed(infra.Invalid)
						return
					}
				}
			}
		}

	}
	ctx.Next()
}

// authorizing token验证
func (this *Instance) authorizing(ctx *Context) {

	if ctx.Config.Sign {
		if false == ctx.Signed(ctx.Config.Kind) {
			ctx.Result(infra.Unsigned)
			this.denied(ctx)
			return
		}
	}

	if ctx.Config.Auth {
		if false == ctx.Authed(ctx.Config.Kind) {
			ctx.Result(infra.Unauthed)
			this.denied(ctx)
			return
		}
	}

	ctx.Next()
}

// 专门处理base64格式的文件上传
func (this *Instance) uploading(ctx *Context, values []string) []Map {
	files := []Map{}

	baseExp := regexp.MustCompile(`data\:(.*)\;base64,(.*)`)
	for _, base := range values {
		arr := baseExp.FindStringSubmatch(base)
		if len(arr) == 3 {
			baseBytes, err := base64.StdEncoding.DecodeString(arr[2])
			if err == nil {
				h := sha256.New()
				if _, err := h.Write(baseBytes); err == nil {
					// hash := fmt.Sprintf("%x", h.Sum(nil))
					hashBytes := h.Sum(nil)
					checksum := base64.URLEncoding.EncodeToString(hashBytes)

					mimeType := arr[1]
					extension := infra.Extension(mimeType)
					filename := fmt.Sprintf("%s.%s", checksum, extension)
					size := len(baseBytes)

					tempfile := "up_*"
					if extension != "" {
						tempfile = fmt.Sprintf("%s.%s", tempfile, extension)
					}

					file, err := ctx.uploadFile(tempfile)
					if err == nil {
						if _, err := file.Write(baseBytes); err == nil {

							files = append(files, Map{
								"hash": checksum,
								"name": filename,
								"type": strings.ToLower(extension),
								"mime": mimeType,
								"size": size,
								"file": file.Name(),
							})
						}
						file.Close()
					}

				}
			}
		}
	}

	return files
}

func (this *Instance) parsing(ctx *Context) {
	var req = ctx.reader

	builder := NewTOMLBuilder()

	//URL中的参数
	for key, val := range ctx.Params {
		if vv, ok := val.(string); ok {
			builder.Append(key, vv)
		} else if vs, ok := val.([]string); ok {
			builder.Append(key, vs...)
		} else {
			builder.Append(key, fmt.Sprintf("%v", val))
		}
	}

	//urlquery
	for key, vals := range req.URL.Query() {
		builder.Append(key, vals...)
		if len(vals) == 1 {
			ctx.Query[key] = vals[0]
		} else if len(vals) > 1 {
			ctx.Query[key] = vals
		}
	}

	// uploads := map[string][]Map{}

	if ctx.Method != "GET" {
		// 根据content-type来处理
		// json, toml 等格式传过来的数据，直接写入value和form
		// 不做统一build
		ctype := ctx.Header("Content-Type")
		if strings.Contains(ctype, "text") {
			body, err := ioutil.ReadAll(req.Body)
			if err == nil {
				ctx.Body = RawBody(body)

				jsonBody := Map{}
				err := infra.UnmarshalJSON(body, &jsonBody)
				if err == nil {
					for key, val := range jsonBody {
						ctx.Form[key] = val
						ctx.Value[key] = val
					}
				}
			}
		} else if strings.Contains(ctype, "json") {
			body, err := ioutil.ReadAll(req.Body)
			if err == nil {
				ctx.Body = RawBody(body)

				jsonBody := Map{}
				err := infra.UnmarshalJSON(body, &jsonBody)
				if err == nil {
					for key, val := range jsonBody {
						ctx.Form[key] = val
						ctx.Value[key] = val
					}
				}
			}
		} else if strings.Contains(ctype, "toml") {
			body, err := ioutil.ReadAll(req.Body)
			if err == nil {
				ctx.Body = RawBody(body)

				tomlBody := Map{}
				err := infra.UnmarshalTOML(body, &tomlBody)
				if err == nil {
					for key, val := range tomlBody {
						ctx.Form[key] = val
						ctx.Value[key] = val
					}
				}
			}
		} else {

			// 表单直接传的才做统一 build

			err := req.ParseMultipartForm(32 << 20)
			if err != nil {
				//表单解析有问题，就处理成RawBody
				body, err := ioutil.ReadAll(req.Body)
				if err == nil {
					ctx.Body = RawBody(body)
				}
			}

			if req.MultipartForm != nil {

				for key, vals := range req.MultipartForm.Value {
					builder.Append(key, vals...)
					if len(vals) == 1 {
						ctx.Form[key] = vals[0]
					} else if len(vals) > 1 {
						ctx.Form[key] = vals
					}
				}
				//FILE可能要弄成JSON，文件保存后，MIME相关的东西，都要自己处理一下
				for key, vs := range req.MultipartForm.File {

					//处理多个文件
					for _, f := range vs {
						if f.Size <= 0 || f.Filename == "" {
							continue
						}
						//先计算hash
						if file, err := f.Open(); err == nil {
							filename := f.Filename
							mimetype := f.Header.Get("Content-Type")

							builder.Store(key, filename, mimetype, file)
						}
					}
				}

			} else if req.PostForm != nil {
				for key, vals := range req.PostForm {
					builder.Append(key, vals...)
					if len(vals) == 1 {
						ctx.Form[key] = vals[0]
					} else if len(vals) > 1 {
						ctx.Form[key] = vals
					}
				}
			} else if req.Form != nil {
				for key, vals := range req.Form {
					builder.Append(key, vals...)
					if len(vals) == 1 {
						ctx.Form[key] = vals[0]
					} else if len(vals) > 1 {
						ctx.Form[key] = vals
					}
				}
			}
		}
	}

	files := builder.Files()
	for key, vals := range files {
		files := this.saveFiles(ctx, key, vals)
		if len(files) == 1 {
			ctx.Upload[key] = files[0]
			ctx.Value[key] = files[0]
		} else if len(files) > 1 {
			ctx.Upload[key] = files
			ctx.Value[key] = files
		}
	}

	// 解析过后的，才存入value
	forms := builder.Forms()
	for key, vals := range forms {
		if len(vals) == 1 {
			ctx.Value[key] = vals[0]
		} else if len(vals) > 1 {
			ctx.Value[key] = vals
		}
	}

	tomlText := builder.Build()
	tomlValue := Map{}
	err := infra.UnmarshalTOML([]byte(tomlText), &tomlValue)
	if err == nil {
		for k, v := range tomlValue {
			ctx.Value[k] = v
		}
	}

	ctx.Next()
}

// parsing body解析
func (this *Instance) saveFiles(ctx *Context, key string, datas []TOMLFile) []Map {
	files := []Map{}

	for i, data := range datas {
		h := sha256.New()
		if size, err := io.Copy(h, data.Buffer); err == nil {
			hashBytes := h.Sum(nil)

			extension := ""
			if data.Name == "" {
				extension = infra.Extension(data.MIME)
				if extension == "" {
					data.Name = fmt.Sprintf("%s_%d", key, i)
				} else {
					data.Name = fmt.Sprintf("%s_%d.%s", key, i, extension)
				}
			} else {
				extension = util.Extension(data.Name)
			}

			tempfile := "fs_*"
			if extension != "" {
				tempfile = fmt.Sprintf("%s.%s", tempfile, extension)
			}

			tempFile, err := ctx.uploadFile(tempfile)
			if err == nil {
				//重新定位
				data.Buffer.Seek(0, 0)

				io.Copy(tempFile, data.Buffer) //保存文件
				tempFile.Close()

				checksum := base64.URLEncoding.EncodeToString(hashBytes)

				files = append(files, Map{
					"hash": checksum,
					"name": data.Name,
					"type": extension,
					"mime": data.MIME,
					"size": size,
					"file": tempFile.Name(),
				})

			}
		}

		defer data.Buffer.Close()
	}

	return files
}

// arguing 参数解析
func (this *Instance) arguing(ctx *Context) {
	if ctx.Config.Args != nil {
		argsValue := Map{}
		res := infra.Mapping(ctx.Config.Args, ctx.Value, argsValue, ctx.Config.Nullable, false, ctx.Timezone())
		if res != nil && res.Fail() {
			ctx.Failed(res)
			return
		}
		for k, v := range argsValue {
			ctx.Args[k] = v
		}
	}
	ctx.Next()
}

// iteming 查询数据
func (this *Instance) iteming(ctx *Context) {
	if ctx.Config.Find != nil {
		saveMap := Map{}

		for itemKey, config := range ctx.Config.Find {
			realKey := "id"
			if config.Value != "" {
				realKey = config.Value
			}
			var realVal Any
			if vv, ok := ctx.Args[realKey]; ok {
				realVal = vv
			} else if vv, ok := ctx.Value[realKey]; ok {
				realVal = vv
			}

			if realVal == nil && config.Required {
				if config.Empty != nil {
					ctx.Failed(config.Empty)
				} else {
					ctx.Failed(resItemEmpty)
				}
				return
			} else {

				//判断是否需要查询数据
				if config.Method != "" && realVal != nil {
					args := "id"
					if config.Args != "" {
						args = config.Args
					}
					//要查询库
					item := ctx.Invoke(config.Method, Map{args: realVal})
					if item == nil && config.Required {
						if config.Error != nil {
							ctx.Failed(config.Error)
						} else {
							ctx.Failed(resItemError)
						}
						return
					} else {
						saveMap[itemKey] = item
					}
				}

			}
		}

		//存入
		for k, v := range saveMap {
			ctx.Locals[k] = v
		}
	}

	ctx.Next()
}
