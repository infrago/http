package http

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/bamgoo/bamgoo"
	. "github.com/bamgoo/base"
)

// preprocessing handles token and language.
func (inst *Instance) preprocessing(ctx *Context) {
	token := ""
	if ctx.inst.Config.Cookie != "" {
		if c, e := ctx.reader.Cookie(ctx.inst.Config.Cookie); e == nil {
			token = c.Value
		}
	}
	if vv := ctx.Header("Authorization"); vv != "" {
		token = strings.TrimPrefix(vv, "Bearer ")
	}

	if token != "" {
		ctx.Verify(token)
	}

	// Detect AJAX
	if ctx.Header("X-Requested-With") != "" ||
		ctx.Header("Authorization") != "" ||
		ctx.Header("Ajax") != "" {
		ctx.Ajax = true
	}

	// Language from Accept-Language
	if al := ctx.Header("Accept-Language"); al != "" {
		accepts := strings.Split(al, ",")
		if len(accepts) > 0 {
			for _, accept := range accepts {
				if i := strings.Index(accept, ";"); i > 0 {
					accept = accept[0:i]
				}
				for lang, config := range bamgoo.Languages() {
					for _, acccc := range config.Accepts {
						if strings.EqualFold(acccc, accept) {
							ctx.Language(lang)
							break
						}
					}
				}
			}
		}
	}

	ctx.Next()
}

// finding handles static files.
func (inst *Instance) finding(ctx *Context) {
	if ctx.Name == "" {
		fsys := bamgoo.AssetFS()
		file := resolveStaticFile(ctx.inst.Config.Static, ctx.Path, ctx.inst.Config.Defaults, fsys)
		if file != "" && !strings.Contains(file, "../") {
			if fsys != nil {
				bts, err := bamgoo.AssetFile(file)
				if err == nil {
					ext := path.Ext(file)
					if strings.HasPrefix(ext, ".") {
						ext = ext[1:]
					}
					ctx.Binary(bts, bamgoo.Mimetype(ext, "application/octet-stream"))
					return
				}
			}
			ctx.File(file)
			return
		}
		ctx.Found()
		return
	}

	ctx.Next()
}

func resolveStaticFile(root, requestPath string, defaults []string, fsys fs.FS) string {
	if root == "" {
		return ""
	}
	cleanPath := path.Clean("/" + requestPath)
	target := path.Join(root, cleanPath)

	if fsys != nil {
		if fi, err := fs.Stat(fsys, target); err == nil {
			if fi.IsDir() {
				for _, doc := range defaults {
					docPath := path.Join(target, doc)
					if ff, err := fs.Stat(fsys, docPath); err == nil && !ff.IsDir() {
						return docPath
					}
				}
				return ""
			}
			return target
		}
		return ""
	}

	fi, err := os.Stat(target)
	if err != nil {
		return ""
	}
	if fi.IsDir() {
		for _, doc := range defaults {
			docPath := path.Join(target, doc)
			if ff, err := os.Stat(docPath); err == nil && !ff.IsDir() {
				return docPath
			}
		}
		return ""
	}
	return target
}

// crossing handles CORS.
func (inst *Instance) crossing(ctx *Context) {
	cross := ctx.inst.Cross

	if cross.Allow {
		origin := ctx.Header("Origin")
		originPassed := false

		if cross.Origin == "*" || cross.Origin == "" {
			originPassed = true
		} else if origin != "" {
			for _, prefix := range cross.Origins {
				if strings.HasPrefix(origin, prefix) {
					originPassed = true
					break
				}
			}
		}

		method := ctx.Header("Access-Control-Request-Method")
		methodPassed := cross.Method == "*" || cross.Method == "" || method == ""

		header := ctx.Header("Access-Control-Request-Headers")
		headerPassed := cross.Header == "*" || cross.Header == "" || header == ""

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
				return
			}
		}
	}

	ctx.Next()
}

// authorizing handles authentication.
func (inst *Instance) authorizing(ctx *Context) {
	if ctx.Config.Sign {
		if !ctx.Signed() {
			ctx.Result(bamgoo.Unsigned)
			inst.denied(ctx)
			return
		}
	}

	if ctx.Config.Auth {
		if !ctx.Authed() {
			ctx.Result(bamgoo.Unauthed)
			inst.denied(ctx)
			return
		}
	}

	ctx.Next()
}

// parsing parses request body.
func (inst *Instance) parsing(ctx *Context) {
	req := ctx.reader

	// URL params
	for key, val := range ctx.Params {
		if vv, ok := val.(string); ok {
			ctx.Value[key] = vv
		} else if vs, ok := val.([]string); ok && len(vs) > 0 {
			if len(vs) == 1 {
				ctx.Value[key] = vs[0]
			} else {
				ctx.Value[key] = vs
			}
		} else {
			ctx.Value[key] = fmt.Sprintf("%v", val)
		}
	}

	// URL query
	for key, vals := range req.URL.Query() {
		if len(vals) == 1 {
			ctx.Query[key] = vals[0]
			ctx.Value[key] = vals[0]
		} else if len(vals) > 1 {
			ctx.Query[key] = vals
			ctx.Value[key] = vals
		}
	}

	if ctx.Method != "GET" {
		ctype := ctx.Header("Content-Type")

		if strings.Contains(ctype, "json") {
			body, err := io.ReadAll(req.Body)
			if err == nil {
				var jsonBody Map
				if err := json.Unmarshal(body, &jsonBody); err == nil {
					for key, val := range jsonBody {
						ctx.Form[key] = val
						ctx.Value[key] = val
					}
				}
			}
		} else {
			// Parse form
			err := req.ParseMultipartForm(32 << 20)
			if err != nil {
				body, err := io.ReadAll(req.Body)
				if err == nil {
					ctx.Body = string(body)
				}
			}

			if req.MultipartForm != nil {
				for key, vals := range req.MultipartForm.Value {
					if len(vals) == 1 {
						ctx.Form[key] = vals[0]
						ctx.Value[key] = vals[0]
					} else if len(vals) > 1 {
						ctx.Form[key] = vals
						ctx.Value[key] = vals
					}
				}

				// Handle file uploads
				for key, vs := range req.MultipartForm.File {
					files := []Map{}
					for _, f := range vs {
						if f.Size <= 0 || f.Filename == "" {
							continue
						}

						file, err := f.Open()
						if err != nil {
							continue
						}

						ext := ""
						if idx := strings.LastIndex(f.Filename, "."); idx > 0 {
							ext = f.Filename[idx+1:]
						}

						tempfile, err := ctx.uploadFile("upload_*." + ext)
						if err != nil {
							file.Close()
							continue
						}

						io.Copy(tempfile, file)
						tempfile.Close()
						file.Close()

						files = append(files, Map{
							"name": f.Filename,
							"type": ext,
							"mime": f.Header.Get("Content-Type"),
							"size": f.Size,
							"file": tempfile.Name(),
						})
					}

					if len(files) == 1 {
						ctx.Upload[key] = files[0]
						ctx.Value[key] = files[0]
					} else if len(files) > 1 {
						ctx.Upload[key] = files
						ctx.Value[key] = files
					}
				}
			} else if req.PostForm != nil {
				for key, vals := range req.PostForm {
					if len(vals) == 1 {
						ctx.Form[key] = vals[0]
						ctx.Value[key] = vals[0]
					} else if len(vals) > 1 {
						ctx.Form[key] = vals
						ctx.Value[key] = vals
					}
				}
			}
		}
	}

	ctx.Next()
}

// arguing validates and maps arguments.
func (inst *Instance) arguing(ctx *Context) {
	if ctx.Config.Args != nil {
		argsValue := Map{}
		res := bamgoo.Mapping(ctx.Config.Args, ctx.Value, argsValue, ctx.Config.Nullable, false, ctx.Timezone())
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
