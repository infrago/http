package http

import (
	"fmt"
	"net/http"
	"strings"

	. "github.com/infrago/base"
)

type (
	Cookie = http.Cookie

	Routing map[string]Router
	Router  struct {
		site   string
		Method string

		Uri      string   `json:"uri"`
		Uris     []string `json:"uris"`
		Name     string   `json:"name"`
		Text     string   `json:"text"`
		Nullable bool     `json:"-"`
		Socket   bool     `json:"socket"` //预留，为后面的websocket模块
		Args     Vars     `json:"args"`
		Data     Vars     `json:"data"`
		Setting  Map      `json:"-"`

		Find Find `json:"find"`

		Coding bool `json:"-"`

		Routing Routing   `json:"routing"`
		Actions []ctxFunc `json:"-"`
		Action  ctxFunc   `json:"-"`

		Sign bool   `json:"Sign"`
		Auth bool   `json:"auth"`
		Kind string `json:"kind"`

		// 路由单独可定义的处理器
		Found  ctxFunc `json:"-"`
		Error  ctxFunc `json:"-"`
		Failed ctxFunc `json:"-"`
		Denied ctxFunc `json:"-"`
	}

	// Filter 拦截器
	Filter struct {
		site     string
		Name     string  `json:"name"`
		Text     string  `json:"text"`
		Serve    ctxFunc `json:"-"`
		Request  ctxFunc `json:"-"`
		Execute  ctxFunc `json:"-"`
		Response ctxFunc `json:"-"`
	}
	// Handler 处理器
	Handler struct {
		site   string
		Name   string  `json:"name"`
		Text   string  `json:"text"`
		Found  ctxFunc `json:"-"`
		Error  ctxFunc `json:"-"`
		Failed ctxFunc `json:"-"`
		Denied ctxFunc `json:"-"`
	}

	Helper struct {
		Name   string   `json:"name"`
		Desc   string   `json:"desc"`
		Alias  []string `json:"alias"`
		Action Any      `json:"-"`
	}

	Find map[string]Item
	Item struct {
		Required bool   `json:"required"`
		Method   string `json:"method"`
		Value    string `json:"value"` //http
		Args     string `json:"args"`  //method
		Name     string `json:"name"`
		Text     string `json:"text"`
		Empty    Res    `json:"-"`
		Error    Res    `json:"-"`
	}

	File struct {

		// Checksum 使用 sha256算法
		Checksum string `json:"checksum"`

		// Filename 是文件的原始文件名
		Filename string `json:"filename"`

		// Extension 扩展名，不包括点（.）
		Extension string `json:"extension"`

		// Mimetype 是文件的MIMEType
		Mimetype string `json:"mimetype"`

		// Length 文件大小，单位：字节
		Length int64 `json:"length"`

		// Tempfile 临时文件路径
		Tempfile string `json:"tempfile"`
	}
)

// Router 注册路由
// 这里就直接按methods拆分路由，因为要继承
// *不在这里处理，因为注册的时候，可能配置文件还没有加载
// sitesConifg 有可能还没有准备好。
func (this *Module) Router(name string, config Router, override bool) {

	// 默认都要加站点
	if strings.Contains(name, ".") == false {
		name = "." + name
	}

	if config.Uris == nil || len(config.Uris) == 0 {
		config.Uris = []string{config.Uri}
	} else {
		if config.Uri != "" {
			config.Uris = append(config.Uris, config.Uri)
		}
	}

	routers := make(map[string]Router, 0)

	// 处理多method的路由，单独保存，并且要复制
	if config.Routing != nil {

		for method, methodConfig := range config.Routing {
			realName := fmt.Sprintf("%s.%s", name, method)
			realConfig := config //复制一份，但是这里的引用字段还是引用，需要单独处理

			realConfig.Method = method
			realConfig.Nullable = methodConfig.Nullable
			realConfig.Action = nil
			realConfig.Actions = nil
			realConfig.Routing = nil

			// 这几个字段是引用，所有不置空的话，
			// 所有methods中的定义全部引用的中同个
			realConfig.Args = nil
			realConfig.Data = nil
			realConfig.Setting = nil
			realConfig.Find = nil

			//复制全局的
			if config.Args != nil {
				if realConfig.Args == nil {
					realConfig.Args = Vars{}
				}
				for k, v := range config.Args {
					realConfig.Args[k] = v
				}
			}
			if config.Data != nil {
				if realConfig.Data == nil {
					realConfig.Data = Vars{}
				}
				for k, v := range config.Data {
					realConfig.Data[k] = v
				}
			}
			if config.Setting != nil {
				if realConfig.Setting == nil {
					realConfig.Setting = Map{}
				}
				for k, v := range config.Setting {
					realConfig.Setting[k] = v
				}
			}

			if config.Find != nil {
				if realConfig.Find == nil {
					realConfig.Find = Find{}
				}
				for k, v := range config.Find {
					realConfig.Find[k] = v
				}
			}

			//-----------------

			//方法级的覆盖
			if methodConfig.Name != "" {
				realConfig.Name = methodConfig.Name
			}
			if methodConfig.Text != "" {
				realConfig.Text = methodConfig.Text
			}

			if methodConfig.Args != nil {
				if realConfig.Args == nil {
					realConfig.Args = Vars{}
				}
				for k, v := range methodConfig.Args {
					realConfig.Args[k] = v
				}
			}
			if methodConfig.Data != nil {
				if realConfig.Data == nil {
					realConfig.Data = Vars{}
				}
				for k, v := range methodConfig.Data {
					realConfig.Data[k] = v
				}
			}
			if methodConfig.Setting != nil {
				if realConfig.Setting == nil {
					realConfig.Setting = Map{}
				}
				for k, v := range methodConfig.Setting {
					realConfig.Setting[k] = v
				}
			}

			if methodConfig.Find != nil {
				if realConfig.Find == nil {
					realConfig.Find = Find{}
				}
				for k, v := range methodConfig.Find {
					realConfig.Find[k] = v
				}
			}

			//复制方法
			if methodConfig.Action != nil {
				realConfig.Action = methodConfig.Action
			}
			if methodConfig.Actions != nil {
				realConfig.Actions = methodConfig.Actions
			}

			// 路由级的处理器
			if methodConfig.Found != nil {
				realConfig.Found = methodConfig.Found
			}
			if methodConfig.Error != nil {
				realConfig.Error = methodConfig.Error
			}
			if methodConfig.Failed != nil {
				realConfig.Failed = methodConfig.Failed
			}
			if methodConfig.Denied != nil {
				realConfig.Denied = methodConfig.Denied
			}

			routers[realName] = realConfig
		}
		//清掉这个 Routing 没用了
		config.Routing = nil
	}
	if config.Action != nil {
		//全方法版，自动加*号，这样和get,post保持一样的尾节数
		name += ".*"
		routers[name] = config
	}

	// 写入routers
	for key, router := range routers {
		key = strings.ToLower(key) //key全部小写
		if override {
			this.routers[key] = router
		} else {
			if _, ok := this.routers[key]; ok == false {
				this.routers[key] = router
			}
		}
	}

}

func (module *Module) Routers(sites ...string) map[string]Router {
	prefix := ""
	if len(sites) > 0 {
		prefix = sites[0] + "."
	}

	routers := make(map[string]Router)
	for name, config := range module.routers {
		if prefix == "" || strings.HasPrefix(name, prefix) {
			routers[name] = config
		}
	}

	return routers
}

// Filter 注册 拦截器
func (this *Module) Filter(name string, config Filter, override bool) {
	if override {
		this.filters[name] = config
	} else {
		if _, ok := this.filters[name]; ok == false {
			this.filters[name] = config
		}
	}
}

// Handler 注册 处理器
func (this *Module) Handler(name string, config Handler, override bool) {
	if override {
		this.handlers[name] = config
	} else {
		if _, ok := this.handlers[name]; ok == false {
			this.handlers[name] = config
		}
	}
}

func (this *Module) Helper(name string, config Helper, override bool) {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	alias := make([]string, 0)
	if name != "" {
		alias = append(alias, name)
	}
	if config.Alias != nil {
		alias = append(alias, config.Alias...)
	}

	for _, key := range alias {
		if override {
			this.helpers[key] = config
		} else {
			if _, ok := this.helpers[key]; ok == false {
				this.helpers[key] = config
			}
		}

	}
}
