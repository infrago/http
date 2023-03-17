package http

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	. "github.com/infrago/base"
)

type (
	httpUrl struct {
		ctx *Context
	}
)

// Routo 强制带site base url的
func (this *httpUrl) Routo(name string, values ...Map) string {
	value := Map{}
	if len(values) > 0 {
		value = values[0]
	}
	value["[site]"] = true
	return this.Route(name, value)
}

// Route
func (this *httpUrl) Route(name string, values ...Map) string {
	name = strings.ToLower(name) //路由名全转小写

	if strings.HasPrefix(name, "http://") || strings.HasPrefix(name, "https://") ||
		strings.HasPrefix(name, "ws://") || strings.HasPrefix(name, "wss://") {
		return name
	}

	//从整理后的infos拿到真实的路由名
	// name += ".0"
	// if info, ok := module.routerInfos[name]; ok == false {
	// 	return "[no router here]"
	// }

	//当前站点
	currSite := ""
	if this.ctx != nil {
		currSite = this.ctx.Site
		if name == "" {
			name = this.ctx.Name
		}
	}

	// 默认都要加站点
	if strings.Contains(name, ".") == false {
		name = "." + name
	}

	params, querys, options := Map{}, Map{}, Map{}
	if len(values) > 0 {
		for k, v := range values[0] {
			if strings.HasPrefix(k, "{") && strings.HasSuffix(k, "}") {
				params[k] = v
			} else if strings.HasPrefix(k, "[") && strings.HasSuffix(k, "]") {
				options[k] = v
			} else {
				querys[k] = v
			}
		}
	}

	// justSite, justName := "", ""
	justSite := ""
	if strings.Contains(name, ".") {
		i := strings.Index(name, ".")
		justSite = name[:i]
		// justName = name[i+1:]
	}

	//如果是*.开头
	if justSite == "*" {
		if currSite != "" {
			justSite = currSite
		} else {
			//只能随机选一个站点了
			for site, _ := range module.sites {
				justSite = site
				break
			}
		}
		name = strings.Replace(name, "*", justSite, 1)
	}

	//如果是不同站点，强制带域名
	if justSite != currSite {
		options["[site]"] = justSite
	} else if options["[site]"] != nil {
		options["[site]"] = currSite
	}

	// 见infos表，因为对Uris做了遍历，单独存了
	nameget := fmt.Sprintf("%s.get.0", name)
	namepost := fmt.Sprintf("%s.post.0", name)
	nameall := fmt.Sprintf("%s.*.0", name)

	var info Info

	//搜索定义
	if vv, ok := module.routerInfos[name]; ok {
		info = vv
	} else if vv, ok := module.routerInfos[nameget]; ok {
		info = vv
	} else if vv, ok := module.routerInfos[namepost]; ok {
		info = vv
	} else if vv, ok := module.routerInfos[nameall]; ok {
		info = vv //全方法版加了.*
	} else {
		//没有找到路由定义
		return name
	}

	if info.socket {
		options["[socket]"] = true
	}

	argsConfig := Vars{}
	if info.args != nil {
		for k, v := range info.args {
			argsConfig[k] = v
		}
	}

	//选项处理

	if options["[back]"] != nil && this.ctx != nil {
		backUrl := this.Back()
		if vvv, err := infra.EncryptTEXT(backUrl); err == nil {
			backUrl = vvv
		}
		querys["backurl"] = backUrl
	}
	//选项处理
	if options["[last]"] != nil && this.ctx != nil {
		backUrl := this.Last()
		if vvv, err := infra.EncryptTEXT(backUrl); err == nil {
			backUrl = vvv
		}
		querys["backurl"] = backUrl
	}
	//选项处理
	if options["[current]"] != nil && this.ctx != nil {
		backUrl := this.Current()
		if vvv, err := infra.EncryptTEXT(backUrl); err == nil {
			backUrl = vvv
		}
		querys["backurl"] = backUrl
	}
	//自动携带原有的query信息
	if options["[query]"] != nil && this.ctx != nil {
		for k, v := range this.ctx.Query {
			querys[k] = v
		}
	}

	//所以，解析uri中的参数，值得分几类：
	//1传的值，2param值, 3默认值
	//其中主要问题就是，传的值，需要到args解析，用于加密，这个值和auto值完全重叠了，除非分2次解析
	//为了框架好用，真是操碎了心
	dataValues, paramValues, autoValues := Map{}, Map{}, Map{}

	//1. 处理传过来的值
	//从value中获取
	//如果route不定义args，这里是拿不到值的
	dataArgsValues, dataParseValues := Map{}, Map{}
	for k, v := range params {
		if k[0:1] == "{" {
			k = strings.Replace(k, "{", "", -1)
			k = strings.Replace(k, "}", "", -1)
			dataArgsValues[k] = v
		} else {
			//这个也要？要不然指定的一些page啥的不行？
			dataArgsValues[k] = v
			//另外的是query的值
			querys[k] = v
		}
	}

	zone := time.Local
	if this.ctx != nil {
		zone = this.ctx.Timezone()
	}

	//上下文
	dataErr := infra.Mapping(argsConfig, dataArgsValues, dataParseValues, false, true, zone)
	if dataErr == nil || dataErr.OK() {
		for k, v := range dataParseValues {

			//注意，这里能拿到的，还有非param，所以不能直接用加{}写入
			if _, ok := params[k]; ok {
				dataValues[k] = v
			} else if _, ok := params["{"+k+"}"]; ok {
				dataValues["{"+k+"}"] = v
			} else {
				//这里是默认值应该，就不需要了
			}
		}
	}

	//所以这里还得处理一次，如果route不定义args，parse就拿不到值，就直接用values中的值
	for k, v := range params {
		if k[0:1] == "{" && dataValues[k] == nil {
			dataValues[k] = v
		}
	}

	//2.params中的值
	//从params中来一下，直接参数解析
	if this.ctx != nil {
		for k, v := range this.ctx.Params {
			paramValues["{"+k+"}"] = v
		}
	}

	//3. 默认值
	//从value中获取
	autoArgsValues, autoParseValues := Map{}, Map{}
	autoErr := infra.Mapping(argsConfig, autoArgsValues, autoParseValues, false, true, zone)
	if autoErr == nil || autoErr.OK() {
		for k, v := range autoParseValues {
			autoValues["{"+k+"}"] = v
		}
	}

	//开始替换值
	regx := regexp.MustCompile(`\{[_\*A-Za-z0-9]+\}`)
	uri := regx.ReplaceAllStringFunc(info.Uri, func(p string) string {
		key := strings.Replace(p, "*", "", -1)

		if v, ok := dataValues[key]; ok {
			//for query string encode/decode
			delete(dataValues, key)
			//先从传的值去取
			return fmt.Sprintf("%v", v)
		} else if v, ok := paramValues[key]; ok {
			//再从params中去取
			return fmt.Sprintf("%v", v)
		} else if v, ok := autoValues[key]; ok {
			//最后从默认值去取
			return fmt.Sprintf("%v", v)
		} else {
			//有参数没有值,
			return p
		}
	})

	//get参数，考虑一下走mapping，自动加密参数不？
	queryStrings := []string{}
	for k, v := range querys {
		sv := fmt.Sprintf("%v", v)
		if sv != "" {
			queryStrings = append(queryStrings, fmt.Sprintf("%v=%v", k, v))
		}
	}
	if len(queryStrings) > 0 {
		uri += "?" + strings.Join(queryStrings, "&")
	}

	if site, ok := options["[site]"].(string); ok && site != "" {
		uri = this.Site(site, uri, options)
	}

	return uri
}

func (this *httpUrl) Site(name string, path string, options ...Map) string {
	// config := mHttp.config

	option := Map{}
	if len(options) > 0 {
		option = options[0]
	}

	uuu := ""
	ssl, socket := false, false

	//待优化，多hosts时候的分发

	//如果有上下文，如果是当前站点，就使用当前域
	if this.ctx != nil && this.ctx.Site == name {
		uuu = this.ctx.Host
		if vv, ok := module.sites[name]; ok {
			ssl = vv.Ssl
		}
	} else if vv, ok := module.sites[name]; ok {
		ssl = vv.Ssl
		if len(vv.Hosts) > 0 {
			uuu = vv.Hosts[0]
		}
	} else {
		uuu = "127.0.0.1"
		//uuu = fmt.Sprintf("127.0.0.1:%v", Config.Http.Port)
	}

	// 开发模式
	if infra.Developing() && module.config.Port != 80 {
		uuu = fmt.Sprintf("%s:%d", uuu, module.config.Port)
	}

	if option["[ssl]"] != nil {
		ssl = true
	}
	if option["[socket]"] != nil {
		socket = true
	}

	if socket {
		if ssl {
			uuu = "wss://" + uuu
		} else {
			uuu = "ws://" + uuu
		}
	} else {
		if ssl {
			uuu = "https://" + uuu
		} else {
			uuu = "http://" + uuu
		}
	}

	if path != "" {
		return fmt.Sprintf("%s%s", uuu, path)
	} else {
		return uuu
	}
}

func (this *httpUrl) Backing() bool {
	if this.ctx == nil {
		return false
	}

	if s, ok := this.ctx.Query["backurl"]; ok && s != "" {
		return true
	} else if this.ctx.reader.Referer() != "" {
		return true
	}
	return false
}

func (this *httpUrl) Back() string {
	if this.ctx == nil {
		return "/"
	}

	if backUrl, ok := this.ctx.Query["backurl"].(string); ok && backUrl != "" {
		if vvv, err := infra.DecryptTEXT(backUrl); err == nil {
			backUrl = fmt.Sprintf("%v", vvv)
		}
		return backUrl

	} else if this.ctx.Header("referer") != "" {
		return this.ctx.Header("referer")
	} else {
		//都没有，就是当前URL
		return this.Current()
	}
}

func (this *httpUrl) Last() string {
	if this.ctx == nil {
		return "/"
	}

	if ref := this.ctx.reader.Referer(); ref != "" {
		return ref
	} else {
		//都没有，就是当前URL
		return this.Current()
	}
}

func (this *httpUrl) Current() string {
	if this.ctx == nil {
		return "/"
	}
	return this.Site(this.ctx.Site, this.ctx.reader.URL.RequestURI())
}

// 接入文件模块，？ 为了降低模块间耦合，这个方法暂时弃用
//为了view友好，expires改成Any，支持duration解析
// func (this *httpUrl) Download(target Any, name string, args ...Any) string {
// 	if this.ctx == nil {
// 		return ""
// 	}

// 	if coding, ok := target.(string); ok && coding != "" {

// 		if strings.HasPrefix(coding, "http://") || strings.HasPrefix(coding, "https://") || strings.HasPrefix(coding, "ftp://") {
// 			return coding
// 		}

// 		expires := []time.Duration{}
// 		if len(args) > 0 {
// 			switch vv := args[0].(type) {
// 			case int:
// 				expires = append(expires, time.Second*time.Duration(vv))
// 			case time.Duration:
// 				expires = append(expires, vv)
// 			case string:
// 				if dd, ee := util.ParseDuration(vv); ee == nil {
// 					expires = append(expires, dd)
// 				}
// 			}
// 		}

// 		return Browse(coding, name, expires...)
// 	}

// 	return "[无效下载]"
// }

// // 接入文件模块，？ 为了降低模块间耦合，这个方法暂时弃用
// func (this *httpUrl) Browse(target Any, args ...Any) string {
// 	if this.ctx == nil {
// 		return ""
// 	}

// 	if coding, ok := target.(string); ok && coding != "" {

// 		if strings.HasPrefix(coding, "http://") || strings.HasPrefix(coding, "https://") || strings.HasPrefix(coding, "ftp://") {
// 			return coding
// 		}

// 		expires := []time.Duration{}
// 		if len(args) > 0 {
// 			switch vv := args[0].(type) {
// 			case int:
// 				expires = append(expires, time.Second*time.Duration(vv))
// 			case time.Duration:
// 				expires = append(expires, vv)
// 			case string:
// 				if dd, ee := util.ParseDuration(vv); ee == nil {
// 					expires = append(expires, dd)
// 				}
// 			}
// 		}

// 		return Browse(coding, "", expires...)

// 		//this.ctx.lastError = nil
// 		//if uuu, err := mFile.Browse(coding, "", aaaaa, expires...); err != nil {
// 		//	this.ctx.lastError = errResult(err)
// 		//	return ""
// 		//} else {
// 		//	return uuu
// 		//}
// 	}

// 	return "[无效文件]"
// }

// // 接入文件模块，？ 为了降低模块间耦合，这个方法暂时弃用
// func (this *httpUrl) Preview(target Any, width, height, tttt int64, args ...Any) string {
// 	if this.ctx == nil {
// 		return ""
// 	}

// 	if coding, ok := target.(string); ok && coding != "" {

// 		if strings.HasPrefix(coding, "http://") || strings.HasPrefix(coding, "https://") || strings.HasPrefix(coding, "ftp://") {
// 			return coding
// 		}

// 		expires := []time.Duration{}
// 		if len(args) > 0 {
// 			switch vv := args[0].(type) {
// 			case int:
// 				expires = append(expires, time.Second*time.Duration(vv))
// 			case time.Duration:
// 				expires = append(expires, vv)
// 			case string:
// 				if dd, ee := util.ParseDuration(vv); ee == nil {
// 					expires = append(expires, dd)
// 				}
// 			}
// 		}

// 		return Preview(coding, width, height, tttt, expires...)
// 	}

// 	return "/nothing.png"
// }
