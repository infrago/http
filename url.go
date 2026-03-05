package http

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	. "github.com/infrago/base"
	"github.com/infrago/infra"
)

type httpUrl struct {
	ctx *Context
}

func (m *Module) url() *httpUrl {
	return &httpUrl{}
}

// RouteUri builds relative URI by route name.
func (u *httpUrl) RouteUri(name string, values ...Map) string {
	siteName, uri, _, fallback, ok := u.route(name, values...)
	_ = siteName
	if !ok {
		return fallback
	}
	return uri
}

// RouteUrl builds absolute URL by route name.
func (u *httpUrl) RouteUrl(name string, values ...Map) string {
	siteName, uri, options, fallback, ok := u.route(name, values...)
	if !ok {
		return fallback
	}

	targetSite := siteName
	if siteOpt, ok := options["[site]"]; ok && siteOpt != nil {
		if s, ok := siteOpt.(string); ok && s != "" {
			targetSite = u.resolveSiteName(s)
		}
	}
	return u.SiteUrl(targetSite, uri, options)
}

func (u *httpUrl) route(name string, values ...Map) (string, string, Map, string, bool) {
	name = strings.ToLower(name)
	if strings.HasPrefix(name, "http://") || strings.HasPrefix(name, "https://") ||
		strings.HasPrefix(name, "ws://") || strings.HasPrefix(name, "wss://") {
		return "", name, Map{}, name, true
	}

	currSite := ""
	if u.ctx != nil && u.ctx.inst != nil {
		currSite = strings.ToLower(u.ctx.inst.Name)
		if name == "" {
			name = u.ctx.Name
		}
	}

	if strings.Contains(name, ".") == false {
		if currSite != "" {
			name = currSite + "." + name
		} else {
			name = infra.DEFAULT + "." + name
		}
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

	siteName, routeName := splitPrefix(name)
	if siteName == "*" {
		if currSite != "" {
			siteName = currSite
		} else {
			for s := range module.instances {
				siteName = s
				break
			}
		}
	}
	siteName = u.resolveSiteName(siteName)

	inst := module.instances[siteName]
	if inst == nil {
		inst = module.instances[infra.DEFAULT]
	}
	if inst == nil {
		return siteName, "", options, name, false
	}

	info, ok := findRouteInfo(inst, routeName)
	if !ok {
		return siteName, "", options, name, false
	}

	argsConfig := Vars{}
	if info.Args != nil {
		for k, v := range info.Args {
			argsConfig[k] = v
		}
	}

	dataArgsValues, dataParseValues := Map{}, Map{}
	for k, v := range params {
		if strings.HasPrefix(k, "{") && strings.HasSuffix(k, "}") {
			kk := strings.TrimSuffix(strings.TrimPrefix(k, "{"), "}")
			dataArgsValues[kk] = v
		} else {
			dataArgsValues[k] = v
			querys[k] = v
		}
	}

	zone := time.Local
	if u.ctx != nil && u.ctx.Meta != nil {
		zone = u.ctx.Meta.Timezone()
	}

	_ = infra.Mapping(argsConfig, dataArgsValues, dataParseValues, false, true, zone)

	dataValues := Map{}
	for k, v := range dataParseValues {
		dataValues[k] = v
	}

	uri := info.Uri
	re := regexp.MustCompile(`\{[^}]+\}`)
	uri = re.ReplaceAllStringFunc(uri, func(m string) string {
		key := strings.TrimSuffix(strings.TrimPrefix(m, "{"), "}")
		if v, ok := dataValues[key]; ok {
			return fmt.Sprintf("%v", v)
		}
		if v, ok := params[m]; ok {
			return fmt.Sprintf("%v", v)
		}
		return ""
	})

	if len(querys) > 0 {
		q := url.Values{}
		for k, v := range querys {
			q.Set(k, fmt.Sprintf("%v", v))
		}
		if strings.Contains(uri, "?") {
			uri = uri + "&" + q.Encode()
		} else {
			uri = uri + "?" + q.Encode()
		}
	}

	return siteName, uri, options, name, true
}

func findRouteInfo(inst *Instance, routeName string) (Info, bool) {
	if inst == nil || routeName == "" {
		return Info{}, false
	}

	if info, ok := inst.routerInfos[routeName]; ok {
		return info, true
	}

	candidates := []string{
		routeName + ".*",
		routeName + ".get",
		routeName + ".post",
		routeName + ".put",
		routeName + ".patch",
		routeName + ".delete",
		routeName + ".head",
		routeName + ".options",
	}
	for _, key := range candidates {
		if info, ok := inst.routerInfos[key]; ok {
			return info, true
		}
	}

	for _, key := range inst.routerOrder {
		info, ok := inst.routerInfos[key]
		if !ok {
			continue
		}
		if info.Router == routeName || strings.HasPrefix(info.Router, routeName+".") {
			return info, true
		}
	}

	return Info{}, false
}

func (u *httpUrl) resolveSiteName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return infra.DEFAULT
	}
	if _, ok := module.instances[name]; ok {
		return name
	}
	return name
}

// SiteUrl builds absolute site URL with path.
func (u *httpUrl) SiteUrl(name, path string, options ...Map) string {
	opts := Map{}
	if len(options) > 0 {
		opts = options[0]
	}

	name = u.resolveSiteName(name)
	inst := module.instances[name]
	if inst == nil {
		inst = module.instances[infra.DEFAULT]
	}
	if inst == nil {
		return path
	}

	host := u.resolveSiteHost(name, inst)

	port := inst.Config.Port
	if !strings.Contains(host, ":") && port > 0 {
		if port != 80 && port != 443 {
			host = fmt.Sprintf("%s:%d", host, port)
		}
	}

	socket := false
	ssl := false
	if v, ok := opts["[socket]"].(bool); ok && v {
		socket = true
	}
	if v, ok := opts["[ssl]"].(bool); ok && v {
		ssl = true
	}

	scheme := "http://"
	if socket {
		scheme = "ws://"
	}
	if ssl {
		if socket {
			scheme = "wss://"
		} else {
			scheme = "https://"
		}
	}

	if path == "" {
		return scheme + host
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return scheme + host + path
}

func (u *httpUrl) resolveSiteHost(name string, inst *Instance) string {
	if u.ctx != nil && u.ctx.Host != "" {
		curr := normalizeHost(u.ctx.Host)
		currSite := infra.DEFAULT
		if u.ctx.inst != nil && u.ctx.inst.Name != "" {
			currSite = strings.ToLower(u.ctx.inst.Name)
		}

		if name == currSite {
			return curr
		}
		if tail := hostTail(curr); tail != "" {
			if name == infra.DEFAULT {
				return normalizeHost(tail)
			}
			return normalizeHost(name + "." + tail)
		}
	}

	if inst.Config.Domain != "" {
		return normalizeHost(inst.Config.Domain)
	}
	if inst.Config.Host != "" && inst.Config.Host != "0.0.0.0" && inst.Config.Host != "::" {
		return normalizeHost(inst.Config.Host)
	}
	if name != "" && name != infra.DEFAULT {
		return normalizeHost(name + ".localhost")
	}
	return "localhost"
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		if idx := strings.Index(host, "://"); idx > -1 {
			host = host[idx+3:]
		}
	}
	if i := strings.Index(host, "/"); i > -1 {
		host = host[:i]
	}
	if strings.Contains(host, ":") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	return strings.TrimSpace(host)
}

func hostTail(host string) string {
	host = normalizeHost(host)
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return ""
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts[1:], ".")
}

// RouteUrl shortcut.
func RouteUrl(name string, values ...Map) string {
	return module.url().RouteUrl(name, values...)
}

// RouteUri shortcut.
func RouteUri(name string, values ...Map) string {
	return module.url().RouteUri(name, values...)
}

// SiteUrl shortcut.
func SiteUrl(name, path string, options ...Map) string {
	return module.url().SiteUrl(name, path, options...)
}
