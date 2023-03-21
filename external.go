package http

import (
	. "github.com/infrago/base"
)

func Routes(sites ...string) map[string]Route {
	return module.Routes(sites...)
}

func SiteHosts(site string) []string {
	if cfg, ok := module.sites[site]; ok {
		return cfg.Hosts
	}

	return []string{}
}

func RouteUrl(name string, args ...Map) string {
	return module.url.Route(name, args...)
}

func SiteUrl(name string, path string, options ...Map) string {
	return module.url.Site(name, path, options...)
}
