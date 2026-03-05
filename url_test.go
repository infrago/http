package http

import (
	"testing"

	"github.com/infrago/infra"
)

func TestRouteUriAndRouteUrl(t *testing.T) {
	oldInstances := module.instances
	defer func() {
		module.instances = oldInstances
	}()

	module.instances = map[string]*Instance{
		infra.DEFAULT: {
			Name: infra.DEFAULT,
			Config: Config{
				Domain: "demo.local",
				Port:   8090,
			},
			routerInfos: map[string]Info{
				"home.*": {Router: "home.*", Uri: "/"},
			},
			routerOrder: []string{"home.*"},
		},
	}

	if got := RouteUri("home"); got != "/" {
		t.Fatalf("expected route uri /, got %s", got)
	}
	if got := RouteUrl("home"); got != "http://demo.local:8090/" {
		t.Fatalf("expected route url http://demo.local:8090/, got %s", got)
	}
}

func TestContextRouteMethods(t *testing.T) {
	oldInstances := module.instances
	defer func() {
		module.instances = oldInstances
	}()

	module.instances = map[string]*Instance{
		infra.DEFAULT: {
			Name: infra.DEFAULT,
			Config: Config{
				Port: 8090,
			},
			routerInfos: map[string]Info{
				"home.*": {Router: "home.*", Uri: "/home"},
			},
			routerOrder: []string{"home.*"},
		},
	}

	ctx := &Context{
		inst: &Instance{Name: infra.DEFAULT},
		Name: "home",
		Host: "api.example.org",
	}

	if got := ctx.RouteUri("home"); got != "/home" {
		t.Fatalf("expected context route uri /home, got %s", got)
	}
	if got := ctx.RouteUrl("home"); got != "http://api.example.org:8090/home" {
		t.Fatalf("expected context route url http://api.example.org:8090/home, got %s", got)
	}
	if got := ctx.SiteUrl(infra.DEFAULT, "/home"); got != "http://api.example.org:8090/home" {
		t.Fatalf("expected context site url http://api.example.org:8090/home, got %s", got)
	}
}
