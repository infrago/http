package http

import (
	"testing"

	. "github.com/infrago/base"
)

func TestBuildInstanceUsesNumericUriSuffix(t *testing.T) {
	uris := make([]string, 0, 12)
	for i := 0; i < 12; i++ {
		uris = append(uris, "/u"+string(rune('a'+i)))
	}

	inst := &Instance{
		routers: map[string]Router{
			"demo.*": {
				Uris: uris,
			},
		},
	}

	var m Module
	m.buildInstance(inst)

	if _, ok := inst.routerInfos["demo.*.10"]; !ok {
		t.Fatalf("expected router key demo.*.10 to exist, got keys=%v", inst.routerOrder)
	}
}

func TestConfigureAllowsBoolFalseOverride(t *testing.T) {
	m := &Module{
		defaultConfig: Config{},
		configs:       map[string]Config{},
	}

	m.configure("demo", Map{
		"require":  true,
		"token":    true,
		"crypto":   true,
		"httponly": true,
	})

	m.configure("demo", Map{
		"require":  false,
		"token":    false,
		"crypto":   false,
		"httponly": false,
	})

	cfg := m.configs["demo"]
	if cfg.Require || cfg.Token || cfg.Crypto || cfg.HttpOnly {
		t.Fatalf("expected bools to be overridden to false, got require=%v token=%v crypto=%v httponly=%v", cfg.Require, cfg.Token, cfg.Crypto, cfg.HttpOnly)
	}
}
