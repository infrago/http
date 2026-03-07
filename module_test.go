package http

import (
	"testing"

	. "github.com/infrago/base"
	"github.com/infrago/infra"
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
		"require":      true,
		"token":        true,
		"crypto":       true,
		"httponly":     true,
		"answerencode": true,
	})

	m.configure("demo", Map{
		"require":      false,
		"token":        false,
		"crypto":       false,
		"httponly":     false,
		"answerencode": false,
	})

	cfg := m.configs["demo"]
	if cfg.Require || cfg.Token || cfg.Crypto || cfg.HttpOnly || cfg.AnswerDataEncode {
		t.Fatalf("expected bools to be overridden to false, got require=%v token=%v crypto=%v httponly=%v answerencode=%v", cfg.Require, cfg.Token, cfg.Crypto, cfg.HttpOnly, cfg.AnswerDataEncode)
	}
}

func TestConfigureSupportsCodecAndAnswerMap(t *testing.T) {
	m := &Module{
		defaultConfig: Config{},
		configs:       map[string]Config{},
	}

	m.configure("api", Map{
		"answerencode": true,
		"codec":        "codec_a",
	})
	cfg := m.configs["api"]
	if !cfg.AnswerDataEncode || cfg.AnswerDataCodec != "codec_a" {
		t.Fatalf("expected codec key to work, got encode=%v codec=%q", cfg.AnswerDataEncode, cfg.AnswerDataCodec)
	}

	m.configure("api", Map{
		"answer": Map{
			"encode": false,
			"codec":  "codec_b",
		},
	})
	cfg = m.configs["api"]
	if cfg.AnswerDataEncode || cfg.AnswerDataCodec != "codec_b" {
		t.Fatalf("expected answer map override, got encode=%v codec=%q", cfg.AnswerDataEncode, cfg.AnswerDataCodec)
	}
}

func TestConfigParsesInstanceCrossOnly(t *testing.T) {
	m := &Module{
		defaultConfig: Config{},
		configs:       map[string]Config{},
		crosses:       map[string]Cross{},
	}

	m.Config(Map{
		"cross": Map{
			"allow": true,
		},
		"http": Map{
			"port": 8080,
			"cross": Map{
				"enable": true,
				"origin": "https://admin.example.com",
			},
			"api": Map{
				"port": 9090,
				"cross": Map{
					"allow":   true,
					"methods": []Any{"OPTIONS", "GET"},
				},
			},
		},
	})

	if _, ok := m.configs["cross"]; ok {
		t.Fatalf("expected http.cross to configure default instance, not create an instance named cross")
	}

	defaultCross := m.crosses[infra.DEFAULT]
	if !defaultCross.Allow || defaultCross.Origin != "https://admin.example.com" {
		t.Fatalf("unexpected default instance cross: %#v", defaultCross)
	}

	apiCross := m.crosses["api"]
	if !apiCross.Allow {
		t.Fatalf("expected api instance cross to enable allow")
	}
	if len(apiCross.Methods) != 2 || apiCross.Methods[0] != "OPTIONS" || apiCross.Methods[1] != "GET" {
		t.Fatalf("unexpected api instance cross methods: %#v", apiCross.Methods)
	}
}
