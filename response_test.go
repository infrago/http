package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/infrago/base"
	"github.com/infrago/infra"
)

func TestBodyAnswerEncodesDataByInstanceConfig(t *testing.T) {
	infra.Register("answer_test_http", infra.Codec{
		Encode: func(v Any) (Any, error) {
			return "encoded-http", nil
		},
		Decode: func(d Any, v Any) (Any, error) {
			return d, nil
		},
	})

	if got, err := infra.Encrypt("answer_test_http", Map{"name": "demo"}); err != nil || got != "encoded-http" {
		t.Fatalf("expected codec to work, got=%v err=%v", got, err)
	}

	rec := httptest.NewRecorder()
	inst := &Instance{}
	ctx := &Context{
		Meta:    infra.NewMeta(),
		inst:    &Instance{Config: Config{AnswerDataEncode: true, AnswerDataCodec: "answer_test_http"}},
		writer:  rec,
		headers: map[string]string{},
		cookies: map[string]Cookie{},
		Config:  Router{},
		Code:    StatusOK,
	}

	inst.bodyAnswer(ctx, httpAnswerBody{
		code: 0,
		text: "",
		data: Map{"name": "demo"},
	})

	var payload map[string]Any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected JSON payload, got err=%v body=%s", err, rec.Body.String())
	}

	data, ok := payload["data"].(string)
	if !ok {
		t.Fatalf("expected encoded data as string, got %T (%#v)", payload["data"], payload["data"])
	}
	if data != "encoded-http" {
		t.Fatalf("expected encoded data %q, got %q", "encoded-http", data)
	}
}

func TestBodyProxyJoinsTargetPathAndSetsForwardedHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]Any{
			"path":              r.URL.Path,
			"query":             r.URL.RawQuery,
			"host":              r.Host,
			"x_forwarded_for":   r.Header.Get("X-Forwarded-For"),
			"x_forwarded_host":  r.Header.Get("X-Forwarded-Host"),
			"x_forwarded_proto": r.Header.Get("X-Forwarded-Proto"),
		})
	}))
	defer upstream.Close()

	req := httptest.NewRequest(http.MethodGet, "http://frontend.demo.local/api/items?id=9", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	rec := httptest.NewRecorder()

	ctx := &Context{
		Meta:    infra.NewMeta(),
		inst:    &Instance{Config: Config{}},
		reader:  req,
		writer:  rec,
		headers: map[string]string{},
		cookies: map[string]Cookie{},
	}
	ctx.Proxy(upstream.URL + "/base?fixed=1")

	var inst Instance
	inst.body(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected proxy status 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var payload map[string]Any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected JSON payload, got err=%v body=%s", err, rec.Body.String())
	}

	if got := payload["path"]; got != "/base/api/items" {
		t.Fatalf("expected joined path /base/api/items, got %#v", got)
	}
	if got := payload["query"]; got != "fixed=1&id=9" {
		t.Fatalf("expected merged query fixed=1&id=9, got %#v", got)
	}
	if got := payload["x_forwarded_host"]; got != "frontend.demo.local" {
		t.Fatalf("expected forwarded host frontend.demo.local, got %#v", got)
	}
	if got := payload["x_forwarded_proto"]; got != "http" {
		t.Fatalf("expected forwarded proto http, got %#v", got)
	}
	if got := payload["x_forwarded_for"]; got != "10.0.0.1, 192.0.2.1" {
		t.Fatalf("expected appended forwarded for, got %#v", got)
	}
}
