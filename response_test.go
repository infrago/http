package http

import (
	"encoding/json"
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
