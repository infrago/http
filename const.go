package http

import (
	"errors"

	"github.com/infrago/infra"
)

const (
	NAME = "HTTP"
	WWW  = "www"

	defNothing = "_)(*&^%"
)

const (
	typeText   = "text"
	typeHtml   = "html"
	typeScript = "script"
	typeJson   = "json"
	typeXml    = "xml"
	typeFile   = "file"
)

var (
	resFound     = infra.Result(-1, "http.found", "Http Not Found.")
	resError     = infra.Result(-1, "http.error", "Http Error.")
	resFailed    = infra.Result(-1, "http.failed", "Http Failed.")
	resDenied    = infra.Result(-1, "http.denied", "Http Denied.")
	resItemEmpty = infra.Result(-1, "http.item.empty", "empty item.")
	resItemError = infra.Result(-1, "http.item.error", "error item.")

	resViewParsingFailed = infra.Result(-1, "http.view_parsing_failed", "view %s parsing failed.")

	resBodyParsingFailed = infra.Result(-1, "http.body_parsing_failed", "Http body parsing failed.")

	errInvalidConnection = errors.New("Invalid http connection.")
)
