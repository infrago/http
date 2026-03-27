package http

import (
	"net/http"

	. "github.com/infrago/base"
	"github.com/infrago/ws"
)

type (
	// Driver defines HTTP driver interface.
	Driver interface {
		Connect(*Instance) (Connect, error)
	}

	// Connect defines HTTP connection interface.
	Connect interface {
		Open() error
		Close() error

		Register(name string, info Info) error
		Upgrade(res http.ResponseWriter, req *http.Request) (ws.Conn, error)

		Start() error
		StartTLS(certFile, keyFile string) error
	}

	// Delegate handles HTTP requests.
	Delegate interface {
		Serve(name string, params Map, res http.ResponseWriter, req *http.Request)
	}

	// Info contains route information.
	Info struct {
		Method string
		Uri    string
		Router string
		Entry  string
		Args   Vars
	}
)
