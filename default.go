package http

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	. "github.com/bamgoo/base"
)

func init() {
	module.RegisterDriver(DEFAULT, &defaultDriver{})
}

type (
	defaultDriver struct{}

	defaultConnect struct {
		mutex    sync.RWMutex
		instance *Instance
		server   *http.Server
		router   *mux.Router
		routes   map[string]*mux.Route
	}
)

func (driver *defaultDriver) Connect(inst *Instance) (Connect, error) {
	return &defaultConnect{
		instance: inst,
		routes:   make(map[string]*mux.Route),
	}, nil
}

func (c *defaultConnect) Open() error {
	c.router = mux.NewRouter()
	c.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", c.instance.Config.Host, c.instance.Config.Port),
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      c.router,
	}

	c.router.NotFoundHandler = c
	c.router.MethodNotAllowedHandler = c

	return nil
}

func (c *defaultConnect) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	return c.server.Shutdown(ctx)
}

func (c *defaultConnect) Register(name string, info Info) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	route := c.router.HandleFunc(info.Uri, c.ServeHTTP).Name(name)
	if info.Method != "" {
		route.Methods(info.Method)
	}

	c.routes[name] = route
	return nil
}

func (c *defaultConnect) Start() error {
	if c.server == nil {
		panic("Invalid http server")
	}

	go func() {
		err := c.server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			panic(err.Error())
		}
	}()

	return nil
}

func (c *defaultConnect) StartTLS(certFile, keyFile string) error {
	if c.server == nil {
		panic("Invalid http server")
	}

	go func() {
		err := c.server.ListenAndServeTLS(certFile, keyFile)
		if err != nil && err != http.ErrServerClosed {
			panic(err.Error())
		}
	}()

	return nil
}

func (c *defaultConnect) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	name := ""
	params := Map{}

	route := mux.CurrentRoute(req)
	if route != nil {
		name = route.GetName()
		vars := mux.Vars(req)
		for k, v := range vars {
			params[k] = v
		}
	}

	c.instance.Serve(name, params, res, req)
}
