package http

import (
	"strings"
	"sync"
	"time"

	"github.com/bamgoo/bamgoo"
	. "github.com/bamgoo/base"
)

func init() {
	bamgoo.Mount(module)
}

var module = &Module{
	defaultConfig: Config{Driver: DEFAULT, Charset: UTF8, Port: 8080},
	cross:         Cross{Allow: true},
	drivers:       make(map[string]Driver, 0),
	configs:       make(map[string]Config, 0),
	instances:     make(map[string]*Instance, 0),
	routers:       make(map[string]Router, 0),
	filters:       make(map[string]Filter, 0),
	handlers:      make(map[string]Handler, 0),
}

type (
	Module struct {
		mutex sync.Mutex

		opened  bool
		started bool

		defaultConfig Config
		cross         Cross

		drivers   map[string]Driver
		configs   map[string]Config
		instances map[string]*Instance

		routers  map[string]Router
		filters  map[string]Filter
		handlers map[string]Handler
	}

	Config struct {
		Driver string
		Port   int
		Host   string
		Domain string

		CertFile string
		KeyFile  string

		Charset string

		Cookie   string
		Token    bool
		Expire   time.Duration
		Crypto   bool
		MaxAge   time.Duration
		HttpOnly bool

		Upload   string
		Static   string
		Defaults []string

		Setting Map
	}

	Configs map[string]Config

	Cross struct {
		Allow   bool
		Method  string
		Methods []string
		Origin  string
		Origins []string
		Header  string
		Headers []string
	}

	Instance struct {
		Name    string
		connect Connect
		Config  Config
		Cross   Cross
		Setting Map

		routers  map[string]Router
		filters  map[string]Filter
		handlers map[string]Handler

		routerInfos map[string]Info

		serveFilters    []ctxFunc
		requestFilters  []ctxFunc
		executeFilters  []ctxFunc
		responseFilters []ctxFunc

		foundHandlers  []ctxFunc
		errorHandlers  []ctxFunc
		failedHandlers []ctxFunc
		deniedHandlers []ctxFunc
	}
)

// Register dispatches registrations.
func (m *Module) Register(name string, value Any) {
	switch v := value.(type) {
	case Driver:
		m.RegisterDriver(name, v)
	case Config:
		m.RegisterConfig(bamgoo.DEFAULT, v)
	case Configs:
		m.RegisterConfigs(v)
	case Router:
		m.RegisterRouter(name, v)
	case Filter:
		m.RegisterFilter(name, v)
	case Handler:
		m.RegisterHandler(name, v)
	}
}

// RegisterDriver registers an HTTP driver.
func (m *Module) RegisterDriver(name string, driver Driver) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if driver == nil {
		panic("Invalid http driver: " + name)
	}
	if name == "" {
		name = DEFAULT
	}

	if bamgoo.Override() {
		m.drivers[name] = driver
	} else {
		if _, ok := m.drivers[name]; !ok {
			m.drivers[name] = driver
		}
	}
}

// RegisterConfig registers HTTP config for a named instance.
func (m *Module) RegisterConfig(name string, config Config) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.opened {
		return
	}

	if name == "" {
		name = bamgoo.DEFAULT
	}
	if bamgoo.Override() {
		m.configs[name] = config
	} else {
		if _, ok := m.configs[name]; !ok {
			m.configs[name] = config
		}
	}
}

// RegisterConfigs registers multiple configs.
func (m *Module) RegisterConfigs(configs Configs) {
	for name, cfg := range configs {
		m.RegisterConfig(name, cfg)
	}
}

// Config parses global config for http.
func (m *Module) Config(global Map) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.opened {
		return
	}

	cfgAny, ok := global["http"]
	if !ok {
		return
	}
	cfgMap, ok := cfgAny.(Map)
	if !ok || cfgMap == nil {
		return
	}

	rootConfig := Map{}
	for key, val := range cfgMap {
		if conf, ok := val.(Map); ok && key != "setting" {
			m.configure(key, conf)
		} else {
			rootConfig[key] = val
		}
	}
	if len(rootConfig) > 0 {
		m.configure(bamgoo.DEFAULT, rootConfig)
	}
}

func (m *Module) configure(name string, conf Map) {
	cfg := m.defaultConfig
	if existing, ok := m.configs[name]; ok {
		cfg = existing
	}

	if v, ok := conf["driver"].(string); ok && v != "" {
		cfg.Driver = v
	}
	if v, ok := conf["port"].(int); ok {
		cfg.Port = v
	}
	if v, ok := conf["port"].(int64); ok {
		cfg.Port = int(v)
	}
	if v, ok := conf["port"].(float64); ok {
		cfg.Port = int(v)
	}
	if v, ok := conf["host"].(string); ok {
		cfg.Host = v
	}
	if v, ok := conf["domain"].(string); ok {
		cfg.Domain = v
	}
	if v, ok := conf["cert"].(string); ok {
		cfg.CertFile = v
	}
	if v, ok := conf["certfile"].(string); ok {
		cfg.CertFile = v
	}
	if v, ok := conf["key"].(string); ok {
		cfg.KeyFile = v
	}
	if v, ok := conf["keyfile"].(string); ok {
		cfg.KeyFile = v
	}
	if v, ok := conf["charset"].(string); ok {
		cfg.Charset = v
	}
	if v, ok := conf["cookie"].(string); ok {
		cfg.Cookie = v
	}
	if v, ok := conf["token"].(bool); ok {
		cfg.Token = v
	}
	if v, ok := conf["expire"]; ok {
		if d := parseDuration(v); d > 0 {
			cfg.Expire = d
		}
	}
	if v, ok := conf["crypto"].(bool); ok {
		cfg.Crypto = v
	}
	if v, ok := conf["maxage"]; ok {
		if d := parseDuration(v); d > 0 {
			cfg.MaxAge = d
		}
	}
	if v, ok := conf["httponly"].(bool); ok {
		cfg.HttpOnly = v
	}
	if v, ok := conf["upload"].(string); ok {
		cfg.Upload = v
	}
	if v, ok := conf["static"].(string); ok {
		cfg.Static = v
	}
	if v, ok := conf["defaults"].([]string); ok {
		cfg.Defaults = v
	}
	if v, ok := conf["setting"].(Map); ok {
		cfg.Setting = v
	}

	m.configs[name] = cfg
}

func (m *Module) ensureInstance(name string) *Instance {
	if name == "" {
		name = bamgoo.DEFAULT
	}
	inst, ok := m.instances[name]
	if ok {
		return inst
	}
	inst = &Instance{
		Name:     name,
		Config:   m.defaultConfig,
		Cross:    m.cross,
		Setting:  m.defaultConfig.Setting,
		routers:  make(map[string]Router, 0),
		filters:  make(map[string]Filter, 0),
		handlers: make(map[string]Handler, 0),
	}
	m.instances[name] = inst
	return inst
}

// Setup initializes defaults and instances.
func (m *Module) Setup() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.opened {
		return
	}

	names := map[string]struct{}{}

	// ensure instances for configs
	if len(m.configs) == 0 {
		m.configs[bamgoo.DEFAULT] = m.defaultConfig
	}
	for name, cfg := range m.configs {
		names[name] = struct{}{}
		inst := m.ensureInstance(name)
		inst.Config = mergeConfig(inst.Config, cfg)
		inst.Setting = inst.Config.Setting
		inst.Cross = m.cross
	}

	for key := range m.routers {
		instName, _ := splitPrefix(key)
		if instName != "*" {
			names[instName] = struct{}{}
		}
	}
	for key := range m.filters {
		instName, _ := splitPrefix(key)
		if instName != "*" {
			names[instName] = struct{}{}
		}
	}
	for key := range m.handlers {
		instName, _ := splitPrefix(key)
		if instName != "*" {
			names[instName] = struct{}{}
		}
	}

	if len(names) == 0 {
		names[bamgoo.DEFAULT] = struct{}{}
	}

	for name := range names {
		inst := m.ensureInstance(name)
		if cfg, ok := m.configs[name]; ok {
			inst.Config = mergeConfig(inst.Config, cfg)
		} else {
			inst.Config = mergeConfig(inst.Config, m.defaultConfig)
		}
		inst.Setting = inst.Config.Setting
		inst.Cross = m.cross

		inst.routers = make(map[string]Router, 0)
		inst.filters = make(map[string]Filter, 0)
		inst.handlers = make(map[string]Handler, 0)
	}

	for key, router := range m.routers {
		instName, routerName := splitPrefix(key)
		if instName == "*" {
			for _, inst := range m.instances {
				applyRouter(inst, routerName, router)
			}
			continue
		}
		inst := m.ensureInstance(instName)
		applyRouter(inst, routerName, router)
	}
	for key, filter := range m.filters {
		instName, filterName := splitPrefix(key)
		if instName == "*" {
			for _, inst := range m.instances {
				storeFilter(inst.filters, filterName, filter)
			}
			continue
		}
		inst := m.ensureInstance(instName)
		storeFilter(inst.filters, filterName, filter)
	}
	for key, handler := range m.handlers {
		instName, handlerName := splitPrefix(key)
		if instName == "*" {
			for _, inst := range m.instances {
				storeHandler(inst.handlers, handlerName, handler)
			}
			continue
		}
		inst := m.ensureInstance(instName)
		storeHandler(inst.handlers, handlerName, handler)
	}

	for _, inst := range m.instances {
		m.applyDefaults(inst)
		m.buildInstance(inst)
	}
}

func (m *Module) applyDefaults(inst *Instance) {
	if inst.Config.Port <= 0 || inst.Config.Port > 65535 {
		inst.Config.Port = 0
	}
	if inst.Config.Host == "" {
		inst.Config.Host = "0.0.0.0"
	}
	if inst.Config.Charset == "" {
		inst.Config.Charset = UTF8
	}
	if inst.Config.Defaults == nil || len(inst.Config.Defaults) == 0 {
		inst.Config.Defaults = []string{"index.html", "default.html"}
	}
	if inst.Config.Expire == 0 {
		inst.Config.Expire = time.Hour * 24 * 30
	}
	if inst.Config.MaxAge == 0 {
		inst.Config.MaxAge = time.Hour * 24 * 30
	}
}

func (m *Module) buildInstance(inst *Instance) {
	inst.routerInfos = make(map[string]Info, 0)
	for key, router := range inst.routers {
		for i, uri := range router.Uris {
			infoKey := key
			if i > 0 {
				infoKey = key + "." + string(rune('0'+i))
			}
			inst.routerInfos[infoKey] = Info{
				Method: router.Method,
				Uri:    uri,
				Router: key,
				Args:   router.Args,
			}
		}
	}

	inst.serveFilters = make([]ctxFunc, 0)
	inst.requestFilters = make([]ctxFunc, 0)
	inst.executeFilters = make([]ctxFunc, 0)
	inst.responseFilters = make([]ctxFunc, 0)

	for _, filter := range inst.filters {
		if filter.Serve != nil {
			inst.serveFilters = append(inst.serveFilters, filter.Serve)
		}
		if filter.Request != nil {
			inst.requestFilters = append(inst.requestFilters, filter.Request)
		}
		if filter.Execute != nil {
			inst.executeFilters = append(inst.executeFilters, filter.Execute)
		}
		if filter.Response != nil {
			inst.responseFilters = append(inst.responseFilters, filter.Response)
		}
	}

	inst.foundHandlers = make([]ctxFunc, 0)
	inst.errorHandlers = make([]ctxFunc, 0)
	inst.failedHandlers = make([]ctxFunc, 0)
	inst.deniedHandlers = make([]ctxFunc, 0)

	for _, handler := range inst.handlers {
		if handler.Found != nil {
			inst.foundHandlers = append(inst.foundHandlers, handler.Found)
		}
		if handler.Error != nil {
			inst.errorHandlers = append(inst.errorHandlers, handler.Error)
		}
		if handler.Failed != nil {
			inst.failedHandlers = append(inst.failedHandlers, handler.Failed)
		}
		if handler.Denied != nil {
			inst.deniedHandlers = append(inst.deniedHandlers, handler.Denied)
		}
	}
}

func (m *Module) Open() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.opened {
		return
	}

	for name, inst := range m.instances {
		cfg := inst.Config
		driver := m.drivers[cfg.Driver]
		if driver == nil {
			panic("Invalid http driver: " + cfg.Driver)
		}

		inst.Name = name
		conn, err := driver.Connect(inst)
		if err != nil {
			panic("Failed to connect http: " + err.Error())
		}
		if err := conn.Open(); err != nil {
			panic("Failed to open http: " + err.Error())
		}

		for routeName, info := range inst.routerInfos {
			if err := conn.Register(routeName, info); err != nil {
				panic("Failed to register http route: " + err.Error())
			}
		}

		inst.connect = conn
	}

	m.opened = true
}

func (m *Module) Start() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.started {
		return
	}

	for _, inst := range m.instances {
		if inst.connect == nil {
			continue
		}
		if inst.Config.CertFile != "" && inst.Config.KeyFile != "" {
			_ = inst.connect.StartTLS(inst.Config.CertFile, inst.Config.KeyFile)
		} else {
			_ = inst.connect.Start()
		}
	}

	m.started = true
}

func (m *Module) Stop() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if !m.started {
		return
	}
	m.started = false
}

func (m *Module) Close() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if !m.opened {
		return
	}

	for _, inst := range m.instances {
		if inst.connect != nil {
			_ = inst.connect.Close()
			inst.connect = nil
		}
	}

	m.opened = false
}

func parseDuration(val Any) time.Duration {
	switch v := val.(type) {
	case time.Duration:
		return v
	case int:
		return time.Second * time.Duration(v)
	case int64:
		return time.Second * time.Duration(v)
	case float64:
		return time.Second * time.Duration(v)
	case string:
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return 0
}

func mergeConfig(baseCfg, newCfg Config) Config {
	out := baseCfg
	if newCfg.Driver != "" {
		out.Driver = newCfg.Driver
	}
	if newCfg.Port != 0 {
		out.Port = newCfg.Port
	}
	if newCfg.Host != "" {
		out.Host = newCfg.Host
	}
	if newCfg.Domain != "" {
		out.Domain = newCfg.Domain
	}
	if newCfg.CertFile != "" {
		out.CertFile = newCfg.CertFile
	}
	if newCfg.KeyFile != "" {
		out.KeyFile = newCfg.KeyFile
	}
	if newCfg.Charset != "" {
		out.Charset = newCfg.Charset
	}
	if newCfg.Cookie != "" {
		out.Cookie = newCfg.Cookie
	}
	if newCfg.Token {
		out.Token = true
	}
	if newCfg.Expire != 0 {
		out.Expire = newCfg.Expire
	}
	if newCfg.Crypto {
		out.Crypto = true
	}
	if newCfg.MaxAge != 0 {
		out.MaxAge = newCfg.MaxAge
	}
	if newCfg.HttpOnly {
		out.HttpOnly = true
	}
	if newCfg.Upload != "" {
		out.Upload = newCfg.Upload
	}
	if newCfg.Static != "" {
		out.Static = newCfg.Static
	}
	if newCfg.Defaults != nil && len(newCfg.Defaults) > 0 {
		out.Defaults = newCfg.Defaults
	}
	if newCfg.Setting != nil {
		out.Setting = newCfg.Setting
	}
	return out
}

func splitPrefix(name string) (string, string) {
	name = strings.ToLower(name)
	if name == "" {
		return bamgoo.DEFAULT, ""
	}
	if strings.Contains(name, ".") {
		parts := strings.SplitN(name, ".", 2)
		return parts[0], parts[1]
	}
	return bamgoo.DEFAULT, name
}
