package http

import (
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	. "github.com/infrago/base"
	"github.com/infrago/infra"
)

func init() {
	infra.Mount(module)
}

var module = &Module{
	defaultConfig: Config{Driver: DEFAULT, Charset: UTF8, Port: 8080},
	drivers:       make(map[string]Driver, 0),
	configs:       make(map[string]Config, 0),
	crosses:       make(map[string]Cross, 0),
	instances:     make(map[string]*Instance, 0),
	routers:       make(map[string]Router, 0),
	filters:       make(map[string]Filter, 0),
	handlers:      make(map[string]Handler, 0),
	endpoints:     make(map[string]Endpoint, 0),
}

func SetFS(fsys fs.FS) {
	infra.AssetFS(fsys)
}

type (
	Module struct {
		mutex sync.Mutex

		opened  bool
		started bool

		defaultConfig Config

		drivers   map[string]Driver
		configs   map[string]Config
		crosses   map[string]Cross
		instances map[string]*Instance

		routers   map[string]Router
		filters   map[string]Filter
		handlers  map[string]Handler
		endpoints map[string]Endpoint
	}

	Config struct {
		Driver  string
		Port    int
		Host    string
		Domain  string
		Require bool

		CertFile string
		KeyFile  string

		Charset string

		Cookie   string
		Token    bool
		Expire   time.Duration
		Crypto   bool
		MaxAge   time.Duration
		HttpOnly bool
		// AnswerDataEncode toggles ctx.Answer(data) payload encoding.
		AnswerDataEncode bool
		// AnswerDataCodec is codec name used by infra.Mapping Var.Encode.
		AnswerDataCodec string

		Upload   string
		Static   string
		Defaults []string

		Setting Map

		requireSet          bool
		tokenSet            bool
		cryptoSet           bool
		httpOnlySet         bool
		answerDataEncodeSet bool
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
		routerOrder []string

		serveFilters    []ctxFunc
		requestFilters  []ctxFunc
		executeFilters  []ctxFunc
		responseFilters []ctxFunc

		notFoundHandlers []ctxFunc
		errorHandlers    []ctxFunc
		failedHandlers   []ctxFunc
		unsignedHandlers []ctxFunc
		unauthedHandlers []ctxFunc
		deniedHandlers   []ctxFunc
	}
)

// Register dispatches registrations.
func (m *Module) Register(name string, value Any) {
	switch v := value.(type) {
	case Driver:
		m.RegisterDriver(name, v)
	case Config:
		m.RegisterConfig(name, v)
	case Configs:
		m.RegisterConfigs(v)
	case Router:
		m.RegisterRouter(name, v)
	case Routers:
		m.RegisterRouters(name, v)
	case Filter:
		m.RegisterFilter(name, v)
	case Handler:
		m.RegisterHandler(name, v)
	case Endpoint:
		m.RegisterEndpoint(name, v)
	}
}

// RegisterRouters registers multiple routers.
func (m *Module) RegisterRouters(prefix string, routers Routers) {
	for name, router := range routers {
		target := name
		if prefix != "" {
			target = prefix + "." + name
		}
		m.RegisterRouter(target, router)
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

	if infra.Override() {
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
		name = infra.DEFAULT
	}
	if infra.Override() {
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
		if conf, ok := httpMapValue(val); ok && key == "cross" {
			m.configureCross(infra.DEFAULT, conf)
		} else if conf, ok := httpMapValue(val); ok && key != "setting" {
			m.configure(key, conf)
		} else {
			rootConfig[key] = val
		}
	}
	if len(rootConfig) > 0 {
		m.configure(infra.DEFAULT, rootConfig)
	}
}

func (m *Module) configure(name string, conf Map) {
	if crossConf, ok := httpMapValue(conf["cross"]); ok && crossConf != nil {
		m.configureCross(name, crossConf)
	}

	cfg := m.defaultConfig
	if existing, ok := m.configs[name]; ok {
		cfg = existing
	}

	if v, ok := conf["driver"].(string); ok && v != "" {
		cfg.Driver = v
	}
	if port, ok := parsePort(conf["port"]); ok {
		cfg.Port = port
	}
	if v, ok := conf["host"].(string); ok {
		cfg.Host = v
	}
	if v, ok := conf["domain"].(string); ok {
		cfg.Domain = v
	}
	if v, ok := conf["require"].(bool); ok {
		cfg.Require = v
		cfg.requireSet = true
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
		cfg.tokenSet = true
	}
	if v, ok := conf["expire"]; ok {
		if d := parseDuration(v); d > 0 {
			cfg.Expire = d
		}
	}
	if v, ok := conf["crypto"].(bool); ok {
		cfg.Crypto = v
		cfg.cryptoSet = true
	}
	if v, ok := conf["maxage"]; ok {
		if d := parseDuration(v); d > 0 {
			cfg.MaxAge = d
		}
	}
	if v, ok := conf["httponly"].(bool); ok {
		cfg.HttpOnly = v
		cfg.httpOnlySet = true
	}
	if v, ok := conf["answerencode"].(bool); ok {
		cfg.AnswerDataEncode = v
		cfg.answerDataEncodeSet = true
	}
	if v, ok := conf["answer_encode"].(bool); ok {
		cfg.AnswerDataEncode = v
		cfg.answerDataEncodeSet = true
	}
	if v, ok := conf["answerdataencode"].(bool); ok {
		cfg.AnswerDataEncode = v
		cfg.answerDataEncodeSet = true
	}
	if v, ok := conf["answer_data_encode"].(bool); ok {
		cfg.AnswerDataEncode = v
		cfg.answerDataEncodeSet = true
	}
	if v, ok := conf["answercodec"].(string); ok {
		cfg.AnswerDataCodec = strings.TrimSpace(v)
	}
	if v, ok := conf["answer_codec"].(string); ok {
		cfg.AnswerDataCodec = strings.TrimSpace(v)
	}
	if v, ok := conf["answerdatacodec"].(string); ok {
		cfg.AnswerDataCodec = strings.TrimSpace(v)
	}
	if v, ok := conf["answer_data_codec"].(string); ok {
		cfg.AnswerDataCodec = strings.TrimSpace(v)
	}
	if v, ok := conf["codec"].(string); ok {
		cfg.AnswerDataCodec = strings.TrimSpace(v)
	}
	if answer, ok := conf["answer"].(Map); ok && answer != nil {
		if v, ok := answer["encode"].(bool); ok {
			cfg.AnswerDataEncode = v
			cfg.answerDataEncodeSet = true
		}
		if v, ok := answer["answerencode"].(bool); ok {
			cfg.AnswerDataEncode = v
			cfg.answerDataEncodeSet = true
		}
		if v, ok := answer["codec"].(string); ok {
			cfg.AnswerDataCodec = strings.TrimSpace(v)
		}
		if v, ok := answer["answercodec"].(string); ok {
			cfg.AnswerDataCodec = strings.TrimSpace(v)
		}
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

func (m *Module) configureCross(name string, conf Map) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		name = infra.DEFAULT
	}
	if m.crosses == nil {
		m.crosses = make(map[string]Cross, 0)
	}
	m.crosses[name] = mergeCross(m.crosses[name], conf)
}

func (m *Module) ensureInstance(name string) *Instance {
	if name == "" {
		name = infra.DEFAULT
	}
	inst, ok := m.instances[name]
	if ok {
		return inst
	}
	inst = &Instance{
		Name:     name,
		Config:   m.defaultConfig,
		Cross:    m.crosses[name],
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

	if len(m.configs) == 0 {
		m.configs[infra.DEFAULT] = m.defaultConfig
	}

	m.instances = make(map[string]*Instance, 0)

	instanceNames := map[string]struct{}{}
	for name := range m.configs {
		name = strings.ToLower(name)
		if name == "" {
			name = infra.DEFAULT
		}
		instanceNames[name] = struct{}{}
	}
	if len(instanceNames) == 0 {
		instanceNames[infra.DEFAULT] = struct{}{}
	}

	multiSite := false
	for name := range instanceNames {
		if name != infra.DEFAULT {
			multiSite = true
			break
		}
	}
	if !multiSite {
		// Single-site mode: everything goes to default instance.
		instanceNames = map[string]struct{}{infra.DEFAULT: {}}
	} else if m.needsDefaultInstance(instanceNames) {
		// Multi-site mode: create default instance only when there are non-scoped definitions.
		instanceNames[infra.DEFAULT] = struct{}{}
	}

	for name := range instanceNames {
		inst := m.ensureInstance(name)
		cfg := m.defaultConfig
		if c, ok := m.configs[name]; ok {
			cfg = mergeConfig(cfg, c)
		}
		inst.Config = cfg
		inst.Setting = inst.Config.Setting
		inst.Cross = m.crosses[name]
		inst.routers = make(map[string]Router, 0)
		inst.filters = make(map[string]Filter, 0)
		inst.handlers = make(map[string]Handler, 0)
	}

	for key, router := range m.routers {
		targets, routerName := bindName(key, instanceNames, multiSite)
		for _, target := range targets {
			if inst, ok := m.instances[target]; ok {
				applyRouter(inst, routerName, router)
			}
		}
	}
	for key, filter := range m.filters {
		targets, filterName := bindName(key, instanceNames, multiSite)
		for _, target := range targets {
			if inst, ok := m.instances[target]; ok {
				storeFilter(inst.filters, filterName, filter)
			}
		}
	}
	for key, handler := range m.handlers {
		targets, handlerName := bindName(key, instanceNames, multiSite)
		for _, target := range targets {
			if inst, ok := m.instances[target]; ok {
				storeHandler(inst.handlers, handlerName, handler)
			}
		}
	}

	for _, inst := range m.instances {
		m.applyDefaults(inst)
		m.buildInstance(inst)
	}

	active := make(map[string]*Instance, 0)
	for name, inst := range m.instances {
		if inst.Config.Require || len(inst.routerInfos) > 0 {
			active[name] = inst
		}
	}
	m.instances = active
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
	keys := make([]string, 0, len(inst.routers))
	for key := range inst.routers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		router := inst.routers[key]
		for i, uri := range router.Uris {
			infoKey := key
			if i > 0 {
				infoKey = key + "." + strconv.Itoa(i)
			}
			inst.routerInfos[infoKey] = Info{
				Method: router.method,
				Uri:    uri,
				Router: key,
				Entry:  router.Key,
				Args:   router.Args,
			}
		}
	}
	inst.routerOrder = make([]string, 0, len(inst.routerInfos))
	for key := range inst.routerInfos {
		inst.routerOrder = append(inst.routerOrder, key)
	}
	sort.SliceStable(inst.routerOrder, func(i, j int) bool {
		left := inst.routerInfos[inst.routerOrder[i]]
		right := inst.routerInfos[inst.routerOrder[j]]

		if left.Uri != right.Uri {
			return left.Uri < right.Uri
		}

		leftWeight := 1
		rightWeight := 1
		if left.Method != "" {
			leftWeight = 0
		}
		if right.Method != "" {
			rightWeight = 0
		}
		if leftWeight != rightWeight {
			return leftWeight < rightWeight
		}
		if left.Method != right.Method {
			return left.Method < right.Method
		}

		return inst.routerOrder[i] < inst.routerOrder[j]
	})

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

	inst.notFoundHandlers = make([]ctxFunc, 0)
	inst.errorHandlers = make([]ctxFunc, 0)
	inst.failedHandlers = make([]ctxFunc, 0)
	inst.unsignedHandlers = make([]ctxFunc, 0)
	inst.unauthedHandlers = make([]ctxFunc, 0)
	inst.deniedHandlers = make([]ctxFunc, 0)

	for _, handler := range inst.handlers {
		if handler.NotFound != nil {
			inst.notFoundHandlers = append(inst.notFoundHandlers, handler.NotFound)
		}
		if handler.Error != nil {
			inst.errorHandlers = append(inst.errorHandlers, handler.Error)
		}
		if handler.Failed != nil {
			inst.failedHandlers = append(inst.failedHandlers, handler.Failed)
		}
		if handler.Unsigned != nil {
			inst.unsignedHandlers = append(inst.unsignedHandlers, handler.Unsigned)
		}
		if handler.Unauthed != nil {
			inst.unauthedHandlers = append(inst.unauthedHandlers, handler.Unauthed)
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

		for _, routeName := range inst.routerOrder {
			info := inst.routerInfos[routeName]
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
	fmt.Printf("infrago http module is running with %d connections, %d routers.\n", len(m.instances), len(m.routers))
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

func httpMapValue(value Any) (Map, bool) {
	switch v := value.(type) {
	case Map:
		return v, v != nil
	default:
		return nil, false
	}
}

func parseStringList(val Any) []string {
	switch v := val.(type) {
	case nil:
		return nil
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []string:
		out := make([]string, 0, len(v))
		for _, s := range v {
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case []Any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func mergeCross(base Cross, conf Map) Cross {
	out := base

	if v, ok := conf["allow"].(bool); ok {
		out.Allow = v
	}
	if v, ok := conf["enable"].(bool); ok {
		out.Allow = v
	}
	if v, ok := conf["method"].(string); ok {
		out.Method = v
	}
	if vals := parseStringList(conf["methods"]); len(vals) > 0 {
		out.Methods = vals
	}
	if v, ok := conf["origin"].(string); ok {
		out.Origin = v
	}
	if vals := parseStringList(conf["origins"]); len(vals) > 0 {
		out.Origins = vals
	}
	if v, ok := conf["header"].(string); ok {
		out.Header = v
	}
	if vals := parseStringList(conf["headers"]); len(vals) > 0 {
		out.Headers = vals
	}

	return out
}

func parsePort(val Any) (int, bool) {
	switch v := val.(type) {
	case int:
		return v, true
	case int8:
		return int(v), true
	case int16:
		return int(v), true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	case uint:
		return int(v), true
	case uint8:
		return int(v), true
	case uint16:
		return int(v), true
	case uint32:
		return int(v), true
	case uint64:
		return int(v), true
	case float32:
		return int(v), true
	case float64:
		return int(v), true
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return 0, false
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
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
	if newCfg.requireSet {
		out.Require = newCfg.Require
		out.requireSet = true
	} else if newCfg.Require {
		out.Require = true
		out.requireSet = true
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
	if newCfg.tokenSet {
		out.Token = newCfg.Token
		out.tokenSet = true
	} else if newCfg.Token {
		out.Token = true
		out.tokenSet = true
	}
	if newCfg.Expire != 0 {
		out.Expire = newCfg.Expire
	}
	if newCfg.cryptoSet {
		out.Crypto = newCfg.Crypto
		out.cryptoSet = true
	} else if newCfg.Crypto {
		out.Crypto = true
		out.cryptoSet = true
	}
	if newCfg.MaxAge != 0 {
		out.MaxAge = newCfg.MaxAge
	}
	if newCfg.httpOnlySet {
		out.HttpOnly = newCfg.HttpOnly
		out.httpOnlySet = true
	} else if newCfg.HttpOnly {
		out.HttpOnly = true
		out.httpOnlySet = true
	}
	if newCfg.answerDataEncodeSet {
		out.AnswerDataEncode = newCfg.AnswerDataEncode
		out.answerDataEncodeSet = true
	} else if newCfg.AnswerDataEncode {
		out.AnswerDataEncode = true
		out.answerDataEncodeSet = true
	}
	if newCfg.AnswerDataCodec != "" {
		out.AnswerDataCodec = newCfg.AnswerDataCodec
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
		return infra.DEFAULT, ""
	}
	if strings.HasPrefix(name, ".") {
		return infra.DEFAULT, strings.TrimPrefix(name, ".")
	}
	if strings.Contains(name, ".") {
		parts := strings.SplitN(name, ".", 2)
		return parts[0], parts[1]
	}
	return infra.DEFAULT, name
}

func bindName(name string, instances map[string]struct{}, multiSite bool) ([]string, string) {
	name = strings.ToLower(name)
	if name == "" {
		return []string{infra.DEFAULT}, ""
	}

	if strings.HasPrefix(name, "*.") {
		targets := make([]string, 0, len(instances))
		for instName := range instances {
			targets = append(targets, instName)
		}
		return targets, strings.TrimPrefix(name, "*.")
	}

	if !multiSite {
		return []string{infra.DEFAULT}, name
	}

	prefix, rest := splitPrefix(name)
	if _, ok := instances[prefix]; ok && rest != "" {
		return []string{prefix}, rest
	}
	return []string{infra.DEFAULT}, name
}

func (m *Module) needsDefaultInstance(instances map[string]struct{}) bool {
	if _, ok := instances[infra.DEFAULT]; ok {
		return true
	}

	for key := range m.routers {
		if requireDefaultForName(key, instances) {
			return true
		}
	}
	for key := range m.filters {
		if requireDefaultForName(key, instances) {
			return true
		}
	}
	for key := range m.handlers {
		if requireDefaultForName(key, instances) {
			return true
		}
	}
	return false
}

func requireDefaultForName(name string, instances map[string]struct{}) bool {
	name = strings.ToLower(name)
	if name == "" || strings.HasPrefix(name, "*.") {
		return false
	}

	prefix, rest := splitPrefix(name)
	if rest == "" {
		return true
	}
	if _, ok := instances[prefix]; ok {
		return false
	}
	return true
}

func (m *Module) endpoint(name string) (Endpoint, bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if len(m.endpoints) == 0 {
		return Endpoint{}, false
	}

	if name == "" {
		name = infra.DEFAULT
	}
	name = strings.TrimSpace(strings.ToLower(name))

	endpoint, ok := m.endpoints[name]
	return endpoint, ok
}
