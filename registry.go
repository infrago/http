package http

func (Router) RegistryComponent() string {
	return "http.router"
}

func (Filter) RegistryComponent() string {
	return "http.filter"
}

func (Handler) RegistryComponent() string {
	return "http.handler"
}
