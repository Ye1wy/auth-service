package config

type Config interface {
	MustLoad()
}

type config struct {
}
