package logger

import (
	"log"

	"github.com/err0r500/go-solid-server/uc"
)

type logger struct {
	debug *log.Logger
}

func New(log *log.Logger) uc.Debug {
	return logger{
		debug: log,
	}
}

func (l logger) Debug(v ...interface{}) {
	l.debug.Println(v)
}
