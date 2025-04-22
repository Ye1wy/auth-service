package mailer

import (
	"auth-service/pkg/logger"

	"gopkg.in/gomail.v2"
)

type Mailer interface {
	SandText(to, subject, body string) error
}

type MailerConfig struct {
	SenderHost     string `env:"sender_host"`
	SenderUsername string `env:"sender_email"`
	SenderPassword string `env:"sender_password"`
	SenderPort     int    `env:"sender_port"`
}

type goMailer struct {
	cfg    *MailerConfig
	diller *gomail.Dialer
	logger *logger.Logger
}

func NewGoMailer(cfg *MailerConfig, logger *logger.Logger) *goMailer {
	d := gomail.NewDialer(cfg.SenderHost, cfg.SenderPort, cfg.SenderUsername, cfg.SenderPassword)
	return &goMailer{
		cfg:    cfg,
		diller: d,
		logger: logger,
	}
}

func (m *goMailer) SendText(to, subject, body string) error {
	msg := gomail.NewMessage()
	msg.SetHeader("From", m.cfg.SenderUsername)
	msg.SetHeader("To", to)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/plain", body)

	return m.diller.DialAndSend(msg)
}
