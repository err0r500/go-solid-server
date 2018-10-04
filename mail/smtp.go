package mail

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/mail"
	"net/smtp"
	"strconv"

	"github.com/err0r500/go-solid-server/uc"
)

// fixme set config
func New() uc.Mailer {
	return smtpMailer{}
}

type smtpMailer struct {
	config emailConfig
}

type emailStruct struct {
	To       string
	ToName   string
	From     string
	FromName string
	Subject  string
	Body     string
}

// emailConfig holds configuration values for remote SMTP servers
type emailConfig struct {
	// Name of the remote SMTP server account, i.e. Server admin
	Name string
	// Addr is the remote SMTP server email address, i.e. admin@server.org
	Addr string
	// User is the remote SMTP server username, i.e. admin
	User string
	// Pass is the remote SMTP server password
	Pass string
	// Host is the remote SMTP server IP address or domain
	Host string
	// Port is the remote SMTP server port number
	Port int
	// ForceSSL forces SSL/TLS connection instead of StartTLS
	ForceSSL bool
	// Insecure allows connections to insecure remote SMTP servers (self-signed certs)
	Insecure bool
}

func NewEmailStruct() *emailStruct {
	return &emailStruct{}
}

func (s smtpMailer) SendWelcomeMail(params map[string]string) {
	email := NewEmailStruct()
	email.To = params["{{.To}}"]
	email.ToName = params["{{.Name}}"]
	email.From = params["{{.From}}"]
	email.FromName = "Notifications Service"
	email.Subject = "Welcome to " + params["{{.Host}}"] + "!"
	email.Body = Welcome()

	s.sendMail(email)
}

func (s smtpMailer) SendRecoveryMail(params map[string]string) {
	email := NewEmailStruct()
	email.To = params["{{.To}}"]
	email.ToName = params["{{.Name}}"]
	email.From = params["{{.From}}"]
	email.FromName = "Account Recovery"
	email.Subject = "Recovery instructions for your account on " + params["{{.Host}}"]
	email.Body = AccountRecovery()

	s.sendMail(email)
}

// should be run in a go routine
func (s smtpMailer) sendMail(email *emailStruct) {
	auth := smtp.PlainAuth("",
		s.config.User,
		s.config.Pass,
		s.config.Host,
	)

	// Setup headers
	src := mail.Address{Name: email.FromName, Address: email.From}
	dst := mail.Address{Name: email.ToName, Address: email.To}
	headers := make(map[string]string)
	headers["From"] = src.String()
	headers["To"] = dst.String()
	headers["Subject"] = email.Subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=\"utf-8\""

	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + email.Body

	if len(s.config.Host) > 0 && s.config.Port > 0 && auth != nil {
		smtpServer := s.config.Host + ":" + strconv.Itoa(s.config.Port)
		var err error
		// force upgrade to full SSL/TLS connection
		if s.config.ForceSSL {
			err = s.sendSecureMail(src, dst, []byte(message))
		} else {
			err = smtp.SendMail(smtpServer, auth, s.config.Addr, []string{email.To}, []byte(message))
		}
		if err != nil {
			log.Println("Error sending recovery email to " + email.To + ": " + err.Error())
		} else {
			log.Println("Successfully sent recovery email to " + email.To)
		}
	} else {
		log.Println("Missing smtp server and/or port")
	}
}

func (s smtpMailer) sendSecureMail(from mail.Address, to mail.Address, msg []byte) (err error) {
	// Connect to the SMTP Server
	serverName := s.config.Host + ":" + strconv.Itoa(s.config.Port)
	auth := smtp.PlainAuth("", s.config.User, s.config.Pass, s.config.Host)

	// TLS config
	tlsconfig := &tls.Config{
		InsecureSkipVerify: s.config.Insecure,
		ServerName:         s.config.Host,
	}

	// Here is the key, you need to call tls.Dial instead of smtp.Dial
	// for smtp servers running on 465 that require an ssl connection
	// from the very beginning (no starttls)
	conn, err := tls.Dial("tcp", serverName, tlsconfig)
	if err != nil {
		log.Println(err.Error())
		return
	}
	defer conn.Close()

	c, err := smtp.NewClient(conn, s.config.Host)
	if err != nil {
		log.Println(err.Error())
		return
	}

	// Auth
	if err = c.Auth(auth); err != nil {
		log.Println(err.Error())
		return
	}

	// To && From
	if err = c.Mail(from.Address); err != nil {
		log.Println(err.Error())
		return
	}

	if err = c.Rcpt(to.Address); err != nil {
		log.Println(err.Error())
		return
	}

	// Data
	w, err := c.Data()
	if err != nil {
		log.Println(err.Error())
		return
	}

	_, err = w.Write(msg)
	if err != nil {
		log.Println(err.Error())
		return
	}

	err = w.Close()
	if err != nil {
		log.Println(err.Error())
		return
	}

	c.Quit()
	return nil
}

//func parseMailTemplate(tpl string, vals map[string]string) string {
//	body := SMTPTemplates[tpl]
//
//	for oVal, nVal := range vals {
//		body = strings.Replace(body, oVal, nVal, -1)
//	}
//	return body
//}
