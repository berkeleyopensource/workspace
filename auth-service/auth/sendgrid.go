package auth

import (
	"os"
	"log"
	"github.com/joho/godotenv"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"bytes"
	"html/template"
)

var (
	sendgridKey    string
	sendgridClient *sendgrid.Client
	defaultSender  = mail.NewEmail("Workspace Bot", "noreply@projectbot.arifulrigan.com")
	defaultAPI     = "api.arifulrigan.com"
	defaultScheme  = "http"
)

func init() {
	// Load sendgrid credentials
	err := godotenv.Load()
	if err != nil {
		log.Print(err.Error())
	}
	sendgridKey = os.Getenv("SENDGRID_KEY")
	sendgridClient = sendgrid.NewSendClient(sendgridKey)	
}

func SendEmail(recipient string, subject string, templatePath string, data map[string]interface{}) error {
	// Parse template file and execute with data.
	var html bytes.Buffer
	tmpl, err := template.ParseFiles("./auth/templates/" + templatePath)
	if err != nil {
		return err
	}
	tmpl.Execute(&html, data)

	recipientEmail := mail.NewEmail("recipient", recipient)
	plainTextContent := html.String()

	// Construct and send email via Sendgrid.
	message := mail.NewSingleEmail(defaultSender, subject, recipientEmail, plainTextContent, html.String())
	response, err := sendgridClient.Send(message)
	if err != nil {
		return err
	} else {
		log.Println(response.StatusCode)
	}
	return nil
}
