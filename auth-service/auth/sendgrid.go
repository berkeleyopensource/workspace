package auth

import (
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"html/template"
	"bytes"
)

func SendEmail(recipient string, subject string, templatePath string, data map[string]interface{}) error {

	// Parse template file and execute with data.
	var html bytes.Buffer
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return err
	}
	tmpl.Execute(&html, data)

	recipientEmail := mail.NewEmail("recipient", recipient)
	plainTextContent := "Your password reset token is "

	// Construct and send email via Sendgrid.
	message := mail.NewSingleEmail(defaultSender, subject, recipientEmail, plainTextContent, html.String())
	response, err := sendgridClient.Send(message)
	if err != nil {
		return err
	}

	return nil
}
