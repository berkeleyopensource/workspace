package auth

import (
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"log"
)

func SendEmail(recipient, subject, body string) error {

	recipientEmail := mail.NewEmail("recipient", recipient)
	htmlContent := "<p>" + body + "</p>"

	message := mail.NewSingleEmail(defaultSender, subject, recipientEmail, body, htmlContent)

	response, err := sendgridClient.Send(message)
	if err != nil {
		return err
	}

	log.Printf("Statuscode: %d, Response:%s", response.StatusCode, response.Body)
	return nil
}
