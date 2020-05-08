package auth

import (
	"context"
	"log"
	"time"
)

func SendEmail(recipient, subject, body string) error {
	message := mg.NewMessage(mailgunSender, subject, body, recipient)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// Send the message with a 10 second timeout
	resp, id, err := mg.Send(ctx, message)

	if err != nil {
		return err
	}
	log.Printf("ID: %s Resp: %s\n", id, resp)
	return nil
}
