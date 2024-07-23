package socks5server

import (
	"bytes"
	"fmt"
	"testing"
)

func TestSecondMessage_Bytes(t *testing.T) {
	t.Run("test", func(t *testing.T) {
		buf := []byte{0x05, 0x01, 0x00, 0x01, 123, 123, 123, 80, 0x00, 0x50}
		r := bytes.NewBuffer(buf)
		message, err := builfSecondMessage(r)
		if err != nil {
			t.Fatal(err)
		}
		if message == nil {
			t.Fatal("message is nil")
		}
		fmt.Println(message)
		fmt.Println(message.Bytes())
	})
}
