package main

import (
    "log"
    "github.com/Yscliking/ysla/socks5server"
    )

func main() {
    ip := "127.0.0.1"
    port := 1081

    server := socks5server.NewSocks5Server(ip, port)
    if err := server.Run(); err != nil {
        log.Fatalf("Failed to run SOCKS5 server: %v", err)
    }
}
