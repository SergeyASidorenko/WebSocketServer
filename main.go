package main

import (
	"log"
	"net"
	"websocket/chat"
)

func main() {
	s := new(Settings)
	err := s.Init()
	if err != nil {
		log.Panicf("ошибка: %v", err.Error())
	}
	ln, err := net.Listen("tcp", s.Host)
	if err != nil {
		log.Panicf("ошибка: %v", err.Error())
	}
	chat := chat.CreateAndRunChat()
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Panicf("ошибка: %v", err.Error())
		}
		chat.AddClient(conn)
	}
}
