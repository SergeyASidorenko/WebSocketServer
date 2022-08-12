package main

import (
	"log"
	"net"
	"websocket/server"
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
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Panicf("ошибка: %v", err.Error())
		}
		err = server.Handle(conn)
		if err != nil {
			log.Panicf("ошибка: %v", err.Error())
		}
	}
}
