package chat

import (
	"io"
	"net"
	"os"
	"sync"
	"websocket/server"
)

var logger server.WebSocketLogger

// ChatLog Структура логирования
type ChatLog struct {
	w io.Writer
}

// Log - Регистрация сообщений-логов
func (l ChatLog) Log(msg string) error {
	_, err := l.w.Write([]byte(msg))
	return err
}

// InitLogger - Регистрация сообщений-логов
func InitLogger() error {
	f, err := os.OpenFile("chat.log", os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	logger = ChatLog{w: f}
	return nil
}

// Chat - структура чата
type Chat struct {
	clients  []*Client
	messages chan *server.Message
	m        sync.RWMutex
}

// CreateAndRunChat Создание мультипользовательского чата
func CreateAndRunChat() *Chat {
	InitLogger()
	chat := new(Chat)
	chat.clients = []*Client{}
	chat.m = sync.RWMutex{}
	chat.messages = make(chan *server.Message)
	chat.Run()
	return chat
}

// AddClient Добавление нового клиента к чату
func (chat *Chat) AddClient(c net.Conn) {
	client, err := CreateClient(c)
	if err != nil {
		logger.Log(err.Error())
		return
	}
	chat.m.Lock()
	chat.clients = append(chat.clients, client)
	chat.m.Unlock()
	go func() {
		for m := range client.Run() {
			chat.messages <- m
		}
	}()
}

// Run Запуск в работу чата
func (chat *Chat) Run() {
	go func() {
		for m := range chat.messages {
			for _, client := range chat.clients {
				client.ch <- m
			}
		}
	}()
}

// Client - клиент чата
type Client struct {
	s  *server.Stream
	ch chan *server.Message
}

// CreateClient Подключение нового клиента,
// создание на основе подключения обертки типа Stream
func CreateClient(c net.Conn) (*Client, error) {
	cl := new(Client)
	cl.s = server.CreateStream(c, logger)
	cl.ch = make(chan *server.Message)
	return cl, nil
}

// Run Запуск получения сообщений клиенту
func (cl *Client) Run() <-chan *server.Message {
	go func() {
		for m := range cl.ch {
			cl.s.Send(m)
		}
	}()
	return cl.s.Stream()
}
