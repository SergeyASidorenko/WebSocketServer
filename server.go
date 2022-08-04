package websocket

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

const (
	ConstFrame byte = 0x0 // 0x0 обозначает фрейм настроек
	TextFrame  byte = 0x1 // 0x1 обозначает текстовый фрейм
	BinFrame   byte = 0x2 // 0x2 обозначает двоичный rame
	CloseFrame byte = 0x8 // 0x8 обозначание фрейма-сигнала о закрытии подключения одной из сторон
	PingFrame  byte = 0x9 // 0x9 обозначание фрейма типа Пинг (проверка соединения одной из сторон)
	PongFrame  byte = 0xA // 0xA обозначание фрейма типа Понг (ответ на фрейм типа Пинг)
)

// Stream ...
type Stream struct {
	c   net.Conn
	buf *bufio.ReadWriter
}

//  Фрагмент данных протокола WebSockets
type Message struct {
	fin    byte
	opCode byte
	data   []byte
}

//	Encode кодирует фрейм для отправки по сети
func (m Message) Encode() ([]byte, error) {
	msgLen := len(m.data)
	encodedMsg := new(bytes.Buffer)

	// Размер заголовка фрейма с размером сообщения до 125 байт
	var frameHeaderSize byte = 0x02

	// Размер заголовка фрейма с размером сообщения от 125 до 65535 байт
	if msgLen > 0x7D && msgLen <= 0xFFFF {
		frameHeaderSize += 2
	} else if msgLen > 0xFFFF {
		frameHeaderSize += 8
	}
	frameHeader := make([]byte, frameHeaderSize)
	// Проставляем в заголовок фрейма требуемый тип фрейма
	frameHeader[0] = 0x80 | (m.opCode & 0x0F)
	// Проставляем в заголовок идентификатор диапазона размера данных в
	// фрейме и фактический размер фрейма в кодировке BigEndian
	if msgLen == 0 {
		frameHeader[1] = 0
		encodedMsg.Write(frameHeader)
	} else {
		if msgLen <= 125 {
			frameHeader[1] = byte(msgLen)
		} else if msgLen <= 0xFFFF {
			frameHeader[1] = 126
			binary.BigEndian.PutUint16(frameHeader[2:], uint16(msgLen))
		} else if msgLen > 0xFFFF {
			frameHeader[1] = 127
			binary.BigEndian.PutUint64(frameHeader[2:], uint64(msgLen))
		}
		encodedMsg.Write(frameHeader)
		encodedMsg.Write(m.data)
	}
	return encodedMsg.Bytes(), nil
}

// SendMessage
func (s *Stream) Send(m *Message) error {
	_, err := s.buf.Write(m.data)
	return err
}

//	Decode декодирует полное сообщение, полученное из потока
func (s *Stream) Get() (*Message, error) {
	var payLoadLen uint64
	var isMasked byte
	var payLoadLenMarker byte
	var data []byte
	m := new(Message)
	key := make([]byte, 4)
	flags, err := s.buf.ReadByte()
	if err != nil {
		return nil, err
	}
	m.fin = flags & 0x80
	m.opCode = flags & 0x0F
	if m.opCode == 0x1 && m.fin == 0x0 {
		for m.fin == 0x0 {
			// Считываем следующий байт
			flags, err = s.buf.ReadByte()
			if err != nil {
				return nil, err
			}
			isMasked = flags & 0x80
			if isMasked == 0x0 {
				return nil, errors.New("фрейм сообщения не содержит маски")
			}
			// Считываем длину содержимого пакета
			payLoadLenMarker = flags & 0x7F
			// Если содержимого нет - выходим из функции
			if payLoadLenMarker == 0x0 {
				return nil, nil
			}
			payLoadLen = uint64(payLoadLenMarker)
			if payLoadLenMarker == 126 {
				buf := make([]byte, 2)
				_, err = s.buf.Read(buf)
				if err != nil {
					return nil, err
				}
				payLoadLen = uint64(binary.BigEndian.Uint16(buf))
			} else if payLoadLenMarker == 127 {
				buf := make([]byte, 8)
				_, err = s.buf.Read(buf)
				if err != nil {
					return nil, err
				}
				payLoadLen = binary.BigEndian.Uint64(buf)

			}
			keySize, err := s.buf.Read(key)
			if err != nil || keySize < 4 {
				return nil, errors.New("ошибка при чтении маски")
			}
			if binary.BigEndian.Uint32(key) == 0 {
				return nil, errors.New("неизвестный тип маски")
			}
			data = make([]byte, payLoadLen)
			msgWriter := new(bytes.Buffer)
			realPayLoadLen, err := io.CopyN(msgWriter, s.buf, int64(payLoadLen))
			if err != nil {
				return nil, fmt.Errorf("ошибка чтения данных, прочитано только %d байт", realPayLoadLen)
			}
			// Перекодировка содержимого пакета
			for i, b := range msgWriter.Bytes() {
				data[i] = b ^ key[i%4]
			}
			m.data = append(m.data, data...)
		}
	}
	return m, nil
}

// HashPassword
func HashPassword(data string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(data), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(hash), nil
}

// handShake ...
func (s *Stream) handShake() error {
	_, _, err := s.buf.ReadLine()
	if err != nil {
		return err
	}
	tpReader := textproto.NewReader(s.buf.Reader)
	httpHeaderMap, err := tpReader.ReadMIMEHeader()
	if err != nil {
		return err
	}
	secWebSocketKey := httpHeaderMap.Get("Sec-WebSocket-Key")
	if len(secWebSocketKey) == 0 {
		return nil
	}
	UserCreds := httpHeaderMap.Get("Autorization")
	if len(UserCreds) == 0 {
		return nil
	}
	fmt.Println(UserCreds)
	const webSocketMagicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(secWebSocketKey + webSocketMagicString))
	bWebSocketAccept := h.Sum([]byte{})
	webSocketAccept := base64.StdEncoding.EncodeToString(bWebSocketAccept)
	response := "HTTP/1.1 101 Switching Protocols\r\n"
	response += "Upgrade: websocket\r\n"
	response += "Streamection: Upgrade\r\n"
	response += "Sec-WebSocket-Version: 13\r\n"
	response += "Sec-WebSocket-Accept: %s\r\n\r\n"
	response = fmt.Sprintf(response, webSocketAccept)
	_, err = s.buf.Write([]byte(response))
	if err != nil {
		return err
	}
	return nil
}

// Ping ...
func (s *Stream) Ping() error {
	m := &Message{fin: 1, opCode: PingFrame, data: nil}
	return s.Send(m)
}

// Pong ...
func (s *Stream) Pong() error {
	m := &Message{fin: 1, opCode: PongFrame, data: nil}
	return s.Send(m)
}

// CloseStream ...
func (s *Stream) Close() error {
	m := &Message{fin: 1, opCode: CloseFrame, data: nil}
	return s.Send(m)
}

// BroadCast
func BroadCast(m *Message) error {
	var clients []Stream
	for _, client := range clients {
		err := client.Send(m)
		if err != nil {
			return err
		}
	}
	return nil
}

// NewStream Подключение нового клиента
func NewStream(c net.Conn) (*Stream, error) {
	s := &Stream{buf: bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c)), c: c}
	err := s.handShake()
	return s, err
}
