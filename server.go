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

// Тип Ошибки
type Error string

func (e Error) Error() string {
	return string(e)
}

const (
	ConstFrame byte = 0x0 // 0x0 обозначает фрейм настроек
	TextFrame  byte = 0x1 // 0x1 обозначает текстовый фрейм
	BinFrame   byte = 0x2 // 0x2 обозначает двоичный фрейм
	CloseFrame byte = 0x8 // 0x8 обозначание фрейма-сигнала о закрытии подключения одной из сторон
	PingFrame  byte = 0x9 // 0x9 обозначание фрейма типа Пинг (проверка соединения одной из сторон)
	PongFrame  byte = 0xA // 0xA обозначание фрейма типа Понг (ответ на фрейм типа Пинг)
)
const (
	ErrNoOutputData           Error = "нет данных для отправки"
	InValidControlFrameLength Error = "неверный размер управляющего фрейма"
)

var DefaultFrameMaxSize int = 0x200 // максимальный размер фрейма по умолчанию - 512 байт

// Stream Буферизованный ввод-вывод по протоколу WebSockets
type Stream struct {
	c   net.Conn
	buf *bufio.ReadWriter
}

//  Message Фрагмент данных протокола WebSockets
type Message struct {
	opCode byte
	data   []byte
}

//	Encode кодирует фрейм для отправки по сети
func (m Message) Encode() ([]byte, error) {
	var frameHeaderSize byte
	var frameData []byte
	// Размер данных всего сообщения
	msgDataLen := len(m.data)
	if msgDataLen == 0 {
		return nil, ErrNoOutputData
	}
	// Создаем продвинутую версию динамического массива
	// байтов для хранения нашего закодированного сообщения
	buf := new(bytes.Buffer)
	totalFrames := msgDataLen/DefaultFrameMaxSize + 1
	curFrameNumber := 0
	// Размер данных во всех типах управляющих фреймов должен быть не более 125 байт
	if m.opCode == PingFrame || m.opCode == PongFrame || m.opCode == CloseFrame {
		if totalFrames > 1 {
			return nil, InValidControlFrameLength
		}
	}
	for curFrameNumber <= totalFrames {
		if curFrameNumber == totalFrames {
			frameData = m.data[curFrameNumber*DefaultFrameMaxSize:]
		} else {
			frameData = m.data[curFrameNumber*DefaultFrameMaxSize : (curFrameNumber+1)*DefaultFrameMaxSize]
		}
		frameDataSize := len(frameData)
		// Размер заголовка фрейма с размером сообщения до 125 байт
		frameHeaderSize = 0x02
		// Размер заголовка фрейма с размером сообщения от 125 до 65535 байт
		if frameDataSize > 0x7D && frameDataSize <= 0xFFFF {
			frameHeaderSize += 2
		} else if frameDataSize > 0xFFFF {
			frameHeaderSize += 8
		}
		frameHeader := make([]byte, frameHeaderSize)
		// Проставляем в нужные позиции биты, соответствующие требуемому типу фрейма
		frameHeader[0] = 0x80 | (m.opCode & 0x0F)
		// Проставляем в заголовок идентификатор диапазона размера данных в
		// фрейме и фактический размер фрейма в порядке следования байтов BigEndian
		if frameDataSize <= 125 {
			frameHeader[1] = byte(frameDataSize)
		} else if frameDataSize <= 0xFFFF {
			frameHeader[1] = 126
			binary.BigEndian.PutUint16(frameHeader[2:], uint16(frameDataSize))
		} else if frameDataSize > 0xFFFF {
			frameHeader[1] = 127
			binary.BigEndian.PutUint64(frameHeader[2:], uint64(frameDataSize))
		}
		buf.Write(frameHeader)
		buf.Write(frameData)
		curFrameNumber++
	}
	return buf.Bytes(), nil
}

// Send отправка фреймами сообщения в поток
func (s *Stream) Send(m *Message) error {
	data, err := m.Encode()
	if err != nil {
		return err
	}
	_, err = s.buf.Write(data)
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
	finBit := flags & 0x80
	m.opCode = flags & 0x0F
	if m.opCode == 0x1 && finBit == 0x0 {
		for finBit == 0x0 {
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

// handShake сетевое "рукопожатие" по протоколу WebSockets
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

// Ping Отправка сообщения типа Пинг
// Может быть вставлен между посылками фреймов других сообщений
func (s *Stream) Ping() error {
	m := &Message{opCode: PingFrame, data: nil}
	return s.Send(m)
}

// Pong Отправка сообщения типа Понг
// Может быть вставлен между посылками фреймов других сообщений
func (s *Stream) Pong() error {
	m := &Message{opCode: PongFrame, data: nil}
	return s.Send(m)
}

// Close закрытие потока
// Может быть вставлен между посылками фреймов других сообщений
func (s *Stream) Close() error {
	m := &Message{opCode: CloseFrame, data: nil}
	return s.Send(m)
}

// BroadCast отправка сообщения всем имеющимся подключениям (широковещательный запрос)
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

// NewStream Подключение нового клиента,
// создание на основе подключения обертки типа Stream
func NewStream(c net.Conn) (*Stream, error) {
	s := &Stream{buf: bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c)), c: c}
	err := s.handShake()
	return s, err
}
