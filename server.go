package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/textproto"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

const (
	ConstFrame byte = 0x0 // 0x0 denotes a continuation frame
	TextFrame  byte = 0x1 // 0x1 denotes a text frame
	BinFrame   byte = 0x2 // 0x2 denotes a binary frame
	CloseFrame byte = 0x8 // 0x8 denotes a connection close
	PingFrame  byte = 0x9 // 0x9 denotes a ping
	PongFrame  byte = 0xA // 0xA denotes a pong
)

// WebSockConn ...
// ...
type WebSockConn struct {
	Conn   net.Conn
	Buffer *bufio.Writer
	UserId string
}

//	WebSockConn ...
//	...
var clients []WebSockConn

// RawMessage ...
// ...
type RawMessage struct {
	Fin    byte
	Data   []byte
	OpCode byte
}

// Message ...
// ...
type Message struct {
	SenderID string
	Sender   string
	Message  string
	Date     time.Time
	RecvID   string
	Type     byte
}

// GetMsg ...
// ...
func (m Message) GetMsg() []byte {
	return []byte(m.Message)
}

// DB ...
// ...
var DB *sql.DB

// Settings ...
// ...
type Settings struct {
	DB DBSettings
}

// DBSettings ...
//
type DBSettings struct {
	User     string
	Password string
	DBName   string
	Host     string
}

// GetDSN ...
//
func (s Settings) GetDSN() string {
	return s.DB.User +
		":" +
		s.DB.Password +
		fmt.Sprintf("@tcp(%s)/", s.DB.Host) +
		s.DB.DBName +
		"?charset=utf8"
}

// Init ...
//
func (s *Settings) Init() error {
	fSet, err := os.Open("config/settings.json")
	if err != nil {
		return err
	}
	err = json.NewDecoder(fSet).Decode(s)
	if err != nil {
		return err
	}
	return nil
}

//	encodeWebSockMsg
//
func encodeWebSockMsg(msg *Message) ([]byte, error) {
	msgLen := len(msg.Message)
	encodedMsg := new(bytes.Buffer)

	// Размер заголовка фрейма с размером сообщения до 125 байт
	var frameHeaderSize byte = 0x02

	// ставим признак, что отправляем управляющий фрейм о закрытии соединения
	if msgLen > 0x7D && msgLen <= 0xFFFF {
		frameHeaderSize += 2

	} else if msgLen > 0xFFFF {
		frameHeaderSize += 8

	}
	header := make([]byte, frameHeaderSize)
	// Проставляем в заголовок фрейма требуемый тип фрейма
	header[0] = 0x80 | (msg.Type & 0x0F)
	if msgLen == 0 {
		header[1] = 0
		encodedMsg.Write(header)
	} else {
		if msgLen <= 125 {
			header[1] = byte(msgLen)
		} else if msgLen <= 0xFFFF {
			header[1] = 126
			binary.BigEndian.PutUint16(header[2:], uint16(msgLen))
		} else if msgLen > 0xFFFF {
			header[1] = 127
			binary.BigEndian.PutUint64(header[2:], uint64(msgLen))
		}
		encodedMsg.Write(header)
		encodedMsg.Write(msg.GetMsg())
	}
	return encodedMsg.Bytes(), nil
}

//	decodeWebSockMsg
//
func decodeWebSockMsg(conn *bufio.Reader) (*Message, error) {
	rwMsg, err := decoreRawMessage(conn)
	if err != nil {
		return nil, err
	}
	message, err := ParseMessage(rwMsg)
	if err != nil {
		return nil, err
	}
	return message, nil
}

//	ParseMessage
//
//	Функция перекодировки ровно одного фрейма сообщения
func ParseMessage(rwMsg *RawMessage) (*Message, error) {
	var message = new(Message)
	err := json.Unmarshal(rwMsg.Data, message)
	message.Type = rwMsg.OpCode
	if err != nil {
		return nil, err
	}
	return message, nil
}

//	decoreRawMessage
//
//	Функция перекодировки ровно одного фрейма сообщения

func decoreRawMessage(data *bufio.Reader) (*RawMessage, error) {
	var payLoadLen uint64
	var isMasked byte
	var payLoadLenMarker byte
	var decodedMsg []byte
	rwMsg := new(RawMessage)
	key := make([]byte, 4)

	flags, err := data.ReadByte()
	if err != nil {
		return nil, err
	}
	rwMsg.Fin = flags & 0x80
	rwMsg.OpCode = flags & 0x0F
	if rwMsg.OpCode == 0x1 && rwMsg.Fin == 0x0 {
		for rwMsg.Fin == 0x0 {
			// Считываем следующий байт
			flags, err = data.ReadByte()
			if err != nil {
				return nil, err
			}
			isMasked = flags & 0x80
			if isMasked == 0x0 {
				return nil, errors.New("the frame is not masked")
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
				_, err = data.Read(buf)
				if err != nil {
					return nil, err
				}
				payLoadLen = uint64(binary.BigEndian.Uint16(buf))
			} else if payLoadLenMarker == 127 {
				buf := make([]byte, 8)
				_, err = data.Read(buf)
				if err != nil {
					return nil, err
				}
				payLoadLen = binary.BigEndian.Uint64(buf)

			}
			keySize, err := data.Read(key)
			if err != nil || keySize < 4 {
				return nil, errors.New("error during mask reading")
			}
			if binary.BigEndian.Uint32(key) == 0 {
				return nil, errors.New("undefined mask")
			}
			decodedMsg = make([]byte, payLoadLen)
			msgWriter := new(bytes.Buffer)
			realPayLoadLen, err := io.CopyN(msgWriter, data, int64(payLoadLen))
			if err != nil {
				return nil, errors.New(fmt.Sprintf("error during data reading, read only %d bytes\n", realPayLoadLen))
			}
			// Перекодировка содержимого пакета
			for i, b := range msgWriter.Bytes() {
				decodedMsg[i] = b ^ key[i%4]
			}
			rwMsg.Data = append(rwMsg.Data, decodedMsg...)
		}
	}
	return rwMsg, nil
}

// GenerateToken
//
func GenerateToken(data string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(data), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(hash), nil
}

// handShake ...
//
func handShake(buffer *bufio.ReadWriter) (string, error) {
	var UserToken string
	_, _, err := buffer.ReadLine()
	if err != nil {
		return "", err
	}
	tpReader := textproto.NewReader(buffer.Reader)
	httpHeaderMap, err := tpReader.ReadMIMEHeader()
	if err != nil {
		return "", err
	}
	secWebSocketKey := httpHeaderMap.Get("Sec-WebSocket-Key")
	if len(secWebSocketKey) == 0 {
		return "", nil
	}
	UserCreds := httpHeaderMap.Get("Autorization")
	if len(UserCreds) == 0 {
		return "", nil
	}
	fmt.Println(UserCreds)
	const webSocketMagicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(secWebSocketKey + webSocketMagicString))
	bWebSocketAccept := h.Sum([]byte{})
	webSocketAccept := base64.StdEncoding.EncodeToString(bWebSocketAccept)
	response := "HTTP/1.1 101 Switching Protocols\r\n"
	response += "Upgrade: websocket\r\n"
	response += "Connection: Upgrade\r\n"
	response += "Sec-WebSocket-Version: 13\r\n"
	response += "Sec-WebSocket-Accept: %s\r\n\r\n"
	response = fmt.Sprintf(response, webSocketAccept)
	UserToken, err = GenerateToken(UserCreds)
	if err != nil {
		return "", err
	}
	_, err = buffer.Write([]byte(response))
	if err != nil {
		return "", err
	}
	return UserToken, nil
}

// Ping ...
//
func Ping(w *bufio.ReadWriter) error {
	return nil
}

// Pong ...
//
func Pong(w *bufio.ReadWriter) error {
	return nil
}

// CloseConn ...
//
func CloseConn(c net.Conn, b []byte) error {
	msg := &Message{Type: CloseFrame, Message: string(b)}
	encodedMsg, err := encodeWebSockMsg(msg)
	if err != nil {
		return err
	}
	n, err := c.Write(encodedMsg)
	if err != nil || n < len(b) {
		return err
	}
	err = c.Close()
	if err != nil {
		return err
	}
	return nil
}
func saveUserToDB(db *sql.DB, UserToken string) error {
	var storedUserToken string
	stmtIns, err := db.Prepare("SELECT id FROM user WHERE token = ?")
	if err != nil {
		return err
	}
	row := stmtIns.QueryRow(UserToken)
	err = row.Scan(storedUserToken)
	if err == sql.ErrNoRows {
		stmtIns, err = db.Prepare("INSERT INTO user VALUES(NULL, ?, ? ,?)")
		if err != nil {
			return err
		}
		md5Hasher := md5.New()
		_, err = md5Hasher.Write([]byte(UserToken))
		if err != nil {
			return err
		}
		_, err = stmtIns.Exec("test", "test", string(md5Hasher.Sum([]byte{})))
		if err != nil {
			return err
		}
	}
	stmtIns.Close()
	return nil
}

// findClient ...
//
func findClient(recvID string, clients []WebSockConn) ([]WebSockConn, error) {
	var recvConns []WebSockConn
	for _, conn := range clients {
		if conn.UserId == recvID {
			recvConns = append(recvConns, conn)
		}
	}
	return recvConns, nil
}

// BroadCastOnDisconnect todo
//
// todo
func BroadCastOnDisconnect(senderID string, clients []WebSockConn) error {
	var indexToDel int
	for i, cl := range clients {
		if cl.UserId == senderID {
			indexToDel = i
			continue
		}
		msg := &Message{SenderID: "server", Message: "Client has disconnected", Type: TextFrame, Date: time.Now()}
		b, err := encodeWebSockMsg(msg)
		if err != nil {
			return err
		}
		cl.Buffer.Write(b)
	}
	clients[indexToDel] = clients[len(clients)-1]
	clients[len(clients)-1] = WebSockConn{}
	clients = clients[:len(clients)-1]
	return nil
}

//	handleConnection todo
//	todo
func handleConnection(c net.Conn, db *sql.DB, clients []WebSockConn) {
	buffer := bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
	UserToken, err := handShake(buffer)
	fmt.Println(UserToken)
	if err != nil {
		log.Fatalf("Error occured: %v", err)

	} else if len(UserToken) == 0 && err == nil {
		c.Close()
		return
	}
	clients = append(clients, WebSockConn{c, buffer.Writer, UserToken})

	err = saveUserToDB(db, UserToken)
	if err != nil {
		log.Fatalf("Error occured: %v", err)
	}
	for {
		msg, err := decodeWebSockMsg(buffer.Reader)
		if err != nil {
			log.Fatalf("Error occured: %v", err)
		}
		// Если клиент закрыл связь
		if msg.Type == CloseFrame {
			err = CloseConn(c, msg.GetMsg())
			if err != nil {
				log.Fatalf("Error occured: %v", err)
			}
			err = BroadCastOnDisconnect(msg.SenderID, clients)
			if err != nil {
				log.Fatalf("Error occured: %v", err)
			}
			break
		}
		recvConns, err := findClient(msg.RecvID, clients)
		if err != nil {
			log.Fatalf("Error occured: %v", err)
		}
		for _, recvConn := range recvConns {
			_, err = recvConn.Conn.Write(msg.GetMsg())
			if err != nil {
				log.Fatalf("Error occured: %v", err)
			}
		}

	}
}
func main() {
	clients = make([]WebSockConn, 10)
	// listen on a port
	settings := new(Settings)
	settings.Init()

	DB, err := sql.Open("mysql", settings.GetDSN())
	defer DB.Close()
	if err != nil {
		log.Fatalf("Error occured: %s", err.Error())
		return
	}
	ln, err := net.Listen("tcp", ":5555")
	if err != nil {
		log.Fatalf("Error occured: %s", err.Error())
		return
	}
	for {
		// accept a connection
		c, err := ln.Accept()
		fmt.Println("Accepted ...")
		if err != nil {
			log.Fatalf("Error occured: %s", err.Error())
			continue
		}
		go handleConnection(c, DB, clients)
	}
}
