package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
)

var DB *sql.DB

// Settings Структура для хранения настроек сервера
type Settings struct {
	DB   DBSettings
	Host string
}

// DBSettings Структура для хранения настроек сервера базы данных
type DBSettings struct {
	User     string
	Password string
	DBName   string
	Host     string
}

// GetDSN Формирование описания источника данных для севера MySQL
func (s Settings) GetDSN() string {
	return s.DB.User +
		":" +
		s.DB.Password +
		fmt.Sprintf("@tcp(%s)/", s.DB.Host) +
		s.DB.DBName +
		"?charset=utf8"
}

// Init Инициализация настроек сервера
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
