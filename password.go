package configs

import (
	"log"
	"bufio"
	"os"
	"path/filepath"

	"github.com/texttheater/golang-levenshtein/levenshtein"
)

var CommonPasswords map[string]bool

func LoadCommonPasswords() {
	var filePath string

	if _, err := os.Stat("/app/fixtures/common_passwords.txt"); os.IsNotExist(err) {
		filePath = "./fixtures/common_passwords.txt"
	} else {
		filePath = "/app/fixtures/common_passwords.txt"
	}

	cleanPath := filepath.Clean(filePath)

	file, err := os.Open(cleanPath)
	if err != nil {
		log.Println("gagal membuka file kata sandi umum", err)
	}
	defer file.Close()

	CommonPasswords = make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for {
		if !scanner.Scan() {
			break
		}
		CommonPasswords[scanner.Text()] = true
	}

	if err := scanner.Err(); err != nil {
		log.Println("gagal membaca file kata sandi umum", err)
	}
}

func IsSimilarPassword(password string) bool {
	for commonPassword := range CommonPasswords {
		if len(commonPassword) >= 6 {
			similarity := levenshtein.DistanceForStrings([]rune(password), []rune(commonPassword), levenshtein.DefaultOptions)
			if float32(similarity)/float32(len(commonPassword)) < 0.2 {
				return true
			}
		}
	}
	return false
}
