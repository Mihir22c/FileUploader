package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

type FileMetadata struct {
	ID       string `gorm:"primary_key"`
	Filename string
	Filesize int64
	UploadAt time.Time
	Checksum string
}

var db *gorm.DB
var encryptionKey = []byte("mysecretencryptionkey1234")

func initDB() {
	var err error
	db, err = gorm.Open("sqlite3", "fileuploader.db")
	if err != nil {
		log.Fatal("Failed to connect to the database:", err)
	}
	db.AutoMigrate(&FileMetadata{})
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
	return ciphertext, nil
}

func checksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
	// Parse form to handle file uploads
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// Retrieve the file from the form
	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Error retrieving the file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read file content
	fileBytes, err := ioutil.ReadAll(file)
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}

	// Encrypt file content
	encryptedData, err := encrypt(fileBytes)
	if err != nil {
		http.Error(w, "Error encrypting file", http.StatusInternalServerError)
		return
	}

	// Save encrypted file to disk
	tempFilePath := fmt.Sprintf("uploads/%s", handler.Filename)
	tempFile, err := os.Create(tempFilePath)
	if err != nil {
		http.Error(w, "Error creating file on disk", http.StatusInternalServerError)
		return
	}
	defer tempFile.Close()

	_, err = tempFile.Write(encryptedData)
	if err != nil {
		http.Error(w, "Error writing file to disk", http.StatusInternalServerError)
		return
	}

	// Save file metadata to the database
	metadata := FileMetadata{
		ID:       generateID(),
		Filename: handler.Filename,
		Filesize: handler.Size,
		UploadAt: time.Now(),
		Checksum: checksum(fileBytes),
	}
	if err := db.Create(&metadata).Error; err != nil {
		http.Error(w, "Error saving file metadata", http.StatusInternalServerError)
		return
	}

	// Respond with file metadata
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}

func main() {
	initDB()
	defer db.Close()

	// Ensure uploads directory exists
	if _, err := os.Stat("uploads"); os.IsNotExist(err) {
		err := os.Mkdir("uploads", 0755)
		if err != nil {
			log.Fatal("Error creating uploads directory:", err)
		}
	}

	router := mux.NewRouter()
	router.HandleFunc("/upload", uploadFileHandler).Methods("POST")

	fmt.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}
