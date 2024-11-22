package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// Constants
const saltSize = 16

// GenerateRandomSalt creates a random salt of fixed size
func GenerateRandomSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}
	return salt, nil
}

// DeriveKey derives a 32-byte key using PBKDF2 with a random salt
func DeriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
}

// EncryptFile encrypts the contents of a file, prepends the salt, and Base64 encodes the result
func EncryptFile(password, inputFile string, removeOriginal bool) error {
	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Generate random salt and derive the key
	salt, err := GenerateRandomSalt()
	if err != nil {
		return err
	}
	key := DeriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf("failed to generate IV: %w", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	// Prepend the salt to the ciphertext
	finalCiphertext := append(salt, ciphertext...)

	// Base64 encode the result
	encoded := base64.StdEncoding.EncodeToString(finalCiphertext)

	outputFile := inputFile + ".enc"
	err = ioutil.WriteFile(outputFile, []byte(encoded), 0600)
	if err != nil {
		return fmt.Errorf("failed to write encrypted file: %w", err)
	}

	if removeOriginal {
		if err := os.Remove(inputFile); err != nil {
			return fmt.Errorf("failed to remove original file: %w", err)
		}
	}

	fmt.Printf("File encrypted successfully: %s\n", outputFile)
	return nil
}

// DecryptFile Base64 decodes the file, extracts the salt, and decrypts the contents
func DecryptFile(password, inputFile string, removeOriginal bool) error {
	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Base64 decode the file
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return fmt.Errorf("failed to decode Base64 file: %w", err)
	}

	// Extract the salt and ciphertext
	if len(decoded) < saltSize+aes.BlockSize {
		return errors.New("ciphertext too short or missing salt")
	}
	salt := decoded[:saltSize]
	ciphertext := decoded[saltSize:]

	key := DeriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	if len(ciphertext) < aes.BlockSize {
		return fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	outputFile := strings.TrimSuffix(inputFile, ".enc")
	err = ioutil.WriteFile(outputFile, ciphertext, 0600)
	if err != nil {
		return fmt.Errorf("failed to write decrypted file: %w", err)
	}

	if removeOriginal {
		if err := os.Remove(inputFile); err != nil {
			return fmt.Errorf("failed to remove encrypted file: %w", err)
		}
	}

	fmt.Printf("File decrypted successfully: %s\n", outputFile)
	return nil
}

func main() {
	encrypt := flag.Bool("e", false, "Encrypt the file")
	decrypt := flag.Bool("d", false, "Decrypt the file")
	remove := flag.Bool("r", false, "Remove the source file after processing")

	// Custom help message
	flag.Usage = func() {
		fmt.Println("Usage:")
		fmt.Println("  encrypt -e -r <input_file>")
		fmt.Println("  encrypt -d -r <input_file>.enc")
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Println("  Encrypt file:")
		fmt.Println("    echo \"123456\" | encrypt -e -r file.txt")
		fmt.Println("")
		fmt.Println("  Decrypt file:")
		fmt.Println("    echo \"123456\" | encrypt -d -r file.txt.enc")
	}

	flag.Parse()

	if (!*encrypt && !*decrypt) || len(flag.Args()) != 1 {
		flag.Usage()
		os.Exit(1)
	}

	// Read password from stdin
	fmt.Print("Enter password: ")
	bytePassword, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fmt.Printf("\nFailed to read password: %v\n", err)
		os.Exit(1)
	}
	password := strings.TrimSpace(string(bytePassword)) // Trim newlines or spaces

	if password == "" {
		fmt.Println("\nError: Password cannot be empty.")
		os.Exit(1)
	}

	inputFile := flag.Args()[0]

	// Perform the operation
	if *encrypt {
		err := EncryptFile(password, inputFile, *remove)
		if err != nil {
			fmt.Printf("Encryption failed: %v\n", err)
			os.Exit(1)
		}
	} else if *decrypt {
		err := DecryptFile(password, inputFile, *remove)
		if err != nil {
			fmt.Printf("Decryption failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		flag.Usage()
		os.Exit(1)
	}
}
