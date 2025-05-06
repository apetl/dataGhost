package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/blake2b"
	"gopkg.in/yaml.v3"
)

type fileData struct {
	Blake2b string `yaml:"Blake2b"`
}

func calcHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash, err := blake2b.New256(nil)
	if err != nil {
		return "", fmt.Errorf("failed to create BLAKE2b hash: %w", err)
	}

	buffer := make([]byte, 4096)

	for {
		bytesRead, err := file.Read(buffer)
		if err != nil {
			if err != io.EOF {
				return "", fmt.Errorf("failed to read file: %w", err)
			}
			break
		}
		_, err = hash.Write(buffer[:bytesRead])
		if err != nil {
			return "", fmt.Errorf("failed to write to hash: %w", err)
		}
	}
	hashSum := hash.Sum(nil)
	return fmt.Sprintf("%x", hashSum), nil
}

func writeMetadataToYAML(filePath string, hash string, yamlPath string) error {
	filename := filepath.Base(filePath)

	data := map[string]fileData{
		filename: {
			Blake2b: hash,
		},
	}

	file, err := os.Create(yamlPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	encoder := yaml.NewEncoder(file)
	err = encoder.Encode(data)
	if err != nil {
		return fmt.Errorf("failed to encode YAML: %w", err)
	}

	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Error: Please provide a file path as a command-line argument.")
		os.Exit(1)
	}

	filePath := os.Args[1]
	yamlPath := ".trace"

	hash, err := calcHash(filePath)
	if err != nil {
		fmt.Println("\033[31mError calculating hash:\033[0m", err)
		os.Exit(1)
	}

	err = writeMetadataToYAML(filePath, hash, yamlPath)
	if err != nil {
		fmt.Println("\033[31mError writing YAML:\033[0m", err)
		os.Exit(1)
	}

	filename := filepath.Base(filePath)
	fmt.Println("\033[32mFile Metadata:\033[0m")
	fmt.Printf("\033[36mFilename:\033[0m %s\n", filename)
	fmt.Printf("\033[36mBlake2b Hash:\033[0m %s\n", hash)
	fmt.Printf("\033[36mSaved to:\033[0m %s\n", yamlPath)
}
