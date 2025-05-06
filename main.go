package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
	"golang.org/x/crypto/blake2b"
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

func compare(filename string, filePath string, yamlPath string) (bool, bool, string, string, error) {
	currentHash, err := calcHash(filePath)
	if err != nil {
		return false, false, "", "", fmt.Errorf("failed to calculate hash: %w", err)
	}

	data, err := readTrace(yamlPath)
	if err != nil {
		return false, false, currentHash, "", err
	}

	storedData, exists := data[filename]
	if !exists {
		return false, false, currentHash, "", nil
	}

	storedHash := storedData.Blake2b
	hashesMatch := currentHash == storedHash

	return true, hashesMatch, currentHash, storedHash, nil
}

func readTrace(yamlPath string) (map[string]fileData, error) {
	data := make(map[string]fileData)

	if _, err := os.Stat(yamlPath); os.IsNotExist(err) {
		return data, nil
	}

	yamlBytes, err := os.ReadFile(yamlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read trace file: %w", err)
	}

	if len(yamlBytes) == 0 {
		return data, nil
	}

	err = yaml.Unmarshal(yamlBytes, &data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return data, nil
}

func writeTrace(data map[string]fileData, yamlPath string) error {
	yamlBytes, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	err = os.WriteFile(yamlPath, yamlBytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

func add(filePath string, yamlPath string) error {
	filename := filepath.Base(filePath)

	isInTrace, hashesMatch, currentHash, storedHash, err := compare(filename, filePath, yamlPath)
	if err != nil {
		return err
	}

	if isInTrace && !hashesMatch {
		fmt.Printf("\033[33mWarning:\033[0m File '%s' already exists in trace with a different hash.\n", filename)
		fmt.Printf("Existing hash: %s\n", storedHash)
		fmt.Printf("New hash: %s\n", currentHash)
		fmt.Print("Do you want to overwrite it? (y/n): ")

		var response string
		fmt.Scanln(&response)

		if response != "y" && response != "Y" {
			return fmt.Errorf("operation cancelled by user")
		}
	}

	data, err := readTrace(yamlPath)
	if err != nil {
		return err
	}

	data[filename] = fileData{
		Blake2b: currentHash,
	}

	return writeTrace(data, yamlPath)
}

func del(filename string, yamlPath string) error {
	data, err := readTrace(yamlPath)
	if err != nil {
		return err
	}

	if _, exists := data[filename]; !exists {
		return fmt.Errorf("file %s not found in trace", filename)
	}

	delete(data, filename)

	return writeTrace(data, yamlPath)
}

func check(filePath string, yamlPath string) error {
	filename := filepath.Base(filePath)

	isInTrace, hashesMatch, currentHash, storedHash, err := compare(filename, filePath, yamlPath)
	if err != nil {
		return err
	}

	if !isInTrace {
		fmt.Printf("\033[33mFile '%s' not found in trace.\033[0m\n", filename)
		fmt.Printf("\033[36mCurrent hash:\033[0m %s\n", currentHash)
		return nil
	}

	fmt.Printf("\033[36mFilename:\033[0m %s\n", filename)
	fmt.Printf("\033[36mCurrent hash:\033[0m %s\n", currentHash)
	fmt.Printf("\033[36mStored hash:\033[0m %s\n", storedHash)

	if hashesMatch {
		fmt.Println("\033[32mStatus: Hashes match ✓\033[0m")
	} else {
		fmt.Println("\033[31mStatus: Hashes differ ✗\033[0m")
	}

	return nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Error: Please provide a command (add/del) and a file path.")
		fmt.Println("Usage: program add|del filepath")
		os.Exit(1)
	}

	command := os.Args[1]
	filePath := os.Args[2]
	yamlPath := ".trace"

	switch command {
	case "add":
		err := add(filePath, yamlPath)
		if err != nil {
			fmt.Println("\033[31mError adding file to trace:\033[0m", err)
			os.Exit(1)
		}

		filename := filepath.Base(filePath)
		hash, _ := calcHash(filePath)

		fmt.Println("\033[32mFile Added to Trace:\033[0m")
		fmt.Printf("\033[36mFilename:\033[0m %s\n", filename)
		fmt.Printf("\033[36mBlake2b Hash:\033[0m %s\n", hash)
		fmt.Printf("\033[36mSaved to:\033[0m %s\n", yamlPath)

	case "del":
		filename := filepath.Base(filePath)
		err := del(filename, yamlPath)
		if err != nil {
			fmt.Println("\033[31mError removing file from trace:\033[0m", err)
			os.Exit(1)
		}

		fmt.Println("\033[32mFile Removed from Trace:\033[0m")
		fmt.Printf("\033[36mFilename:\033[0m %s\n", filename)
		fmt.Printf("\033[36mRemoved from:\033[0m %s\n", yamlPath)

	case "check":
		err := check(filePath, yamlPath)
		if err != nil {
			fmt.Println("\033[31mError comparing file:\033[0m", err)
			os.Exit(1)
		}

	default:
		fmt.Println("\033[31mError: Invalid command. Use 'add', 'del', or 'check'.\033[0m")
		os.Exit(1)
	}
}
