package main

import (
	"fmt"
	"io"
	"io/fs"
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

func compare(filename string, filePath string, tracePath string) (bool, bool, string, string, error) {
	currentHash, err := calcHash(filePath)
	if err != nil {
		return false, false, "", "", fmt.Errorf("failed to calculate hash: %w", err)
	}

	data, err := readTrace(tracePath)
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

func readTrace(tracePath string) (map[string]fileData, error) {
	data := make(map[string]fileData)

	if _, err := os.Stat(tracePath); os.IsNotExist(err) {
		return data, nil
	}

	yamlBytes, err := os.ReadFile(tracePath)
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

func writeTrace(data map[string]fileData, tracePath string) error {
	yamlBytes, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	err = os.WriteFile(tracePath, yamlBytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

func addF(filePath string, tracePath string) error {
	filename := filepath.Base(filePath)

	isInTrace, hashesMatch, currentHash, storedHash, err := compare(filename, filePath, tracePath)
	if err != nil {
		return err
	}

	if isInTrace {
		if hashesMatch {
			fmt.Printf("\033[36mFilename:\033[0m %s\n", filename)
			fmt.Printf("\033[36mCurrent hash:\033[0m %s\n", currentHash)
			fmt.Printf("\033[36mStored hash:\033[0m %s\n", storedHash)
			fmt.Println("\033[32mStatus: Hashes match ✓\033[0m")
			return nil
		} else {
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
	}

	data, err := readTrace(tracePath)
	if err != nil {
		return err
	}

	data[filename] = fileData{
		Blake2b: currentHash,
	}

	fmt.Printf("\033[32mFile Added to Trace:\033[0m\n")
	fmt.Printf("\033[36mFilename:\033[0m %s\n", filename)
	fmt.Printf("\033[36mBlake2b Hash:\033[0m %s\n", currentHash)

	return writeTrace(data, tracePath)
}

func add(path string) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to access path: %w", err)
	}

	if fileInfo.IsDir() {
		fmt.Printf("\033[36mProcessing directory:\033[0m %s\n", path)

		dirTracePath := filepath.Join(path, ".trace")

		err := filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() {
				return nil
			}

			if filepath.Base(filePath) == ".trace" {
				return nil
			}

			return addF(filePath, dirTracePath)
		})

		if err != nil {
			return fmt.Errorf("error processing directory: %w", err)
		}

		fmt.Printf("\033[36mSaved to:\033[0m %s\n", dirTracePath)
		return nil
	}

	dirPath := filepath.Dir(path)
	fileTracePath := filepath.Join(dirPath, ".trace")

	err = addF(path, fileTracePath)
	if err != nil {
		return err
	}

	fmt.Printf("\033[36mSaved to:\033[0m %s\n", fileTracePath)
	return nil
}

func delF(filename string, tracePath string) error {
	data, err := readTrace(tracePath)
	if err != nil {
		return err
	}

	if _, exists := data[filename]; !exists {
		return fmt.Errorf("file %s not found in trace", filename)
	}

	delete(data, filename)

	fmt.Printf("\033[32mFile Removed from Trace:\033[0m\n")
	fmt.Printf("\033[36mFilename:\033[0m %s\n", filename)

	return writeTrace(data, tracePath)
}

func del(path string) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		dirPath := filepath.Dir(path)
		fileTracePath := filepath.Join(dirPath, ".trace")
		filename := filepath.Base(path)
		return delF(filename, fileTracePath)
	}

	if fileInfo.IsDir() {
		fmt.Printf("\033[36mProcessing directory:\033[0m %s\n", path)

		dirTracePath := filepath.Join(path, ".trace")

		files, err := os.ReadDir(path)
		if err != nil {
			return fmt.Errorf("failed to read directory: %w", err)
		}

		for _, file := range files {
			if !file.IsDir() && file.Name() != ".trace" {
				err := delF(file.Name(), dirTracePath)
				if err != nil {
					fmt.Printf("\033[33mWarning:\033[0m %v\n", err)
				}
			}
		}

		fmt.Printf("\033[36mRemoved from:\033[0m %s\n", dirTracePath)
		return nil
	}

	dirPath := filepath.Dir(path)
	fileTracePath := filepath.Join(dirPath, ".trace")
	filename := filepath.Base(path)

	err = delF(filename, fileTracePath)
	if err != nil {
		return err
	}

	fmt.Printf("\033[36mRemoved from:\033[0m %s\n", fileTracePath)
	return nil
}

func checkF(filePath string, tracePath string) error {
	filename := filepath.Base(filePath)

	isInTrace, hashesMatch, currentHash, storedHash, err := compare(filename, filePath, tracePath)
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

func check(path string) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to access path: %w", err)
	}

	if fileInfo.IsDir() {
		fmt.Printf("\033[36mChecking directory:\033[0m %s\n", path)

		dirTracePath := filepath.Join(path, ".trace")

		err := filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() {
				return nil
			}

			// Skip .trace file itself
			if filepath.Base(filePath) == ".trace" {
				return nil
			}

			fmt.Printf("\n--- Checking %s ---\n", filePath)
			return checkF(filePath, dirTracePath)
		})

		if err != nil {
			return fmt.Errorf("error checking directory: %w", err)
		}

		return nil
	}

	dirPath := filepath.Dir(path)
	fileTracePath := filepath.Join(dirPath, ".trace")

	return checkF(path, fileTracePath)
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Error: Please provide a command (add/del/check) and a file or directory path.")
		fmt.Println("Usage: program add|del|check filepath")
		os.Exit(1)
	}

	command := os.Args[1]
	path := os.Args[2]

	var err error

	switch command {
	case "add":
		err = add(path)
		if err != nil {
			fmt.Println("\033[31mError adding to trace:\033[0m", err)
			os.Exit(1)
		}

	case "del":
		err = del(path)
		if err != nil {
			fmt.Println("\033[31mError removing from trace:\033[0m", err)
			os.Exit(1)
		}

	case "check":
		err = check(path)
		if err != nil {
			fmt.Println("\033[31mError comparing:\033[0m", err)
			os.Exit(1)
		}

	default:
		fmt.Println("\033[31mError: Invalid command. Use 'add', 'del', or 'check'.\033[0m")
		os.Exit(1)
	}
}

