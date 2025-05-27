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

	buffer := make([]byte, 64*1024)

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

func compare(filename string, filePath string, ghostPath string) (bool, bool, string, string, error) {
	currentHash, err := calcHash(filePath)
	if err != nil {
		return false, false, "", "", fmt.Errorf("failed to calculate hash: %w", err)
	}

	data, err := readGhost(ghostPath)
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

func readGhost(ghostPath string) (map[string]fileData, error) {
	data := make(map[string]fileData)

	if _, err := os.Stat(ghostPath); os.IsNotExist(err) {
		return data, nil
	}

	yamlBytes, err := os.ReadFile(ghostPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read ghost file: %w", err)
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

func writeGhost(data map[string]fileData, ghostPath string) error {
	yamlBytes, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	err = os.WriteFile(ghostPath, yamlBytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

func addF(filePath string, ghostPath string) error {
	filename := filepath.Base(filePath)

	isInGhost, hashesMatch, currentHash, storedHash, err := compare(filename, filePath, ghostPath)
	if err != nil {
		return err
	}

	if isInGhost {
		if hashesMatch {
			fmt.Printf("\033[36mFilename:\033[0m %s\n", filename)
			fmt.Printf("\033[36mCurrent hash:\033[0m %s\n", currentHash)
			fmt.Printf("\033[36mStored hash:\033[0m %s\n", storedHash)
			fmt.Println("\033[32mStatus: Hashes match ✓\033[0m")
			return nil
		} else {
			fmt.Printf("\033[33mWarning:\033[0m File '%s' already exists in ghost with a different hash.\n", filename)
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

	data, err := readGhost(ghostPath)
	if err != nil {
		return err
	}

	data[filename] = fileData{
		Blake2b: currentHash,
	}

	fmt.Printf("\033[32mFile Added to Ghost:\033[0m\n")
	fmt.Printf("\033[36mFilename:\033[0m %s\n", filename)
	fmt.Printf("\033[36mBlake2b Hash:\033[0m %s\n", currentHash)

	return writeGhost(data, ghostPath)
}

func add(path string, recursive bool) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to access path: %w", err)
	}

	if fileInfo.IsDir() {
		fmt.Printf("\033[36mProcessing directory:\033[0m %s\n", path)
		dirGhostPath := filepath.Join(path, ".ghost")

		if recursive {
			err := filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() && filePath != path {
					dirGhostFile := filepath.Join(filePath, ".ghost")
					if _, err := os.Stat(dirGhostFile); os.IsNotExist(err) {
						if err := writeGhost(make(map[string]fileData), dirGhostFile); err != nil {
							return fmt.Errorf("failed to create ghost file in %s: %w", filePath, err)
						}
					}
					return nil
				}

				if !d.IsDir() && filepath.Base(filePath) != ".ghost" {
					dirPath := filepath.Dir(filePath)
					localGhostPath := filepath.Join(dirPath, ".ghost")
					return addF(filePath, localGhostPath)
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("error processing directory recursively: %w", err)
			}
		} else {
			files, err := os.ReadDir(path)
			if err != nil {
				return fmt.Errorf("failed to read directory: %w", err)
			}

			for _, file := range files {
				if !file.IsDir() && file.Name() != ".ghost" {
					filePath := filepath.Join(path, file.Name())
					if err := addF(filePath, dirGhostPath); err != nil {
						fmt.Printf("\033[33mWarning: %v\033[0m\n", err)
					}
				}
			}
		}

		fmt.Printf("\033[36mSaved to:\033[0m %s\n", dirGhostPath)
		return nil
	}

	dirPath := filepath.Dir(path)
	fileGhostPath := filepath.Join(dirPath, ".ghost")

	err = addF(path, fileGhostPath)
	if err != nil {
		return err
	}

	fmt.Printf("\033[36mSaved to:\033[0m %s\n", fileGhostPath)
	return nil
}

func delF(filename string, ghostPath string) error {
	data, err := readGhost(ghostPath)
	if err != nil {
		return err
	}

	if _, exists := data[filename]; !exists {
		return fmt.Errorf("file %s not found in ghost", filename)
	}

	delete(data, filename)

	fmt.Printf("\033[32mFile Removed from Ghost:\033[0m\n")
	fmt.Printf("\033[36mFilename:\033[0m %s\n", filename)

	return writeGhost(data, ghostPath)
}

func del(path string, recursive bool) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to access path: %w", err)
	}

	if fileInfo.IsDir() {
		fmt.Printf("\033[36mProcessing directory:\033[0m %s\n", path)
		dirGhostPath := filepath.Join(path, ".ghost")

		if recursive {
			err := filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if !d.IsDir() && filepath.Base(filePath) != ".ghost" {
					dirPath := filepath.Dir(filePath)
					localGhostPath := filepath.Join(dirPath, ".ghost")
					return delF(filePath, localGhostPath)
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("error processing directory recursively: %w", err)
			}
		} else {
			files, err := os.ReadDir(path)
			if err != nil {
				return fmt.Errorf("failed to read directory: %w", err)
			}

			for _, file := range files {
				if !file.IsDir() && file.Name() != ".ghost" {
					filePath := filepath.Join(path, file.Name())
					if err := delF(filePath, dirGhostPath); err != nil {
						fmt.Printf("\033[33mWarning: %v\033[0m\n", err)
					}
				}
			}
		}

		fmt.Printf("\033[36mSaved to:\033[0m %s\n", dirGhostPath)
		return nil
	}

	dirPath := filepath.Dir(path)
	fileGhostPath := filepath.Join(dirPath, ".ghost")

	err = delF(path, fileGhostPath)
	if err != nil {
		return err
	}

	fmt.Printf("\033[36mSaved to:\033[0m %s\n", fileGhostPath)
	return nil
}

func checkF(filePath string, ghostPath string) error {
	filename := filepath.Base(filePath)

	isInGhost, hashesMatch, currentHash, storedHash, err := compare(filename, filePath, ghostPath)
	if err != nil {
		return err
	}

	if !isInGhost {
		fmt.Printf("\033[33mFile '%s' not found in ghost.\033[0m\n", filename)
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

func check(path string, recursive bool) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to access path: %w", err)
	}

	if fileInfo.IsDir() {
		fmt.Printf("\033[36mChecking directory:\033[0m %s\n", path)
		dirGhostPath := filepath.Join(path, ".ghost")

		if recursive {
			err := filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if !d.IsDir() && filepath.Base(filePath) != ".ghost" {
					dirPath := filepath.Dir(filePath)
					localGhostPath := filepath.Join(dirPath, ".ghost")
					if err := checkF(filePath, localGhostPath); err != nil {
						fmt.Printf("\033[31mError: %v\033[0m\n", err)
					}
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("error checking directory recursively: %w", err)
			}
		} else {
			files, err := os.ReadDir(path)
			if err != nil {
				return fmt.Errorf("failed to read directory: %w", err)
			}

			for _, file := range files {
				if !file.IsDir() && file.Name() != ".ghost" {
					filePath := filepath.Join(path, file.Name())
					if err := checkF(filePath, dirGhostPath); err != nil {
						fmt.Printf("\033[31mError: %v\033[0m\n", err)
					}
				}
			}
		}
		return nil
	}

	dirPath := filepath.Dir(path)
	fileGhostPath := filepath.Join(dirPath, ".ghost")

	return checkF(path, fileGhostPath)
}

func cleanF(dirPath string, ghostPath string) error {
	data, err := readGhost(ghostPath)
	if err != nil {
		return fmt.Errorf("failed to read ghost file: %w", err)
	}

	if len(data) == 0 {
		fmt.Printf("\033[36mGhost file is empty at:\033[0m %s\n", ghostPath)
		return nil
	}

	removedCount := 0
	for filename := range data {
		filePath := filepath.Join(dirPath, filename)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			fmt.Printf("\033[33mMissing file:\033[0m %s\n", filename)
			delete(data, filename)
			removedCount++
		}
	}

	if removedCount > 0 {
		fmt.Printf("\033[32mRemoved %d missing file(s) from ghost\033[0m\n", removedCount)
		return writeGhost(data, ghostPath)
	}

	fmt.Printf("\033[32mNo missing files found in ghost\033[0m\n")
	return nil
}

func clean(path string, recursive bool) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to access path: %w", err)
	}

	if fileInfo.IsDir() {
		fmt.Printf("\033[36mCleaning directory:\033[0m %s\n", path)
		dirGhostPath := filepath.Join(path, ".ghost")

		if _, err := os.Stat(dirGhostPath); !os.IsNotExist(err) {
			if err := cleanF(path, dirGhostPath); err != nil {
				return fmt.Errorf("error cleaning ghost file: %w", err)
			}
		} else {
			fmt.Printf("\033[33mNo ghost file found at:\033[0m %s\n", dirGhostPath)
		}

		if recursive {
			err := filepath.WalkDir(path, func(subPath string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() && subPath != path {
					subGhostPath := filepath.Join(subPath, ".ghost")
					if _, err := os.Stat(subGhostPath); !os.IsNotExist(err) {
						if err := cleanF(subPath, subGhostPath); err != nil {
							fmt.Printf("\033[31mError cleaning %s: %v\033[0m\n", subPath, err)
						}
					}
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("error processing directory recursively: %w", err)
			}
		}
		return nil
	}

	dirPath := filepath.Dir(path)
	fileGhostPath := filepath.Join(dirPath, ".ghost")

	if _, err := os.Stat(fileGhostPath); os.IsNotExist(err) {
		return fmt.Errorf("no ghost file found in directory: %s", dirPath)
	}

	return cleanF(dirPath, fileGhostPath)
}

func help() {
	fmt.Println("\033[38;5;183mUsage: dataGhost [OPTIONS] COMMAND\033[0m")
	fmt.Println()
	fmt.Println("\033[38;5;116mCommands:\033[0m")
	fmt.Println("  \033[38;5;117madd\033[0m     Add files to tracking")
	fmt.Println("  \033[38;5;117mdel\033[0m     Delete tracked files")
	fmt.Println("  \033[38;5;117mcheck\033[0m   Check status of tracked files")
	fmt.Println("  \033[38;5;117mclean\033[0m   Clean up tracked files")
	fmt.Println()
	fmt.Println("\033[38;5;116mOptions:\033[0m")
	fmt.Println("  \033[38;5;148m-r\033[0m      Process directories recursively")
	fmt.Println()
	fmt.Println("\033[38;5;116mExamples:\033[0m")
	fmt.Println("  dataGhost \033[38;5;117madd\033[0m file.txt")
	fmt.Println("  dataGhost \033[38;5;148m-r\033[0m \033[38;5;117mclean\033[0m")
}

func main() {
	if len(os.Args) < 2 {
		help()
		return
	}

	if os.Args[1] == "help" {
		help()
		return
	}

	if len(os.Args) < 3 {
		fmt.Printf("\033[38;5;204mError: Missing path for command: %s\033[0m\n", os.Args[1])
		return
	}

	var recursive bool
	var command string
	var path string

	if os.Args[1] == "-r" {
		recursive = true
		command = os.Args[2]
		path = os.Args[3]
	} else {
		recursive = false
		command = os.Args[1]
		path = os.Args[2]
	}

	var err error
	switch command {
	case "add":
		err = add(path, recursive)
	case "del":
		err = del(path, recursive)
	case "check":
		err = check(path, recursive)
	case "clean":
		err = clean(path, recursive)
	default:
		fmt.Printf("\033[38;5;204mError: Unknown command: %s\033[0m\n", command)
		help()
		return
	}

	if err != nil {
		fmt.Printf("\033[38;5;204mError: %v\033[0m\n", err)
	}
}
