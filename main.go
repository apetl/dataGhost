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

type stats struct {
	checked   int
	corrupted int
	ok        int
	errors    int
}

var (
	quietMode   bool
	globalStats stats
)

func printf(format string, args ...interface{}) {
	if !quietMode {
		fmt.Printf(format, args...)
	}
}

func println(args ...interface{}) {
	if !quietMode {
		fmt.Println(args...)
	}
}

func getBufferSize(file *os.File) int {
	const (
		minBuffer     = 64 * 1024   // 64KB
		maxBuffer     = 1024 * 1024 // 1MB
		defaultBuffer = 256 * 1024  // 256KB
	)

	stat, err := file.Stat()
	if err != nil {
		return defaultBuffer
	}

	fileSize := stat.Size()

	switch {
	case fileSize < 1024*1024: // < 1MB
		return minBuffer
	case fileSize < 100*1024*1024: // < 100MB
		return defaultBuffer
	default: // >= 100MB
		return maxBuffer
	}
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

	buffer := make([]byte, getBufferSize(file))

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
			printf("\033[36mFilename:\033[0m %s\n", filename)
			printf("\033[36mCurrent hash:\033[0m %s\n", currentHash)
			printf("\033[36mStored hash:\033[0m %s\n", storedHash)
			println("\033[32mStatus: Hashes match ✓\033[0m")
			return nil
		} else {
			printf("\033[33mWarning:\033[0m File '%s' already exists in ghost with a different hash.\n", filename)
			printf("Existing hash: %s\n", storedHash)
			printf("New hash: %s\n", currentHash)
			printf("Do you want to overwrite it? (y/n): ")

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

	printf("\033[32mFile Added to Ghost:\033[0m\n")
	printf("\033[36mFilename:\033[0m %s\n", filename)
	printf("\033[36mBlake2b Hash:\033[0m %s\n", currentHash)

	return writeGhost(data, ghostPath)
}

func add(path string, recursive bool) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to access path: %w", err)
	}

	if fileInfo.IsDir() {
		printf("\033[36mProcessing directory:\033[0m %s\n", path)
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
						printf("\033[33mWarning: %v\033[0m\n", err)
					}
				}
			}
		}

		printf("\033[36mSaved to:\033[0m %s\n", dirGhostPath)
		return nil
	}

	dirPath := filepath.Dir(path)
	fileGhostPath := filepath.Join(dirPath, ".ghost")

	err = addF(path, fileGhostPath)
	if err != nil {
		return err
	}

	printf("\033[36mSaved to:\033[0m %s\n", fileGhostPath)
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

	printf("\033[32mFile Removed from Ghost:\033[0m\n")
	printf("\033[36mFilename:\033[0m %s\n", filename)

	return writeGhost(data, ghostPath)
}

func del(path string, recursive bool) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to access path: %w", err)
	}

	if fileInfo.IsDir() {
		printf("\033[36mProcessing directory:\033[0m %s\n", path)
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
						printf("\033[33mWarning: %v\033[0m\n", err)
					}
				}
			}
		}

		printf("\033[36mSaved to:\033[0m %s\n", dirGhostPath)
		return nil
	}

	dirPath := filepath.Dir(path)
	fileGhostPath := filepath.Join(dirPath, ".ghost")

	err = delF(path, fileGhostPath)
	if err != nil {
		return err
	}

	printf("\033[36mSaved to:\033[0m %s\n", fileGhostPath)
	return nil
}

func checkF(filePath string, ghostPath string) error {
	filename := filepath.Base(filePath)

	isInGhost, hashesMatch, currentHash, storedHash, err := compare(filename, filePath, ghostPath)
	if err != nil {
		globalStats.errors++
		return err
	}

	globalStats.checked++

	if !isInGhost {
		printf("\033[33mFile '%s' not found in ghost.\033[0m\n", filename)
		printf("\033[36mCurrent hash:\033[0m %s\n", currentHash)
		return nil
	}

	printf("\033[36mFilename:\033[0m %s\n", filename)
	printf("\033[36mCurrent hash:\033[0m %s\n", currentHash)
	printf("\033[36mStored hash:\033[0m %s\n", storedHash)

	if hashesMatch {
		globalStats.ok++
		println("\033[32mStatus: Hashes match ✓\033[0m")
	} else {
		globalStats.corrupted++
		println("\033[31mStatus: Hashes differ ✗\033[0m")
	}

	return nil
}

func check(path string, recursive bool) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to access path: %w", err)
	}

	if fileInfo.IsDir() {
		printf("\033[36mChecking directory:\033[0m %s\n", path)
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
						printf("\033[31mError: %v\033[0m\n", err)
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
						printf("\033[31mError: %v\033[0m\n", err)
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
		printf("\033[36mGhost file is empty at:\033[0m %s\n", ghostPath)
		return nil
	}

	removedCount := 0
	for filename := range data {
		filePath := filepath.Join(dirPath, filename)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			printf("\033[33mMissing file:\033[0m %s\n", filename)
			delete(data, filename)
			removedCount++
		}
	}

	if removedCount > 0 {
		printf("\033[32mRemoved %d missing file(s) from ghost\033[0m\n", removedCount)
		return writeGhost(data, ghostPath)
	}

	printf("\033[32mNo missing files found in ghost\033[0m\n")
	return nil
}

func clean(path string, recursive bool) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to access path: %w", err)
	}

	if fileInfo.IsDir() {
		printf("\033[36mCleaning directory:\033[0m %s\n", path)
		dirGhostPath := filepath.Join(path, ".ghost")

		if _, err := os.Stat(dirGhostPath); !os.IsNotExist(err) {
			if err := cleanF(path, dirGhostPath); err != nil {
				return fmt.Errorf("error cleaning ghost file: %w", err)
			}
		} else {
			printf("\033[33mNo ghost file found at:\033[0m %s\n", dirGhostPath)
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
							printf("\033[31mError cleaning %s: %v\033[0m\n", subPath, err)
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

func printSummary() {
	if globalStats.checked > 0 {
		fmt.Printf("Checked %d files, %d corrupted, %d OK",
			globalStats.checked, globalStats.corrupted, globalStats.ok)
		if globalStats.errors > 0 {
			fmt.Printf(", %d errors", globalStats.errors)
		}
		fmt.Println()
	}
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
	fmt.Println("  \033[38;5;148m-q\033[0m      Quiet mode (for scripting)")
	fmt.Println()
	fmt.Println("\033[38;5;116mExit codes:\033[0m")
	fmt.Println("  0       Success")
	fmt.Println("  1       Corruption found")
	fmt.Println("  2       Error occurred")
	fmt.Println()
	fmt.Println("\033[38;5;116mExamples:\033[0m")
	fmt.Println("  dataGhost \033[38;5;117madd\033[0m file.txt")
	fmt.Println("  dataGhost \033[38;5;148m-r\033[0m \033[38;5;117mclean\033[0m")
	fmt.Println("  dataGhost \033[38;5;148m-q\033[0m \033[38;5;117mcheck\033[0m .")
}

func main() {
	if len(os.Args) < 2 {
		help()
		os.Exit(2)
	}

	if os.Args[1] == "help" {
		help()
		os.Exit(0)
	}

	var recursive bool
	var command string
	var path string
	argIndex := 1

	for argIndex < len(os.Args) && os.Args[argIndex][0] == '-' {
		switch os.Args[argIndex] {
		case "-r":
			recursive = true
		case "-q":
			quietMode = true
		case "-rq", "-qr":
			recursive = true
			quietMode = true
		default:
			fmt.Printf("\033[38;5;204mError: Unknown flag: %s\033[0m\n", os.Args[argIndex])
			os.Exit(2)
		}
		argIndex++
	}

	if argIndex >= len(os.Args) {
		fmt.Printf("\033[38;5;204mError: Missing command\033[0m\n")
		os.Exit(2)
	}

	command = os.Args[argIndex]
	argIndex++

	if argIndex >= len(os.Args) {
		fmt.Printf("\033[38;5;204mError: Missing path for command: %s\033[0m\n", command)
		os.Exit(2)
	}

	path = os.Args[argIndex]

	var err error
	switch command {
	case "add":
		err = add(path, recursive)
	case "del":
		err = del(path, recursive)
	case "check":
		err = check(path, recursive)
		printSummary()
		if globalStats.corrupted > 0 {
			os.Exit(1)
		}
	case "clean":
		err = clean(path, recursive)
	default:
		fmt.Printf("\033[38;5;204mError: Unknown command: %s\033[0m\n", command)
		help()
		os.Exit(2)
	}

	if err != nil {
		fmt.Printf("\033[38;5;204mError: %v\033[0m\n", err)
		os.Exit(2)
	}

	os.Exit(0)
}
