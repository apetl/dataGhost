## DataGhost
A command-line tool for file integrity tracking using BLAKE2b hashes.
### Usage
```bash
# Add files to tracking
dataGhost add file.txt
dataGhost -r add .  # recursive

# Check file integrity  
dataGhost check file.txt
dataGhost -q check .  # quiet mode

# Remove from tracking
dataGhost del file.txt

# Clean up deleted files
dataGhost clean .
```
