## dataGhost
A command-line tool for file integrity tracking using BLAKE2b hashes and human-readable YAML “ghost” files.
Perfect for verifying files on USB drives, backups, or any folder you care about.
### Features
- Tracks file hashes per-directory in a ```.ghost``` YAML file
- Fast, concurrent checks with ```-p N``` (parallelism)
- Configurable ignore rules and behaviour via ```.ghostconf``` YAML files (per-directory or globally)
- Recursive directory support (```-r```)
- Quiet mode for scripting (```-q```)
- Force overwrite without prompt (```-f```)
- Colourful, readable CLI output
- Strict config mode for consistent behaviour across subdirectories
- Supports both command-line flags and config file overrides
### Usage
```bash
$ dataGhost help
Usage: dataGhost [OPTIONS] COMMAND

Commands:
  add     Add files to tracking
  del     Delete tracked files
  check   Check status of tracked files
  clean   Clean up tracked files

Options:
  -c          Load .ghostconf from target directory
  -cs         Load .ghostconf from target directory (strict mode)
  -cf FILE    Load config from specified file
  -csf FILE   Load config from specified file (strict mode)
  -r          Process directories recursively
  -q          Quiet mode (for scripting)
  -p N        Number of parallel threads
  -f          Force overwrite without prompt

Config modes:
  Normal: Allows subdirectory .ghostconf files to override ignore rules
  Strict: Uses only the root config ignore rules for all subdirectories

Exit codes:
  0       Success
  1       Corruption found
  2       Error occurred

Examples:
  dataGhost add file.txt
  dataGhost -r clean
  dataGhost -q check .
  dataGhost -c add .                # loads .ghostconf from target dir
  dataGhost -cf config.yaml add .   # loads config from specified file
  dataGhost -cs add .               # strict mode with .ghostconf
  dataGhost -csf config.yaml add .  # strict mode with custom config
```
### Configuration
You can control dataGhost’s behaviour with a ```.ghostconf``` YAML file in any directory.
Subdirectories can have their own ```.ghostconf``` to override settings (unless strict mode is enabled).
**Example ```.ghostconf```:**
```yaml
ignore:
  - "*.tmp"
  - "*.log"
  - "node_modules/"
  - ".git/"
buffer: 262144
parallel: 4
quiet: false
recursive: true
force: false
```
- ```ignore```: List of files/directories to skip (supports globs and directory names)
- ```buffer```: Buffer size for reading files (in bytes)
- ```parallel```: Number of parallel threads
- ```quiet```: Suppress output except errors
- ```recursive```: Process directories recursively
- ```force```: Overwrite without prompt
#### How Config Works
- By default, dataGhost loads ```.ghostconf``` from the target directory.
- If ```-r``` is used and subdirectories have their own ```.ghostconf```, those settings override the parent config (unless strict mode is enabled).
- Command-line flags always override config file settings.
- Strict mode (```-cs```/```-csf```) disables per-subdir overrides and uses only the root config.
