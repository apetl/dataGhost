## dataGhost
A command-line tool for file integrity tracking using BLAKE2b hashes and human-readable YAML "ghost" files.

Perfect for verifying files on USB drives, backups, or any folder you care about.
### Features
- Tracks file hashes, size, and modification time per-directory in a ```.ghost``` YAML file
- Fast, concurrent checks with ```-p N``` (parallelism)
- Configurable ignore rules and behaviour via ```.ghostconf``` YAML files (per-directory or globally)
- Recursive directory support (```-r```)
- Quiet mode for scripting (```-q```)
- Quick check mode (```-qc```) - skip rehash if size/modtime unchanged
- Force overwrite without prompt (```-f```)
- Atomic file writes for data integrity
- Strict config mode for consistent behaviour across subdirectories
- Supports both command-line flags and config file overrides
### Usage
```bash
$ dataGhost help
Usage: dataGhost [OPTIONS] COMMAND [PATH]

Commands:
  add     Add files to tracking
  del     Delete tracked files
  check   Check status of tracked files
  clean   Clean up tracked files (remove missing file entries)
  update  Update old .ghost files with size/modification metadata

Options:
  -c          Load .ghostconf from target directory
  -cs         Load .ghostconf from target directory (strict mode)
  -cf FILE    Load config from specified file
  -csf FILE   Load config from specified file (strict mode)
  -r          Process directories recursively
  -q          Quiet mode (for scripting)
  -qc         Quick check: skip rehash if size/modtime unchanged
  -p N        Number of parallel workers (default: CPU count)
  -f          Force operations without prompts

Config modes:
  Normal: Allows subdirectory .ghostconf files to override ignore rules
  Strict: Uses only the root config ignore rules for all subdirectories

Exit codes:
  0       Success
  1       Corruption detected / unexpected file changes
  2       Error occurred

Examples:
  dataGhost add file.txt
  dataGhost -r clean
  dataGhost -q check .
  dataGhost -qc check .              # quick check (cached)
  dataGhost update .                 # update metadata in .ghost files
  dataGhost -c add .                 # loads .ghostconf from target dir
  dataGhost -cf config.yaml add .    # loads config from specified file
  dataGhost -cs add .                # strict mode with .ghostconf
  dataGhost -csf config.yaml add .   # strict mode with custom config
```
### Configuration
You can control dataGhost's behaviour with a ```.ghostconf``` YAML file in any directory.
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
show_progress: true
force: false
```
- ```ignore```: List of files/directories to skip (supports globs and directory names)
- ```buffer```: Buffer size for reading files (in bytes)
- ```parallel```: Number of parallel workers
- ```quiet```: Suppress output except errors
- ```show_progress```: Display progress during processing
- ```force```: Overwrite without prompt
#### How Config Works
- By default, dataGhost loads ```.ghostconf``` from the target directory.
- If ```-r``` is used and subdirectories have their own ```.ghostconf```, those settings override the parent config (unless strict mode is enabled).
- Command-line flags always override config file settings.
- Strict mode (```-cs```/```-csf```) disables per-subdir overrides and uses only the root config.

### Ghost File Format
Each tracked file has an entry in the ```.ghost``` YAML file with:
- ```Blake2b```: The BLAKE2b-256 hash of the file contents
- ```size```: File size in bytes (optional, for quick checks)
- ```modified```: Last modification timestamp (optional, for quick checks)

**Example ```.ghost```:**
```yaml
file.txt:
  blake2b: a1b2c3d4e5f6...
  size: 12345
  modified: 2024-01-15T10:30:00Z
```


