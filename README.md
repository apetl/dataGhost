## DataGhost
A command-line tool for file integrity tracking using BLAKE2b hashes and human-readable YAML “ghost” files.  
Perfect for verifying files on USB drives, backups, or any folder you care about.
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
  -r      Process directories recursively
  -q      Quiet mode (for scripting)
  -p N    Number of parallel threads
  -f      Force overwrite without prompt

Exit codes:
  0       Success
  1       Corruption found
  2       Error occurred

Examples:
  dataGhost add file.txt
  dataGhost -r clean
  dataGhost -q check .
```
### Features
- Tracks file hashes per-directory in a ```.ghost``` YAML file
- Fast, concurrent checks (with ```-p N```)
- Coloured, readable CLI output
- Quiet mode for scripting (```-q```)
- Recursive directory support (```-r```)
