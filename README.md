## dataGhost

A command-line tool for file integrity tracking using BLAKE2b hashes and human-readable YAML "ghost" files.

Perfect for verifying files on USB drives, backups, or any folder you care about.

### Features

- Tracks file hashes, size, modification time (and optionally file mode) per-directory in a `.ghost` YAML file
- Fast, concurrent checks with `-p N` (parallelism)
- Quick check mode (`-qc`) skips rehashing when size/modtime are unchanged, and self-heals drifted metadata
- Configurable ignore rules and behaviour via `.ghostconf` YAML files, with optional global config
- Recursive directory support (`-r`)
- Quiet mode and verbosity levels for scripting and inspection
- JSON output for `check`, `list`, and `version` (machine-readable)
- Dry run, did-you-mean suggestions, shell completions
- Terminal-aware colors with `NO_COLOR` / `--color` support
- Atomic file writes for data integrity
- Missing-file detection on `check` (tracked files that have been deleted)
- Optional file-mode (permission) drift detection

### Usage

```
$ dataGhost help

  ┌──────────────────────────────────────────────────────────┐
  │ dataGhost v2.5                                            │
  │ File Integrity Tracking Utility                           │
  └──────────────────────────────────────────────────────────┘

USAGE:
  dataGhost [OPTIONS] COMMAND [PATH]

COMMANDS:
  add         Add files to tracking
  del         Remove files from tracking
  check       Verify file integrity
  clean       Remove missing file entries from tracking
  update      Update old .ghost files with size/modification metadata
  list        List tracked files from .ghost file(s)
  init        Create a commented .ghostconf template
  version     Print version information
  help        Show this help
  completion  Print a shell completion script

OPTIONS:
  -r              Process directories recursively
  -p N            Set number of parallel workers (default: CPU count)
  -f              Force operations without prompts
  -d              Dry run: show what would happen without writing
  -qc             Quick check: skip rehash if size/modtime unchanged
  -q              Quiet mode (prints a one-line summary)
  -v              Verbose output (repeatable: -v -v or -vv)
  --json          Output results as JSON lines
  --color MODE    Color output: auto, always, never
  -b              Raw byte sizes in list output
  -i PATTERN      Ignore pattern (can be used multiple times)
  -c              Load .ghostconf from target directory
  -cf FILE        Load config from a specific file
  -cs             Strict mode (no local overrides)
  -csf FILE       Load config from file (strict mode)

EXIT CODES:
  0  Success
  1  Corruption detected / unexpected changes / missing files / untracked files (with fail_untracked)
  2  Error occurred

EXAMPLES:
  dataGhost add file.txt
  dataGhost -r add .                     # add everything under . recursively
  dataGhost -r check .                   # recursive integrity check
  dataGhost -qc check .                  # quick check (cached on size/modtime)
  dataGhost -q check .                   # one-line summary for scripting
  dataGhost -r clean                     # remove entries for deleted files
  dataGhost update .                     # fill in size/modification metadata
  dataGhost list .                       # list tracked files
  dataGhost -c -r add .                  # load .ghostconf from target dir
  dataGhost -cf config.yaml -r add .     # load config from a specific file
  dataGhost -cs -r add .                 # strict mode with .ghostconf
  dataGhost --json check .               # machine-readable output
  dataGhost completion bash > dg.bash     # shell completions
```

### Configuration

dataGhost's behaviour can be controlled with `.ghostconf` YAML files. Configuration is **layered**:

1. **Built-in defaults** (e.g. `parallel: CPU count`).
2. **Global config** (optional): `<config dir>/dataGhost/config.yaml`. The config directory is `$DG_CONFIG_HOME` if set, otherwise the OS user config directory (`$XDG_CONFIG_HOME` or `~/.config` on Unix, `%AppData%` on Windows). Only keys present in the file override the defaults.
3. **Local `.ghostconf`** in the target directory (loaded with `-c`/`-cs`, or `-cf`/`-csf FILE`). Local keys override global ones; absent keys keep the global value.
4. **Command-line flags** always take precedence over config file settings.

In **normal mode** (`-c`/`-cf`), subdirectories may carry their own `.ghostconf` that overrides inherited ignore rules. In **strict mode** (`-cs`/`-csf`), only the root config's ignore rules are used for all subdirectories.

**Example `.ghostconf`:**

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
track_mode: false
fail_untracked: false
```

- `ignore`: Files/directories to skip (supports globs and directory names)
- `buffer`: Buffer size for reading files (bytes)
- `parallel`: Number of parallel workers
- `quiet`: Suppress output except errors (equivalent to `-q`)
- `show_progress`: Display progress during processing
- `force`: Overwrite without prompt (equivalent to `-f`)
- `track_mode`: When `true`, record each file's permission bits (`mode`) on `add` and report **mode drift** on `check` (useful for detecting accidental `chmod`). Off by default.
- `fail_untracked`: When `true`, `check` exits with code 1 if untracked files are present in a tracked directory. Off by default.

Use `dataGhost init` to write a commented template `.ghostconf` into the target directory.

### Ghost File Format

Each tracked file has an entry in the `.ghost` YAML file with:

- `blake2b`: The BLAKE2b-256 hash of the file contents (hex)
- `size`: File size in bytes (used for quick checks)
- `modified`: Last modification timestamp (used for quick checks)
- `mode`: File permission bits as an octal string, e.g. `"0644"` (only when `track_mode` is enabled)

**Example `.ghost`:**

```yaml
file.txt:
  blake2b: a1b2c3d4e5f6...
  size: 12345
  modified: 2024-01-15T10:30:00Z
  mode: "0644"
```

### Concurrency & Locking

dataGhost coordinates goroutines **within a single process** using per-ghost-file mutexes, so multiple parallel workers sharing one `.ghost` file write it safely and batched. 

However, dataGhost does **not** lock across separate processes. Running two `dataGhost` processes against the same tree simultaneously can lose updates (one overwrites the other). The atomic temp-file-and-rename strategy prevents a corrupted `.ghost` file, but it does not prevent lost writes. For scripted, cron, or parallel workflows that touch the same directories, run commands **sequentially per directory**. An advisory `.ghost.lock` for cross-process coordination may be added in a future release.

### License

dataGhost is licensed under the [Mozilla Public License 2.0](LICENSE).

Prior releases were distributed under the MIT License; that history is retained in the git history. See `LICENSE` for the full MPL-2.0 text.
