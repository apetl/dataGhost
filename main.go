package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"dataGhost/internal/app"
	"dataGhost/internal/completion"
	"dataGhost/internal/config"
	"dataGhost/internal/output"
)

var commands = []string{
	"add", "del", "check", "clean", "update", "list", "init",
	"version", "help", "completion",
}

func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// valueFlags are flags that consume the following token as their value.
var valueFlags = map[string]bool{
	"p": true, "cf": true, "csf": true, "i": true, "color": true,
}

// hoistFlags reorders args so every flag token precedes positional args.
// Go's flag package stops parsing at the first positional, so
// `dataGhost check -qc path` would otherwise treat -qc as the path. We move
// flags ahead of positionals while preserving flag order and value pairings.
// A "--" terminator forces the rest to be positional.
func hoistFlags(args []string) []string {
	var flags, positionals []string
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			name := strings.TrimLeft(a, "-")
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				name = name[:eq]
				flags = append(flags, a)
				i++
				continue
			}
			flags = append(flags, a)
			// Value-taking flag whose next token is not itself a flag: pull
			// it along so the pair stays together.
			if valueFlags[name] && i+1 < len(args) {
				if next := args[i+1]; next != "--" && !strings.HasPrefix(next, "-") {
					flags = append(flags, next)
					i += 2
					continue
				}
			}
			i++
			continue
		}
		positionals = append(positionals, a)
		i++
	}
	return append(flags, positionals...)
}

func main() {
	var (
		useConfig        bool
		useStrictConfig  bool
		configFile       string
		strictConfigFile string
		parallelism      int
		quietMode        bool
		recursive        bool
		forceOverwrite   bool
		quickCheck       bool
		dryRun           bool
		jsonOutput       bool
		rawBytes         bool
		colorMode        string
		verbose          config.CountFlag
		vv               bool
		ignorePatterns   config.StringSlice
	)
	flag.BoolVar(&useConfig, "c", false, "Load .ghostconf from target directory")
	flag.BoolVar(&useStrictConfig, "cs", false, "Load .ghostconf (strict mode)")
	flag.StringVar(&configFile, "cf", "", "Load config from file")
	flag.StringVar(&strictConfigFile, "csf", "", "Load config from file (strict mode)")
	flag.IntVar(&parallelism, "p", runtime.NumCPU(), "Number of parallel workers")
	flag.BoolVar(&quietMode, "q", false, "Quiet mode")
	flag.BoolVar(&recursive, "r", false, "Process recursively")
	flag.BoolVar(&forceOverwrite, "f", false, "Force operations")
	flag.BoolVar(&quickCheck, "qc", false, "Quick check")
	flag.BoolVar(&dryRun, "d", false, "Dry run: show what would happen without writing")
	flag.BoolVar(&jsonOutput, "json", false, "Output results as JSON lines")
	flag.BoolVar(&rawBytes, "b", false, "Raw byte sizes in list output")
	flag.StringVar(&colorMode, "color", "auto", "Color output: auto, always, never")
	flag.Var(&verbose, "v", "Verbose output (repeatable)")
	flag.BoolVar(&vv, "vv", false, "Very verbose output (same as -v -v)")
	flag.Var(&ignorePatterns, "i", "Ignore pattern (can be used multiple times)")
	flag.CommandLine.Parse(hoistFlags(os.Args[1:]))

	mode, err := output.ParseColorMode(colorMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(2)
	}
	output.Configure(mode)

	if flag.NArg() < 1 {
		output.Help()
		os.Exit(2)
	}
	command := flag.Arg(0)

	// Commands that do not require a path argument.
	switch command {
	case "version":
		fmt.Printf("dataGhost %s\n", output.AppVersion)
		os.Exit(0)
	case "help":
		output.Help()
		os.Exit(0)
	case "completion":
		if flag.NArg() < 2 {
			fmt.Fprintf(os.Stderr, "usage: dataGhost completion bash|zsh|fish|powershell\n")
			os.Exit(2)
		}
		script, err := completion.Script(flag.Arg(1))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(2)
		}
		fmt.Print(script)
		os.Exit(0)
	}

	a := app.NewApp()
	a.AlwaysRehash = !isFlagSet("qc")
	a.DryRun = dryRun
	a.JSONOutput = jsonOutput
	a.RawBytes = rawBytes
	a.Verbosity = int(verbose)
	if vv {
		a.Verbosity += 2
	}

	// JSON mode implies quiet for terminal output.
	if a.JSONOutput {
		a.Config.Quiet = true
		a.Config.ShowProgress = false
	}

	if command == "init" {
		dir := "."
		if flag.NArg() >= 2 {
			dir = flag.Arg(1)
		}
		if isFlagSet("f") {
			a.Config.Force = forceOverwrite
		}
		if err := a.InitConfig(dir); err != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", output.TagFatal.String(), err)
			os.Exit(2)
		}
		os.Exit(0)
	}

	if flag.NArg() < 2 {
		output.Help()
		os.Exit(2)
	}
	path := flag.Arg(1)

	useAnyConfig := useConfig || useStrictConfig || configFile != "" || strictConfigFile != ""
	isStrict := useStrictConfig || strictConfigFile != ""
	finalCF := strictConfigFile
	if finalCF == "" {
		finalCF = configFile
	}

	if err := a.LoadConfig(finalCF, path, useAnyConfig, isStrict); err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to load config: %v\n", output.TagFatal.String(), err)
		os.Exit(2)
	}

	// Apply CLI ignore patterns after config is loaded.
	if len(ignorePatterns) > 0 {
		a.Config.Ignore = append(a.Config.Ignore, ignorePatterns...)
	}

	if isFlagSet("p") {
		if parallelism < 1 {
			fmt.Fprintf(os.Stderr, "%s Parallelism must be >= 1, got %d\n", output.TagFatal.String(), parallelism)
			os.Exit(2)
		}
		a.Config.Parallel = parallelism
	}
	if a.Config.Parallel < 1 {
		a.Config.Parallel = 1
	}
	if isFlagSet("q") {
		a.Config.Quiet = quietMode
	}
	if isFlagSet("f") {
		a.Config.Force = forceOverwrite
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var opErr error
	switch command {
	case "add":
		opErr = a.ProcessFiles(ctx, path, recursive,
			func(ctx context.Context, fp, gp, bp string) { a.AddF(ctx, fp, gp, bp) }, "add")
	case "del":
		opErr = a.ProcessFiles(ctx, path, recursive,
			func(ctx context.Context, fp, gp, bp string) { a.DelF(ctx, fp, gp, bp) }, "delete")
	case "check":
		if !a.AlwaysRehash {
			if a.JSONOutput {
				a.JSONLog(map[string]any{"event": "warning", "message": "Quick check mode: does NOT detect bit rot."})
			} else {
				a.Logt(output.TagWarning, "Quick check mode: does NOT detect bit rot.\n")
			}
		}
		opErr = a.ProcessFiles(ctx, path, recursive,
			func(ctx context.Context, fp, gp, bp string) { a.CheckF(ctx, fp, gp, bp) }, "check")
	case "clean":
		opErr = a.Clean(ctx, path, recursive)
	case "update":
		opErr = a.Update(ctx, path, recursive)
	case "list":
		opErr = a.ListGhosts(path, recursive)
	default:
		fmt.Fprintf(os.Stderr, "%s Unknown command: '%s'\n", output.TagError.String(), command)
		if s := output.SuggestCommand(command, commands); s != "" {
			fmt.Fprintf(os.Stderr, "  Did you mean '%s'?\n", s)
		}
		fmt.Fprintln(os.Stderr, "Run 'dataGhost help' for usage.")
		os.Exit(2)
	}

	interrupted := ctx.Err() != nil
	if interrupted {
		if a.JSONOutput {
			a.JSONLog(map[string]any{"event": "interrupted", "message": "Operation cancelled."})
		} else {
			a.Logt(output.TagInterrupted, "Operation cancelled.\n")
		}
	}

	if opErr != nil {
		if a.JSONOutput {
			a.JSONLog(map[string]any{"event": "fatal", "error": opErr.Error()})
		} else {
			fmt.Fprintf(os.Stderr, "%s %v\n", output.TagFatal.String(), opErr)
		}
		os.Exit(2)
	}

	if command != "list" {
		a.PrintSummary(command, interrupted)
	}

	exitCode := 0
	if a.Stats.Corrupted.Load() > 0 {
		exitCode = 1
	}
	if a.Stats.Missing.Load() > 0 && command == "check" {
		exitCode = 1
	}
	if a.Stats.Modified.Load() > 0 && command == "add" {
		exitCode = 1
	}
	if a.Stats.Errors.Load() > 0 {
		exitCode = 2
	}
	os.Exit(exitCode)
}
