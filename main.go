package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"dataGhost/internal/app"
	"dataGhost/internal/output"
)

func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func main() {
	output.InitColors()

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
	flag.Parse()

	if flag.NArg() < 2 {
		output.Help()
		os.Exit(2)
	}
	command := flag.Arg(0)
	path := flag.Arg(1)

	a := app.NewApp()
	a.AlwaysRehash = !isFlagSet("qc")

	useAnyConfig := useConfig || useStrictConfig || configFile != "" || strictConfigFile != ""
	isStrict := useStrictConfig || strictConfigFile != ""
	finalCF := strictConfigFile
	if finalCF == "" {
		finalCF = configFile
	}

	if err := a.LoadConfig(finalCF, path, useAnyConfig, isStrict); err != nil {
		fmt.Printf("%s[FATAL]%s Failed to load config: %v\n", output.ColorRed, output.ColorReset, err)
		os.Exit(2)
	}

	if isFlagSet("p") {
		if parallelism < 1 {
			fmt.Printf("%s[FATAL]%s Parallelism must be >= 1, got %d\n", output.ColorRed, output.ColorReset, parallelism)
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
			fmt.Printf("%s[WARNING]%s Quick check mode: does NOT detect bit rot.\n", output.ColorYellow, output.ColorReset)
		}
		opErr = a.ProcessFiles(ctx, path, recursive,
			func(ctx context.Context, fp, gp, bp string) { a.CheckF(ctx, fp, gp, bp) }, "check")
	case "clean":
		opErr = a.Clean(ctx, path, recursive)
	case "update":
		opErr = a.Update(ctx, path, recursive)
	default:
		fmt.Printf("%s[ERROR]%s Unknown command: %s\n", output.ColorRed, output.ColorReset, command)
		output.Help()
		os.Exit(2)
	}

	if ctx.Err() != nil {
		fmt.Printf("\n%s[INTERRUPTED]%s Operation cancelled.\n", output.ColorYellow, output.ColorReset)
	}

	if opErr != nil {
		fmt.Printf("%s[FATAL]%s %v\n", output.ColorRed, output.ColorReset, opErr)
		os.Exit(2)
	}

	if !a.Config.Quiet {
		a.PrintSummary()
	}

	exitCode := 0
	if a.Stats.Corrupted.Load() > 0 {
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
