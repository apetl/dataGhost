// Copyright (c) 2026 apetl.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package completion provides hand-written shell completion scripts.
package completion

import "fmt"

// Script returns the completion script for the given shell
// ("bash", "zsh", "fish", or "powershell").
func Script(shell string) (string, error) {
	switch shell {
	case "bash":
		return bashScript, nil
	case "zsh":
		return zshScript, nil
	case "fish":
		return fishScript, nil
	case "powershell", "pwsh":
		return powershellScript, nil
	default:
		return "", fmt.Errorf("unknown shell %q: supported shells are bash, zsh, fish, powershell", shell)
	}
}

const bashScript = `# bash completion for dataGhost
_dataGhost() {
    local cur prev cmds opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    cmds="add del check clean update list init version help completion"
    opts="-c -cs -cf -csf -r -q -qc -p -f -d -v -b --json --color -i"

    case "$prev" in
        --color)
            COMPREPLY=( $(compgen -W "auto always never" -- "$cur") )
            return 0
            ;;
        -cf|-csf)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0
            ;;
        completion)
            COMPREPLY=( $(compgen -W "bash zsh fish powershell" -- "$cur") )
            return 0
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
        return 0
    fi

    local have_cmd=0 w
    for w in "${COMP_WORDS[@]:1:COMP_CWORD-1}"; do
        case " $cmds " in *" $w "*) have_cmd=1 ;; esac
    done
    if [[ $have_cmd -eq 0 ]]; then
        COMPREPLY=( $(compgen -W "$cmds $opts" -- "$cur") )
    else
        COMPREPLY=( $(compgen -f -- "$cur") )
    fi
}
complete -F _dataGhost dataGhost
`

const zshScript = `#compdef dataGhost
# zsh completion for dataGhost
_dataGhost() {
    local -a commands
    commands=(
        'add:Add files to tracking'
        'del:Remove files from tracking'
        'check:Verify file integrity'
        'clean:Remove missing file entries'
        'update:Update old .ghost files with metadata'
        'list:List tracked files'
        'init:Create a .ghostconf template'
        'version:Print version information'
        'help:Show help'
        'completion:Print a shell completion script'
    )
    _arguments \
        '-c[Load .ghostconf from target directory]' \
        '-cs[Strict mode]' \
        '-cf[Load config from file]:config file:_files' \
        '-csf[Load config from file (strict)]:config file:_files' \
        '-r[Process recursively]' \
        '-q[Quiet mode]' \
        '-qc[Quick check]' \
        '-p[Parallel workers]:workers:' \
        '-f[Force operations]' \
        '-d[Dry run]' \
        '-v[Verbose output]' \
        '-b[Raw byte sizes]' \
        '--json[JSON output]' \
        '--color[Color mode]:mode:(auto always never)' \
        '-i[Ignore pattern]:pattern:' \
        '1:command:->cmd' \
        '*:path:_files'
    case $state in
        cmd) _describe 'command' commands ;;
    esac
}
compdef _dataGhost dataGhost
`

const fishScript = `# fish completion for dataGhost
complete -c dataGhost -n __fish_use_subcommand -a add -d 'Add files to tracking'
complete -c dataGhost -n __fish_use_subcommand -a del -d 'Remove files from tracking'
complete -c dataGhost -n __fish_use_subcommand -a check -d 'Verify file integrity'
complete -c dataGhost -n __fish_use_subcommand -a clean -d 'Remove missing file entries'
complete -c dataGhost -n __fish_use_subcommand -a update -d 'Update old .ghost files with metadata'
complete -c dataGhost -n __fish_use_subcommand -a list -d 'List tracked files'
complete -c dataGhost -n __fish_use_subcommand -a init -d 'Create a .ghostconf template'
complete -c dataGhost -n __fish_use_subcommand -a version -d 'Print version information'
complete -c dataGhost -n __fish_use_subcommand -a help -d 'Show help'
complete -c dataGhost -n __fish_use_subcommand -a completion -d 'Print a shell completion script'
complete -c dataGhost -s c -d 'Load .ghostconf from target directory'
complete -c dataGhost -o cs -d 'Strict mode'
complete -c dataGhost -o cf -r -d 'Load config from file'
complete -c dataGhost -o csf -r -d 'Load config from file (strict)'
complete -c dataGhost -s r -d 'Process recursively'
complete -c dataGhost -s q -d 'Quiet mode'
complete -c dataGhost -o qc -d 'Quick check'
complete -c dataGhost -s p -x -d 'Parallel workers'
complete -c dataGhost -s f -d 'Force operations'
complete -c dataGhost -s d -d 'Dry run'
complete -c dataGhost -s v -d 'Verbose output'
complete -c dataGhost -s b -d 'Raw byte sizes'
complete -c dataGhost -l json -d 'JSON output'
complete -c dataGhost -l color -xa 'auto always never' -d 'Color mode'
complete -c dataGhost -s i -x -d 'Ignore pattern'
`

const powershellScript = `# PowerShell completion for dataGhost
Register-ArgumentCompleter -Native -CommandName dataGhost -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $commands = 'add','del','check','clean','update','list','init','version','help','completion'
    $flags = '-c','-cs','-cf','-csf','-r','-q','-qc','-p','-f','-d','-v','-b','--json','--color','-i'
    $candidates = if ($wordToComplete -like '-*') { $flags } else { $commands + $flags }
    $candidates |
        Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
}
`
