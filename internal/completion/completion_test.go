package completion

import (
	"strings"
	"testing"
)

func TestScriptAllShells(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		s, err := Script(shell)
		if err != nil {
			t.Fatalf("Script(%q): %v", shell, err)
		}
		if !strings.Contains(s, "dataGhost") {
			t.Errorf("Script(%q) does not mention dataGhost", shell)
		}
		// Every script must know the core subcommands.
		for _, cmd := range []string{"add", "check", "del", "list"} {
			if !strings.Contains(s, cmd) {
				t.Errorf("Script(%q) missing subcommand %q", shell, cmd)
			}
		}
	}
}

func TestScriptUnknownShell(t *testing.T) {
	if _, err := Script("tcsh"); err == nil {
		t.Error("Script(tcsh) should return an error")
	}
}
