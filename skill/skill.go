// Package skill embeds the triage method, which is also usable as an Agent Skill on its own.
package skill

import (
	"embed"
	"fmt"
)

// Text is the method of the reader, which sees the report.
//
//go:embed SKILL.md
var Text string

// Compare is the method of the comparator, which searches the other advisories for duplicates.
//
//go:embed compare.md
var Compare string

// Confirm is the method for checking one candidate in a separate context.
//
//go:embed confirm.md
var Confirm string

//go:embed packs/*.md
var packs embed.FS

// Pack returns the guidance of a built-in pack, named after its file in packs/.
func Pack(name string) (string, error) {
	text, err := packs.ReadFile("packs/" + name + ".md")
	if err != nil {
		return "", fmt.Errorf("unknown pack %q", name)
	}

	return string(text), nil
}
