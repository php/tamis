// Package skill embeds the triage method, which is also usable as an Agent Skill on its own.
package skill

import (
	"embed"
	"fmt"
	"slices"
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

// Packs joins the guidance of the built-in packs, each named after its file in packs/, once each in the given order.
func Packs(names []string) (string, error) {
	var guidance string
	for i, name := range names {
		if slices.Contains(names[:i], name) {
			continue
		}
		text, err := packs.ReadFile("packs/" + name + ".md")
		if err != nil {
			return "", fmt.Errorf("unknown pack %q", name)
		}
		guidance += "\n" + string(text)
	}

	return guidance, nil
}
