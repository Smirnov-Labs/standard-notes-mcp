package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
)

// noteFields is what a restored note must share with its export entry.
type noteFields struct{ Title, Text string }

// Usage: SN_EMAIL=.. SN_PASSWORD=.. [SN_SERVER=..] sn-verify <decrypted-export.txt>
// Exits 0 only if the restored account holds the same notes as the decrypted
// export: same count, same ids, and every note's title and body byte-match.
func main() {
	if len(os.Args) != 2 {
		fail(fmt.Errorf("usage: SN_EMAIL=.. SN_PASSWORD=.. sn-verify <decrypted-export.txt>"))
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fail(err)
	}
	var export struct {
		Items []struct {
			UUID        string `json:"uuid"`
			ContentType string `json:"content_type"`
			Deleted     bool   `json:"deleted"`
			Content     struct {
				Title string `json:"title"`
				Text  string `json:"text"`
			} `json:"content"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &export); err != nil {
		fail(fmt.Errorf("parse export: %w", err))
	}
	exportNotes := map[string]noteFields{}
	for _, it := range export.Items {
		// Skip deleted items: Fetch never returns them, so counting them here
		// would make the two sides disagree.
		if it.ContentType == "Note" && !it.Deleted {
			exportNotes[it.UUID] = noteFields{Title: it.Content.Title, Text: it.Content.Text}
		}
	}
	// An export with no notes proves nothing: it would "match" an empty restore.
	if len(exportNotes) == 0 {
		fail(fmt.Errorf("the export contains no notes; wrong file? (this tool needs the DECRYPTED export)"))
	}

	c, err := snclient.SignIn(snclient.Config{Server: snclient.EnvServer()},
		os.Getenv("SN_EMAIL"), os.Getenv("SN_PASSWORD"), func(string) (string, error) { return "", nil })
	if err != nil {
		fail(fmt.Errorf("sign in: %w", err))
	}
	notes, _, err := c.Fetch()
	if err != nil {
		fail(fmt.Errorf("fetch: %w", err))
	}

	if len(notes) != len(exportNotes) {
		fail(fmt.Errorf("count mismatch: restored %d notes, export has %d", len(notes), len(exportNotes)))
	}
	titleDiff, bodyDiff, unknown := 0, 0, 0
	for _, n := range notes {
		want, ok := exportNotes[n.UUID]
		if !ok {
			unknown++
			continue
		}
		// Check title and body apart. A restore that garbles only one of them
		// still fails.
		if want.Title != n.Title {
			titleDiff++
		}
		if want.Text != n.Text {
			bodyDiff++
		}
	}
	// The counts are equal here, so a restored note with no match in the export
	// means an export note was not restored. Without this check that note would
	// be skipped and never compared.
	if unknown > 0 {
		fail(fmt.Errorf("restored notes with ids that are not in the export: %d", unknown))
	}
	if titleDiff > 0 || bodyDiff > 0 {
		fail(fmt.Errorf("restored notes do not match the export: %d titles differ, %d bodies differ", titleDiff, bodyDiff))
	}
	fmt.Printf("OK: %d notes, titles and bodies match\n", len(notes))
}

func fail(err error) { fmt.Fprintln(os.Stderr, "RESTORE VERIFY FAILED:", err); os.Exit(1) }
