package output

import (
	"strings"
	"testing"
)

func TestTableWriter_AlignedColumns(t *testing.T) {
	tw := NewTableWriter()
	tw.Header("A", "BBBBB")
	tw.Row("XXXXX", "Y")
	result := tw.String()

	// Should have at least 3 spaces between columns (padding=3)
	lines := strings.Split(result, "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines, got %d", len(lines))
	}

	// Verify alignment - columns should line up
	headerBPos := strings.Index(lines[0], "BBBBB")
	rowYPos := strings.Index(lines[1], "Y")
	if headerBPos != rowYPos {
		t.Errorf("columns not aligned: header B at %d, row Y at %d", headerBPos, rowYPos)
	}
}

func TestTableWriter_MultipleRows(t *testing.T) {
	tw := NewTableWriter()
	tw.Header("NAME", "VALUE")
	tw.Row("first", "1")
	tw.Row("second", "2")
	tw.Row("third", "3")
	result := tw.String()

	lines := strings.Split(result, "\n")
	if len(lines) != 4 { // 1 header + 3 rows
		t.Errorf("expected 4 lines, got %d", len(lines))
	}

	if !strings.Contains(result, "first") {
		t.Error("expected first row")
	}
	if !strings.Contains(result, "second") {
		t.Error("expected second row")
	}
	if !strings.Contains(result, "third") {
		t.Error("expected third row")
	}
}
