package output

import (
	"bytes"
	"strings"
	"text/tabwriter"
)

// TableWriter provides kubectl-style aligned column output using text/tabwriter.
type TableWriter struct {
	buf     bytes.Buffer
	w       *tabwriter.Writer
	hasData bool
}

// NewTableWriter creates a new TableWriter with standard kubectl-style settings.
// Settings: minwidth=0, tabwidth=0, padding=3, padchar=' ', flags=0
func NewTableWriter() *TableWriter {
	t := &TableWriter{}
	t.w = tabwriter.NewWriter(&t.buf, 0, 0, 3, ' ', 0)
	return t
}

// Header writes the header row with the given column names.
func (t *TableWriter) Header(columns ...string) {
	t.hasData = true
	_, _ = t.w.Write([]byte(strings.Join(columns, "\t") + "\n"))
}

// Row writes a data row with the given values.
func (t *TableWriter) Row(values ...string) {
	t.hasData = true
	_, _ = t.w.Write([]byte(strings.Join(values, "\t") + "\n"))
}

// String flushes the writer and returns the formatted output.
// Returns empty string if no data was written.
func (t *TableWriter) String() string {
	if !t.hasData {
		return ""
	}
	_ = t.w.Flush()
	return strings.TrimSuffix(t.buf.String(), "\n")
}
