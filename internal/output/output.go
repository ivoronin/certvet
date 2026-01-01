package output

// Format represents the output format type.
type Format int

const (
	FormatText Format = iota
	FormatJSON
)

// Formatter is the interface for output formatters.
// Types implementing this interface can output in text or JSON format.
type Formatter interface {
	FormatText() string
	FormatJSON() ([]byte, error)
}

// FormatOutput formats the given Formatter based on the specified format.
func FormatOutput(f Formatter, format Format) (string, error) {
	switch format {
	case FormatJSON:
		data, err := f.FormatJSON()
		if err != nil {
			return "", err
		}
		return string(data), nil
	default:
		return f.FormatText(), nil
	}
}
