package logutil

import (
	"fmt"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// Formatter is used to by the logrus package to provide a custom logger
type Formatter struct {
	Project         string
	TimestampFormat string
}

const (
	colorDebug = "\x1b[0;34m%s\x1b[0m"
	colorInfo  = "\x1b[0;32m%s\x1b[0m"
	colorWarn  = "\x1b[0;33m%s\x1b[0m"
	colorError = "\x1b[0;31m%s\x1b[0m"
	colorFatal = "\x1b[0;31m%s\x1b[0m"
)

func init() {
	level := os.Getenv("SECURE_LOG_LEVEL")
	log.SetLevel(log.InfoLevel)
	if level != "" {
		logLevel, err := log.ParseLevel(level)

		if err != nil {
			// Log error without stopping.
			log.Error(err)
		} else {
			log.SetLevel(logLevel)
		}
	}
}

// Format creates a custom log formatter so we can colorize and format the output
func (f *Formatter) Format(entry *log.Entry) ([]byte, error) {
	formattedLevel := strings.ToUpper(entry.Level.String()[0:4])

	colorFormatString := func() string {
		switch entry.Level {
		case log.InfoLevel:
			return colorInfo
		case log.WarnLevel:
			return colorWarn
		case log.ErrorLevel:
			return colorError
		case log.DebugLevel:
			return colorDebug
		case log.FatalLevel:
			return colorFatal
		}

		return colorError
	}()

	timestampFormat := time.RFC3339
	if f.TimestampFormat != "" {
		timestampFormat = f.TimestampFormat
	}

	logEntry := fmt.Sprintf("[%s] [%s] ▶ %s\n", formattedLevel, entry.Time.Format(timestampFormat), entry.Message)
	if f.Project != "" {
		logEntry = fmt.Sprintf("[%s] [%s] [%s] ▶ %s\n", formattedLevel, f.Project, entry.Time.Format(timestampFormat), entry.Message)
	}

	coloredLogEntry := fmt.Sprintf(colorFormatString, logEntry)

	return []byte(coloredLogEntry), nil
}
