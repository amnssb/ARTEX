package cve

import (
	"bytes"
	"compress/gzip"
	"io"
)

// gzipReader wraps gz bytes for stream decoding.
func gzipReader(b []byte) (io.Reader, error) {
	return gzip.NewReader(bytes.NewReader(b))
}
