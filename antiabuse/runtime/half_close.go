package runtime

import (
	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

// Protocols can expose half-close only after writing their handshake.
func (c *stream) nativeHalfWriter() N.WriteCloser {
	writer, _ := N.UnwrapCountWriter(c.ExtendedConn, nil)
	closer, _ := N.UnwrapWriter(writer).(N.WriteCloser)
	return closer
}

func (c *stream) WriterReplaceable() bool { return c.nativeHalfWriter() != nil }

// Unwrapping may discover a newly available half-close, but never raw data I/O.
func (c *stream) UpstreamWriter() any {
	if closer := c.nativeHalfWriter(); closer != nil {
		return &halfCloseWriter{stream: c, closer: closer}
	}
	return c
}

type halfCloseStream struct {
	*stream
	closer N.WriteCloser
}

func (c *halfCloseStream) CloseWrite() error { return c.closer.CloseWrite() }

type halfCloseWriter struct {
	stream *stream
	closer N.WriteCloser
}

func (w *halfCloseWriter) Write(data []byte) (int, error) { return w.stream.Write(data) }
func (w *halfCloseWriter) WriteBuffer(buffer *buf.Buffer) error {
	return w.stream.WriteBuffer(buffer)
}
func (w *halfCloseWriter) CloseWrite() error { return w.closer.CloseWrite() }
func (w *halfCloseWriter) CreateVectorisedWriter() (N.VectorisedWriter, bool) {
	return w.stream.CreateVectorisedWriter()
}
func (w *halfCloseWriter) FrontHeadroom() int { return w.stream.FrontHeadroom() }
func (w *halfCloseWriter) RearHeadroom() int  { return w.stream.RearHeadroom() }
func (w *halfCloseWriter) WriterMTU() int     { return w.stream.WriterMTU() }
