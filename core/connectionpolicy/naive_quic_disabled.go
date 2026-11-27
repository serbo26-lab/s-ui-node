//go:build !with_quic

package connectionpolicy

import (
	"context"
	"errors"
	"io"
)

func (h *naiveInbound) startHTTP3(context.Context) (io.Closer, error) {
	return nil, errors.New("QUIC is not included in this build")
}
