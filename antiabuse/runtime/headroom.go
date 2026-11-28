package runtime

import N "github.com/sagernet/sing/common/network"

// Preserve protocol buffer requirements without exposing an unguarded upstream.
func (c *stream) FrontHeadroom() int  { return N.CalculateFrontHeadroom(c.ExtendedConn) }
func (c *stream) RearHeadroom() int   { return N.CalculateRearHeadroom(c.ExtendedConn) }
func (c *stream) ReaderOverhead() int { return N.CalculateReaderOverhead(c.ExtendedConn) }
func (c *stream) ReaderMTU() int      { return N.CalculateMTU(c.ExtendedConn, nil) }
func (c *stream) WriterMTU() int      { return N.CalculateMTU(nil, c.ExtendedConn) }

func (c *packet) FrontHeadroom() int  { return N.CalculateFrontHeadroom(c.PacketConn) }
func (c *packet) RearHeadroom() int   { return N.CalculateRearHeadroom(c.PacketConn) }
func (c *packet) ReaderOverhead() int { return N.CalculateReaderOverhead(c.PacketConn) }
func (c *packet) ReaderMTU() int      { return N.CalculateMTU(c.PacketConn, nil) }
func (c *packet) WriterMTU() int      { return N.CalculateMTU(nil, c.PacketConn) }
