package network

import "net"

type Listener interface {
	net.Listener
	Listen(network string, addr string) error
}

type TcpListener struct {
	ln net.Listener
}

func (t *TcpListener) Listen(network string, addr string) error {
	ln, err := net.Listen(network, addr)
	t.ln = ln
	return err
}

// Accept waits for and returns the next connection to the listener.
func (t *TcpListener) Accept() (net.Conn, error) {
	return t.ln.Accept()
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (t *TcpListener) Close() error {
	if t.ln == nil {
		return nil
	}
	return t.ln.Close()
}

// Addr returns the listener's network address.
func (t *TcpListener) Addr() net.Addr {
	return t.ln.Addr()
}
