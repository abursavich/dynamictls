// Copyright 2020 Andrew Bursavich. All rights reserved.
// Use of this source code is governed by The MIT License
// which can be found in the LICENSE file.

package syscallconn

import (
	"crypto/tls"
	"net"
	"syscall"
)

type syscallConn = syscall.Conn

type wrapperConn struct {
	*tls.Conn
	syscallConn // alias is required because embedded field names syscall.Conn and tls.Conn collide
}

// Wrap tries to wrap rawConn and tlsConn into a net.Conn that implements syscall.Conn.
// rawConn will be used to support syscall and tlsConn will be used for read/write.
func Wrap(rawConn net.Conn, tlsConn *tls.Conn) net.Conn {
	sysConn, ok := rawConn.(syscall.Conn)
	if !ok {
		return tlsConn
	}
	return &wrapperConn{
		Conn:        tlsConn,
		syscallConn: sysConn,
	}
}
