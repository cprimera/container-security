// Package socket provides utilities for length-prefixed protobuf message
// communication over a net.Conn (typically a Unix domain socket).
//
// Wire format:
//
//	[ 4 bytes big-endian uint32 – message length ][ N bytes protobuf message ]
package socket

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"google.golang.org/protobuf/proto"
)

const (
	// DefaultSocketPath is the default path for the Unix domain socket.
	DefaultSocketPath = "/tmp/container-security.sock"

	// maxMessageSize is the maximum allowed message size (16 MiB).
	maxMessageSize = 16 * 1024 * 1024
)

// WriteMessage serialises msg and writes it to conn with a 4-byte big-endian
// length prefix.
func WriteMessage(conn net.Conn, msg proto.Message) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	length := uint32(len(data))
	if err := binary.Write(conn, binary.BigEndian, length); err != nil {
		return fmt.Errorf("write length prefix: %w", err)
	}

	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("write message body: %w", err)
	}

	return nil
}

// ReadMessage reads a length-prefixed protobuf message from conn and
// unmarshals it into msg.
func ReadMessage(conn net.Conn, msg proto.Message) error {
	var length uint32
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return fmt.Errorf("read length prefix: %w", err)
	}

	if length > maxMessageSize {
		return fmt.Errorf("message too large: %d bytes (max %d)", length, maxMessageSize)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return fmt.Errorf("read message body: %w", err)
	}

	if err := proto.Unmarshal(data, msg); err != nil {
		return fmt.Errorf("unmarshal message: %w", err)
	}

	return nil
}
