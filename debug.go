package ldapserver

import (
	"log"

	"github.com/mark-rushakoff/ldapserver/internal/asn1-ber"
)

// debbuging type
//     - has a Printf method to write the debug output
type debugging bool

// write debug output
func (debug debugging) Printf(format string, args ...interface{}) {
	if debug {
		log.Printf(format, args...)
	}
}

func (debug debugging) PrintPacket(packet *ber.Packet) {
	if debug {
		ber.PrintPacket(packet)
	}
}
