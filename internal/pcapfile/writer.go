// Package pcapfile schrijft opnames weg in het klassieke pcap-formaat.
//
// Bewust dat formaat en niet iets eigens: elk analysegereedschap leest
// het, Wireshark voorop. Wij nemen op, zij analyseren — daar zijn ze
// twintig jaar beter in dan wij ooit worden.
//
// Het formaat is simpel: een kop van 24 bytes, en daarna per pakket een
// kop van 16 bytes gevolgd door de ruwe bytes.
package pcapfile

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Linktype zegt wat er in elk pakket zit. Dat moet kloppen, anders ziet
// Wireshark onzin.
type Linktype uint32

const (
	// LinkRaw: een kale IP-pakket zonder ethernetkop. Dat is wat een
	// Windows raw socket met SIO_RCVALL oplevert.
	LinkRaw Linktype = 101
	// LinkEthernet: volledige ethernetframes, zoals Npcap ze geeft.
	// Daar zit ook ARP en LLDP in, wat via raw sockets onbereikbaar is.
	LinkEthernet Linktype = 1
)

const magic = 0xa1b2c3d4

// Schrijver schrijft pakketten naar een pcap-bestand. Veilig voor gebruik
// vanuit meerdere goroutines.
type Schrijver struct {
	mu      sync.Mutex
	f       *os.File
	buf     *bufio.Writer
	snaplen uint32

	pakketten uint64
	bytes     uint64
	gesloten  bool
}

// Maak opent een nieuw bestand en schrijft de kop.
//
// snaplen begrenst hoeveel van elk pakket bewaard wordt. 65535 is alles;
// een kleinere waarde houdt het bestand klein als je alleen de koppen wilt
// zien en niet de inhoud.
func Maak(pad string, lt Linktype, snaplen uint32) (*Schrijver, error) {
	if snaplen == 0 {
		snaplen = 65535
	}
	f, err := os.Create(pad)
	if err != nil {
		return nil, fmt.Errorf("opnamebestand aanmaken: %w", err)
	}
	s := &Schrijver{f: f, buf: bufio.NewWriterSize(f, 1<<16), snaplen: snaplen}

	kop := make([]byte, 24)
	binary.LittleEndian.PutUint32(kop[0:], magic)
	binary.LittleEndian.PutUint16(kop[4:], 2) // hoofdversie
	binary.LittleEndian.PutUint16(kop[6:], 4) // subversie
	binary.LittleEndian.PutUint32(kop[8:], 0) // tijdzone: altijd UTC-offset 0
	binary.LittleEndian.PutUint32(kop[12:], 0)
	binary.LittleEndian.PutUint32(kop[16:], snaplen)
	binary.LittleEndian.PutUint32(kop[20:], uint32(lt))

	if _, err := s.buf.Write(kop); err != nil {
		f.Close()
		return nil, err
	}
	return s, nil
}

// Schrijf legt één pakket vast.
//
// origLen is de lengte zoals hij op de draad was; die kan groter zijn dan
// wat we bewaren als snaplen lager staat. Wireshark toont dan netjes dat
// het pakket afgekapt is in plaats van een beschadigd pakket te melden.
func (s *Schrijver) Schrijf(t time.Time, data []byte, origLen int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gesloten {
		return io.ErrClosedPipe
	}

	n := len(data)
	if uint32(n) > s.snaplen {
		n = int(s.snaplen)
	}
	if origLen < n {
		origLen = n
	}

	var kop [16]byte
	binary.LittleEndian.PutUint32(kop[0:], uint32(t.Unix()))
	binary.LittleEndian.PutUint32(kop[4:], uint32(t.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(kop[8:], uint32(n))
	binary.LittleEndian.PutUint32(kop[12:], uint32(origLen))

	if _, err := s.buf.Write(kop[:]); err != nil {
		return err
	}
	if _, err := s.buf.Write(data[:n]); err != nil {
		return err
	}
	s.pakketten++
	s.bytes += uint64(n)
	return nil
}

// Stand geeft hoeveel er tot nu toe is weggeschreven.
func (s *Schrijver) Stand() (pakketten, bytes uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pakketten, s.bytes
}

// Sluit maakt de buffer leeg en sluit het bestand. Zonder dit mist het
// laatste stuk van de opname.
func (s *Schrijver) Sluit() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gesloten {
		return nil
	}
	s.gesloten = true
	if err := s.buf.Flush(); err != nil {
		s.f.Close()
		return err
	}
	return s.f.Close()
}
