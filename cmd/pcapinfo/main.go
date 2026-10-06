// Command pcapinfo leest een opname terug en vat samen wat erin zit.
//
// Twee doelen. Het controleert of het bestand werkelijk een geldige pcap
// is — bytes op schijf zeggen niets, alleen terugleven bewijst het. En het
// geeft je een eerste blik zonder Wireshark: wie praat met wie, welke
// protocollen, hoeveel.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"time"
)

const magicLE = 0xa1b2c3d4

var linknaam = map[uint32]string{1: "Ethernet", 101: "kale IP-pakketten", 228: "Raw IPv4"}

type paar struct{ van, naar string }

func main() {
	if len(os.Args) < 2 {
		fmt.Println("gebruik: pcapinfo <bestand.pcap>")
		os.Exit(2)
	}
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "fout:", err)
		os.Exit(1)
	}
	if len(b) < 24 {
		fmt.Fprintln(os.Stderr, "fout: te klein voor een pcap-kop")
		os.Exit(1)
	}

	magic := binary.LittleEndian.Uint32(b[0:])
	if magic != magicLE {
		fmt.Fprintf(os.Stderr, "fout: geen pcap-bestand (magic %08x)\n", magic)
		os.Exit(1)
	}
	major := binary.LittleEndian.Uint16(b[4:])
	minor := binary.LittleEndian.Uint16(b[6:])
	snaplen := binary.LittleEndian.Uint32(b[16:])
	lt := binary.LittleEndian.Uint32(b[20:])

	naam := linknaam[lt]
	if naam == "" {
		naam = fmt.Sprintf("linktype %d", lt)
	}
	fmt.Printf("Geldig pcap-bestand, versie %d.%d\n", major, minor)
	fmt.Printf("Inhoud    %s\n", naam)
	fmt.Printf("Snaplen   %d bytes\n\n", snaplen)

	protocol := map[string]int{}
	paren := map[paar]int{}
	poorten := map[uint16]int{}
	var eerste, laatste time.Time
	n, afgekapt := 0, 0

	p := 24
	for p+16 <= len(b) {
		sec := binary.LittleEndian.Uint32(b[p:])
		usec := binary.LittleEndian.Uint32(b[p+4:])
		incl := int(binary.LittleEndian.Uint32(b[p+8:]))
		orig := int(binary.LittleEndian.Uint32(b[p+12:]))
		p += 16
		if incl < 0 || p+incl > len(b) {
			fmt.Fprintf(os.Stderr, "waarschuwing: afgebroken bij pakket %d\n", n+1)
			break
		}
		pkt := b[p : p+incl]
		p += incl
		n++

		t := time.Unix(int64(sec), int64(usec)*1000)
		if eerste.IsZero() {
			eerste = t
		}
		laatste = t
		if orig > incl {
			afgekapt++
		}

		// Kale IP: de versie staat in de bovenste vier bits.
		if len(pkt) < 20 || pkt[0]>>4 != 4 {
			protocol["niet-IPv4"]++
			continue
		}
		hl := int(pkt[0]&0x0f) * 4
		if hl < 20 || len(pkt) < hl {
			protocol["beschadigd"]++
			continue
		}
		src := fmt.Sprintf("%d.%d.%d.%d", pkt[12], pkt[13], pkt[14], pkt[15])
		dst := fmt.Sprintf("%d.%d.%d.%d", pkt[16], pkt[17], pkt[18], pkt[19])
		paren[paar{src, dst}]++

		switch pkt[9] {
		case 1:
			protocol["ICMP"]++
		case 6:
			protocol["TCP"]++
			if len(pkt) >= hl+4 {
				poorten[laagste(binary.BigEndian.Uint16(pkt[hl:]), binary.BigEndian.Uint16(pkt[hl+2:]))]++
			}
		case 17:
			protocol["UDP"]++
			if len(pkt) >= hl+4 {
				poorten[laagste(binary.BigEndian.Uint16(pkt[hl:]), binary.BigEndian.Uint16(pkt[hl+2:]))]++
			}
		default:
			protocol[fmt.Sprintf("protocol %d", pkt[9])]++
		}
	}

	duur := laatste.Sub(eerste)
	fmt.Printf("%d pakketten over %s (%s – %s)\n", n, duur.Round(time.Second),
		eerste.Format("15:04:05"), laatste.Format("15:04:05"))
	if afgekapt > 0 {
		fmt.Printf("%d pakketten afgekapt door snaplen\n", afgekapt)
	}

	fmt.Printf("\nProtocollen:\n")
	for _, k := range gesorteerd(protocol) {
		fmt.Printf("  %-14s %6d\n", k.sleutel, k.aantal)
	}

	fmt.Printf("\nDrukste gesprekken:\n")
	type pr struct {
		p paar
		n int
	}
	var lijst []pr
	for k, v := range paren {
		lijst = append(lijst, pr{k, v})
	}
	sort.Slice(lijst, func(a, b int) bool { return lijst[a].n > lijst[b].n })
	for i, l := range lijst {
		if i >= 10 {
			break
		}
		fmt.Printf("  %-16s → %-16s %6d\n", l.p.van, l.p.naar, l.n)
	}

	fmt.Printf("\nDrukste poorten:\n")
	type pp struct {
		poort uint16
		n     int
	}
	var pl []pp
	for k, v := range poorten {
		pl = append(pl, pp{k, v})
	}
	sort.Slice(pl, func(a, b int) bool { return pl[a].n > pl[b].n })
	for i, x := range pl {
		if i >= 8 {
			break
		}
		fmt.Printf("  %-6d %6d\n", x.poort, x.n)
	}
}

// laagste kiest de laagste van bron- en doelpoort: dat is vrijwel altijd
// de dienst, en de andere een tijdelijke poort van de client.
func laagste(a, b uint16) uint16 {
	if a < b {
		return a
	}
	return b
}

type telling struct {
	sleutel string
	aantal  int
}

func gesorteerd(m map[string]int) []telling {
	var uit []telling
	for k, v := range m {
		uit = append(uit, telling{k, v})
	}
	sort.Slice(uit, func(a, b int) bool { return uit[a].aantal > uit[b].aantal })
	return uit
}
