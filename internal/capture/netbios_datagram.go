package capture

import "strings"

// netbiosNaamUitDatagram haalt de bronnaam uit een NetBIOS-bericht dat we
// passief opvangen.
//
// Twee vormen komen langs. Een name-service-pakket (UDP 137) draagt de
// naam als vraag of antwoord, direct achter de twaalf byte kop. Een
// datagram (UDP 138) heeft een eigen kop van veertien bytes en daarna de
// bronnaam. In beide gevallen staat de naam in NetBIOS' eigen codering:
// zestien bytes worden uitgeschreven als tweeëndertig letters, waarbij
// elke nibble bij 'A' wordt opgeteld.
func netbiosNaamUitDatagram(b []byte) string {
	for _, offset := range []int{12, 14} {
		if naam := decodeerNaam(b, offset); naam != "" {
			return naam
		}
	}
	return ""
}

func decodeerNaam(b []byte, p int) string {
	// Lengtebyte 0x20 betekent: hierna volgen 32 gecodeerde tekens.
	if p >= len(b) || b[p] != 0x20 || p+33 > len(b) {
		return ""
	}
	gecodeerd := b[p+1 : p+33]

	ruw := make([]byte, 0, 16)
	for i := 0; i < 32; i += 2 {
		hi, lo := gecodeerd[i], gecodeerd[i+1]
		if hi < 'A' || hi > 'P' || lo < 'A' || lo > 'P' {
			return "" // geen geldige NetBIOS-codering
		}
		ruw = append(ruw, (hi-'A')<<4|(lo-'A'))
	}

	// De laatste byte is het diensttype, niet een letter van de naam.
	naam := strings.TrimRight(string(ruw[:15]), " \x00")
	if naam == "" || naam == "*" {
		return ""
	}
	for i := 0; i < len(naam); i++ {
		if naam[i] < 32 || naam[i] == 127 {
			return ""
		}
	}
	return naam
}
