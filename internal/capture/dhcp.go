package capture

import (
	"strings"

	"netwerksniffer/internal/oui"
)

// DHCPInfo is wat één DHCP-bericht over een apparaat prijsgeeft.
//
// Dit is de rijkste naambron die er is: een apparaat noemt hier zijn eigen
// hostnaam, en het doet dat ongevraagd. Een Deco die op mDNS, NetBIOS,
// SSDP én UPnP zwijgt, roept in zijn DHCP-verzoek gewoon "deco-M5".
type DHCPInfo struct {
	MAC string
	IP  string
	// Name is optie 12, de hostnaam die het apparaat zelf opgeeft.
	Name string
	// VendorClass is optie 60. Vaak een modelaanduiding, bijvoorbeeld
	// "MSFT 5.0" voor Windows of "udhcp 1.x" voor embedded Linux.
	VendorClass string
	// Type is de tekstsleutel van het soort bericht, voor het logboek.
	Type string
}

const dhcpMagic = 0x63825363

// DHCP-berichttypes uit optie 53 die ons iets vertellen. De waarden zijn
// tekstsleutels; de zin wordt pas op het scherm gemaakt.
var dhcpTypeNaam = map[byte]string{
	1: "dhcp.discover",
	2: "dhcp.offer",
	3: "dhcp.request",
	5: "dhcp.ack",
	7: "dhcp.release",
	8: "dhcp.inform",
}

// ParseDHCP leest een BOOTP/DHCP-bericht. Geeft false terug als het geen
// bruikbaar bericht is.
func ParseDHCP(b []byte) (DHCPInfo, bool) {
	var d DHCPInfo
	// Vaste kop: 236 bytes tot en met het file-veld, dan de magic cookie.
	if len(b) < 240 {
		return d, false
	}
	if uint32(b[236])<<24|uint32(b[237])<<16|uint32(b[238])<<8|uint32(b[239]) != dhcpMagic {
		return d, false
	}

	hlen := int(b[2])
	if hlen == 6 {
		// chaddr staat op offset 28. Dit MAC komt uit het protocol zelf en
		// is betrouwbaar — anders dan het adapteradres in een NetBIOS-
		// antwoord, dat we juist niet vertrouwen.
		d.MAC = oui.Normalize(hex6(b[28:34]))
	}

	// ciaddr (offset 12) is het adres dat de client al heeft; yiaddr
	// (offset 16) is wat de server toekent.
	if ip := ipv4(b[16:20]); ip != "0.0.0.0" {
		d.IP = ip
	} else if ip := ipv4(b[12:16]); ip != "0.0.0.0" {
		d.IP = ip
	}

	p := 240
	for p < len(b) {
		code := b[p]
		if code == 255 { // einde
			break
		}
		if code == 0 { // opvulling
			p++
			continue
		}
		if p+2 > len(b) {
			break
		}
		l := int(b[p+1])
		if p+2+l > len(b) {
			break
		}
		val := b[p+2 : p+2+l]

		switch code {
		case 12: // Host Name
			d.Name = schoonNaam(string(val))
		case 50: // Requested IP — bij een verzoek staat het adres hier
			if d.IP == "" && l == 4 {
				d.IP = ipv4(val)
			}
		case 53: // Message type
			if l == 1 {
				d.Type = dhcpTypeNaam[val[0]]
			}
		case 60: // Vendor class identifier
			d.VendorClass = schoonNaam(string(val))
		}
		p += 2 + l
	}

	return d, d.MAC != "" || d.IP != ""
}

// schoonNaam gooit stuurtekens weg en kapt af. Apparaten sturen hier van
// alles, en het komt ongefilterd op het scherm.
func schoonNaam(s string) string {
	s = strings.TrimRight(s, "\x00")
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r != 127 {
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if len(out) > 63 {
		out = out[:63]
	}
	return out
}

func ipv4(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	return itoa(int(b[0])) + "." + itoa(int(b[1])) + "." + itoa(int(b[2])) + "." + itoa(int(b[3]))
}

func hex6(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, 12)
	for i := 0; i < 6 && i < len(b); i++ {
		out = append(out, hexd[b[i]>>4], hexd[b[i]&0x0f])
	}
	return string(out)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
