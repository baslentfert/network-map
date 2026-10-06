// Command leasequery vraagt de DHCP-server rechtstreeks wat hij over een
// adres weet, volgens RFC 4388.
//
// Als dit werkt, is het de mooiste oplossing voor het naamprobleem: de
// server heeft de hostnaam uit het oorspronkelijke DHCP-verzoek bewaard,
// en we hoeven er niet maandenlang op te wachten of promiscuous voor mee
// te luisteren. Leasequery is alleen wél bedoeld voor access concentrators,
// dus de kans dat consumentenapparatuur het implementeert is klein.
//
// Precies daarom meten we het in plaats van erover te speculeren.
package main

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	"netwerksniffer/internal/netif"
)

const (
	dhcpLeaseQuery      = 10
	dhcpLeaseUnassigned = 11
	dhcpLeaseActive     = 12
	dhcpLeaseUnknown    = 13
)

var antwoordNaam = map[byte]string{
	5:                   "DHCPACK",
	6:                   "DHCPNAK",
	dhcpLeaseUnassigned: "DHCPLEASEUNASSIGNED (adres bekend, niemand gebruikt het)",
	dhcpLeaseActive:     "DHCPLEASEACTIVE (actieve lease — hier zit de informatie in)",
	dhcpLeaseUnknown:    "DHCPLEASEUNKNOWN (server kent dit adres niet)",
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("gebruik: leasequery <ip> [ip...]")
		os.Exit(2)
	}

	iface, err := netif.Primary()
	if err != nil {
		fmt.Fprintln(os.Stderr, "fout:", err)
		os.Exit(1)
	}
	server := iface.Gateway
	fmt.Printf("DHCP-server: %s, wij zijn %s\n\n", server, iface.IP)

	// RFC 4388 wil dat giaddr ons eigen adres is; het antwoord gaat daar
	// naartoe op poort 67. Poort 67 is op een client-pc normaal vrij — de
	// DHCP-client van Windows gebruikt 68.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 67})
	if err != nil {
		fmt.Printf("poort 67 niet beschikbaar (%v), we proberen een willekeurige poort\n\n", err)
		conn, err = net.ListenUDP("udp4", &net.UDPAddr{})
		if err != nil {
			fmt.Fprintln(os.Stderr, "geen socket:", err)
			os.Exit(1)
		}
	}
	defer conn.Close()

	doel := &net.UDPAddr{IP: net.ParseIP(server), Port: 67}
	for _, ip := range os.Args[1:] {
		vraag := bouwLeaseQuery(ip, iface.IP)
		if _, err := conn.WriteToUDP(vraag, doel); err != nil {
			fmt.Printf("%-15s versturen mislukt: %v\n", ip, err)
			continue
		}
		fmt.Printf("%-15s vraag verstuurd\n", ip)
	}

	fmt.Println("\nWachten op antwoord (5 s)...")
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	gekregen := 0
	for {
		n, van, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		gekregen++
		toon(buf[:n], van.IP.String())
	}

	if gekregen == 0 {
		fmt.Println("\nGeen enkel antwoord.")
		fmt.Println("Deze router ondersteunt DHCP Leasequery niet — zoals verwacht bij")
		fmt.Println("consumentenapparatuur. Deze route valt af.")
	}
}

func bouwLeaseQuery(doelIP, onsIP string) []byte {
	b := make([]byte, 240, 300)
	b[0] = 1 // BOOTREQUEST
	b[1] = 1 // ethernet
	b[2] = 6 // MAC-lengte
	xid := rand.Uint32()
	b[4], b[5], b[6], b[7] = byte(xid>>24), byte(xid>>16), byte(xid>>8), byte(xid)

	// ciaddr = het adres waar we naar vragen (query by IP address).
	copy(b[12:16], net.ParseIP(doelIP).To4())
	// giaddr = wijzelf; daar stuurt de server z'n antwoord naartoe.
	copy(b[24:28], net.ParseIP(onsIP).To4())

	// magic cookie
	b[236], b[237], b[238], b[239] = 0x63, 0x82, 0x53, 0x63

	b = append(b, 53, 1, dhcpLeaseQuery)
	// Parameter request list: vraag expliciet om de hostnaam (12), de
	// vendor class (60) en de client identifier (61).
	b = append(b, 55, 3, 12, 60, 61)
	b = append(b, 255)
	return b
}

func toon(b []byte, van string) {
	if len(b) < 240 {
		fmt.Printf("\n%s: te kort antwoord (%d bytes)\n", van, len(b))
		return
	}
	yiaddr := net.IP(b[16:20]).String()
	ciaddr := net.IP(b[12:16]).String()

	var soort byte
	var naam, vendor string
	p := 240
	for p < len(b) {
		code := b[p]
		if code == 255 {
			break
		}
		if code == 0 {
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
		case 53:
			if l == 1 {
				soort = val[0]
			}
		case 12:
			naam = strings.TrimRight(string(val), "\x00")
		case 60:
			vendor = strings.TrimRight(string(val), "\x00")
		}
		p += 2 + l
	}

	label := antwoordNaam[soort]
	if label == "" {
		label = fmt.Sprintf("type %d", soort)
	}
	fmt.Printf("\nANTWOORD van %s\n", van)
	fmt.Printf("  soort   : %s\n", label)
	fmt.Printf("  ciaddr  : %s\n", ciaddr)
	fmt.Printf("  yiaddr  : %s\n", yiaddr)
	if naam != "" {
		fmt.Printf("  HOSTNAAM: %s   <<< dit is wat we zochten\n", naam)
	}
	if vendor != "" {
		fmt.Printf("  vendor  : %s\n", vendor)
	}
	if naam == "" {
		fmt.Printf("  (geen optie 12 in het antwoord)\n")
	}
}
