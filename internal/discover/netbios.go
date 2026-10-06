package discover

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"netwerksniffer/internal/oui"
)

// NetBIOSResult is het antwoord van één host op een node status query.
type NetBIOSResult struct {
	IP        string
	Name      string
	Workgroup string
	// MAC komt gratis mee in het antwoord — handig voor hosts die buiten
	// onze ARP-cache vallen.
	MAC string
}

// nbstatQuery bouwt een NetBIOS node status request.
//
// De vraagnaam is het jokerteken "*", en dat moet in NetBIOS' eigen
// codering: de 16-byte naam wordt per byte in twee nibbles gesplitst en
// elk nibble opgeteld bij 'A'. Zo wordt 0x2A ('*') het paar "CK", en de
// vijftien nulbytes erachter worden "AA" — samen de 32 tekens hieronder.
func nbstatQuery(txid uint16) []byte {
	b := make([]byte, 0, 50)
	b = append(b, byte(txid>>8), byte(txid))
	b = append(b, 0x00, 0x00) // vlaggen: standaard query
	b = append(b, 0x00, 0x01) // 1 vraag
	b = append(b, 0, 0, 0, 0, 0, 0)
	b = append(b, 0x20) // labellengte 32
	b = append(b, "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"...)
	b = append(b, 0x00)       // einde naam
	b = append(b, 0x00, 0x21) // NBSTAT
	b = append(b, 0x00, 0x01) // klasse IN
	return b
}

func parseNBStat(buf []byte, ip string) (NetBIOSResult, bool) {
	r := NetBIOSResult{IP: ip}
	if len(buf) < 12 {
		return r, false
	}
	qd := int(buf[4])<<8 | int(buf[5])
	an := int(buf[6])<<8 | int(buf[7])
	if an < 1 {
		return r, false
	}

	p := 12
	skipNaam := func() bool {
		for p < len(buf) {
			l := int(buf[p])
			if l == 0 {
				p++
				return true
			}
			if l&0xC0 == 0xC0 { // compressiepointer
				p += 2
				return true
			}
			p += 1 + l
		}
		return false
	}
	for i := 0; i < qd; i++ {
		if !skipNaam() || p+4 > len(buf) {
			return r, false
		}
		p += 4
	}
	if !skipNaam() || p+10 > len(buf) {
		return r, false
	}
	p += 8 // type, klasse, ttl
	rdlen := int(buf[p])<<8 | int(buf[p+1])
	p += 2
	if p+rdlen > len(buf) || rdlen < 1 {
		return r, false
	}

	aantal := int(buf[p])
	p++
	volledig := true
	for i := 0; i < aantal; i++ {
		if p+18 > len(buf) {
			volledig = false
			break
		}
		naam := strings.TrimRight(string(buf[p:p+15]), " \x00")
		suffix := buf[p+15]
		vlaggen := uint16(buf[p+16])<<8 | uint16(buf[p+17])
		groep := vlaggen&0x8000 != 0
		p += 18

		// Suffix 0x00 is de computer- of werkgroepnaam; het verschil zit in
		// de groepsvlag. Andere suffixen zijn dienstregistraties waar we
		// hier niets aan hebben.
		if suffix != 0x00 || naam == "" {
			continue
		}
		if groep {
			if r.Workgroup == "" {
				r.Workgroup = naam
			}
		} else if r.Name == "" {
			r.Name = naam
		}
	}

	// Direct achter de namenlijst staat het MAC-adres van de adapter.
	//
	// Alleen uitlezen als we de hele namenlijst hebben doorgelopen: bij een
	// afgekapt antwoord staat p op een willekeurige plek en lezen we zes
	// bytes ruis. Zo'n verzonnen MAC is erger dan geen MAC, want de store
	// sleutelt erop en zou twee apparaten kunnen samenvoegen.
	if volledig && p+6 <= len(buf) {
		mac := oui.Normalize(fmt.Sprintf("%02x%02x%02x%02x%02x%02x",
			buf[p], buf[p+1], buf[p+2], buf[p+3], buf[p+4], buf[p+5]))
		if mac != "" && mac != "00:00:00:00:00:00" && !oui.IsMulticast(mac) {
			r.MAC = mac
		}
	}
	return r, r.Name != ""
}

// NetBIOS vraagt elke host naar z'n naam via een node status query op
// UDP 137.
//
// Dit is de betrouwbaarste bron voor Windows-machines: die antwoorden
// vrijwel altijd, ook als ze ICMP negeren, en geven hun computernaam,
// werkgroep én MAC-adres in één keer prijs. Alles gaat over één socket:
// we vuren de vragen af en luisteren daarna naar wat binnenkomt.
func NetBIOS(ctx context.Context, ips []string, wacht time.Duration, onResult func(NetBIOSResult)) error {
	if wacht <= 0 {
		wacht = 2 * time.Second
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return fmt.Errorf("kon geen UDP-socket openen voor NetBIOS: %w", err)
	}
	defer conn.Close()

	klaar := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.SetReadDeadline(time.Now())
		case <-klaar:
		}
	}()
	defer close(klaar)

	pakket := nbstatQuery(0x4e53)
	for _, ip := range ips {
		addr := &net.UDPAddr{IP: net.ParseIP(ip), Port: 137}
		if addr.IP == nil {
			continue
		}
		conn.WriteToUDP(pakket, addr)
		// Een korte pauze houdt de burst weg bij zwakke apparaten en kost
		// over een /24 nog geen halve seconde.
		time.Sleep(time.Millisecond)
	}

	conn.SetReadDeadline(time.Now().Add(wacht))
	buf := make([]byte, 2048)
	gezien := map[string]bool{}
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil // deadline of geannuleerd: klaar
		}
		ip := from.IP.String()
		if gezien[ip] {
			continue
		}
		if r, ok := parseNBStat(buf[:n], ip); ok {
			gezien[ip] = true
			if onResult != nil {
				onResult(r)
			}
		}
	}
}
