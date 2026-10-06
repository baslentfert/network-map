// Command protoprobe klopt op elke deur die we nog niet geprobeerd hebben.
//
// Vier kandidaten die overbleven na mDNS, NetBIOS, SSDP, UPnP, DNS, TLS,
// HTTP en DHCP-leasequery:
//
//   WS-Discovery (3702)  Windows-machines, netwerkprinters, ONVIF-camera's
//   LLMNR (5355)         de opvolger van NetBIOS bij Microsoft
//   TP-Link eigen        Kasa op 9999, nieuwere apparaten op 20002,
//                        Omada-apparatuur op 29810
//   SNMP (161)           managed apparatuur, community "public"
//
// Alles unicast, want multicast-antwoorden sneuvelen in Windows Firewall.
package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type vondst struct {
	ip, proto, antwoord string
}

func main() {
	doelen := os.Args[1:]
	if len(doelen) == 0 {
		fmt.Println("gebruik: protoprobe <ip> [ip...]")
		os.Exit(2)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var vondsten []vondst
	meld := func(v vondst) {
		mu.Lock()
		vondsten = append(vondsten, v)
		mu.Unlock()
	}

	for _, ip := range doelen {
		for _, p := range probes() {
			wg.Add(1)
			go func(ip string, p probe) {
				defer wg.Done()
				if antw := stuur(ip, p); antw != "" {
					meld(vondst{ip, p.naam, antw})
				}
			}(ip, p)
		}
	}
	wg.Wait()

	if len(vondsten) == 0 {
		fmt.Println("Geen enkel antwoord op geen enkel protocol.")
		return
	}
	for _, v := range vondsten {
		fmt.Printf("%-15s %-22s %s\n", v.ip, v.proto, v.antwoord)
	}
}

type probe struct {
	naam  string
	poort int
	// bouw krijgt het doeladres, omdat sommige vragen daarvan afhangen:
	// een LLMNR-responder antwoordt alleen op vragen over zichzelf.
	bouw    func(ip string) []byte
	ontleed func([]byte) string
}

func vast(b []byte) func(string) []byte { return func(string) []byte { return b } }

func probes() []probe {
	return []probe{
		{"WS-Discovery", 3702, vast(wsdProbe()), leesWSD},
		{"LLMNR", 5355, llmnrProbe, leesRuw},
		{"TP-Link Kasa", 9999, vast(kasaProbe()), leesKasa},
		{"TP-Link 20002", 20002, vast(tplink20002()), leesRuw},
		{"Omada", 29810, vast([]byte{0x01, 0x01, 0x00, 0x00}), leesRuw},
		{"SNMP public", 161, vast(snmpSysName()), leesRuw},
	}
}

func stuur(ip string, p probe) string {
	conn, err := net.DialTimeout("udp4", fmt.Sprintf("%s:%d", ip, p.poort), 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(p.bouw(ip)); err != nil {
		return ""
	}
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	return p.ontleed(buf[:n])
}

// leesRuw toont de leesbare tekens uit een antwoord — genoeg om te zien
// óf er iets terugkomt en of er een naam in zit.
func leesRuw(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 32 && c < 127 {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
	}
	s := sb.String()
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return fmt.Sprintf("(%d bytes) %s", len(b), s)
}

func leesWSD(b []byte) string {
	s := string(b)
	for _, tag := range []string{"FriendlyName", "Types", "XAddrs", "Address"} {
		if i := strings.Index(s, "<"); i >= 0 && strings.Contains(s, tag) {
			return fmt.Sprintf("(%d bytes) bevat %s", len(b), tag)
		}
	}
	return leesRuw(b)
}

// wsdProbe is een WS-Discovery Probe-bericht: de standaardvraag "wie is
// daar en wat ben je".
func wsdProbe() []byte {
	return []byte(`<?xml version="1.0" encoding="utf-8"?>` +
		`<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" ` +
		`xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" ` +
		`xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">` +
		`<soap:Header>` +
		`<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>` +
		`<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>` +
		`<wsa:MessageID>urn:uuid:0a6dc5b0-1111-2222-3333-444455556666</wsa:MessageID>` +
		`</soap:Header><soap:Body><wsd:Probe/></soap:Body></soap:Envelope>`)
}

// llmnrProbe vraagt via LLMNR naar de naam achter een adres.
//
// Het formaat is gelijk aan DNS. Belangrijk: een LLMNR-responder
// antwoordt uitsluitend op vragen over zichzelf, dus de vraag moet het
// omgekeerde adres van precies dit doel bevatten.
func llmnrProbe(ip string) []byte {
	d := strings.Split(ip, ".")
	if len(d) != 4 {
		return nil
	}
	labels := []string{d[3], d[2], d[1], d[0], "in-addr", "arpa"}
	b := []byte{0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, l := range labels {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0x00, 0x00, 0x0c, 0x00, 0x01) // PTR, IN
	return b
}

// kasaProbe is TP-Links eigen ontdekkingsbericht voor Kasa-apparaten:
// JSON, versleuteld met een lopende XOR die op 171 begint.
func kasaProbe() []byte {
	plat := []byte(`{"system":{"get_sysinfo":{}}}`)
	uit := make([]byte, len(plat))
	sleutel := byte(171)
	for i, c := range plat {
		sleutel = c ^ sleutel
		uit[i] = sleutel
	}
	return uit
}

// leesKasa draait diezelfde XOR terug.
func leesKasa(b []byte) string {
	uit := make([]byte, len(b))
	sleutel := byte(171)
	for i, c := range b {
		uit[i] = c ^ sleutel
		sleutel = c
	}
	s := string(uit)
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// tplink20002 is de ontdekkingsvraag van nieuwere TP-Link-apparaten.
func tplink20002() []byte {
	return []byte{
		0x02, 0x00, 0x00, 0x01, 0x01, 0xe5, 0x11, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

// snmpSysName vraagt OID 1.3.6.1.2.1.1.5.0 (sysName) op met de
// standaardcommunity "public".
func snmpSysName() []byte {
	return []byte{
		0x30, 0x27, 0x02, 0x01, 0x00, // SNMPv1
		0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
		0xa0, 0x1a, // GetRequest
		0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // request-id
		0x02, 0x01, 0x00, 0x02, 0x01, 0x00, // error status/index
		0x30, 0x0c, 0x30, 0x0a,
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00,
		0x05, 0x00,
	}
}
