// Package capture luistert passief mee op het netwerk.
//
// Twee routes, dezelfde uitkomst. De standaardroute is een raw socket met
// SIO_RCVALL: pure Go, niets te installeren, wel administratorrechten. Die
// levert al het IPv4-verkeer dat de adapter ziet — inclusief broadcast en
// multicast, en dus inclusief DHCP, mDNS, SSDP, LLMNR en NetBIOS. Daarmee
// vang je de namen die apparaten ongevraagd rondsturen, en apparaten die
// op geen enkele actieve vraag antwoorden.
//
// Wat deze route per definitie niet kan: alles onder de IP-laag. ARP en
// LLDP komen hier nooit langs. Daarvoor is Npcap nodig.
package capture

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"netwerksniffer/internal/discover"
	"netwerksniffer/internal/model"
	"netwerksniffer/internal/netif"
	"netwerksniffer/internal/store"
)

const (
	sioRcvAll = 0x98000001
	rcvallOn  = 1
)

// Sniffer leest mee en schrijft alles wat hij leert in de store.
type Sniffer struct {
	Iface netif.Adapter
	Store *store.Store

	// FlushInterval bepaalt hoe vaak verkeerstellers worden weggeschreven.
	// Per pakket zou de frontend bedelven worden onder updates.
	FlushInterval time.Duration
}

// verkeer telt bytes per host tussen twee flushes.
type verkeer struct {
	rx, tx uint64
}

// Run luistert tot de context afloopt.
//
// De fout die je hier het vaakst krijgt is "toegang geweigerd": raw sockets
// vragen op Windows administratorrechten. Dat is geen bug maar een
// systeemeis, en de melding zegt dat ook zo.
func (s *Sniffer) Run(ctx context.Context) error {
	if s.FlushInterval <= 0 {
		s.FlushInterval = 2 * time.Second
	}
	pfx, err := netip.ParsePrefix(s.Iface.CIDR)
	if err != nil {
		return fmt.Errorf("subnet %q is onbruikbaar: %w", s.Iface.CIDR, err)
	}
	zelf, _ := netip.ParseAddr(s.Iface.IP)

	fd, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_IP)
	if err != nil {
		return fmt.Errorf("raw socket openen mislukt (%w) — passief meeluisteren vraagt administratorrechten", err)
	}
	defer windows.Closesocket(fd)

	var adres [4]byte
	if zelf.Is4() {
		adres = zelf.As4()
	}
	if err := windows.Bind(fd, &windows.SockaddrInet4{Addr: adres}); err != nil {
		return fmt.Errorf("binden aan %s mislukt: %w", s.Iface.IP, err)
	}

	var in uint32 = rcvallOn
	var uit, teruggegeven uint32
	if err := windows.WSAIoctl(fd, sioRcvAll,
		(*byte)(unsafe.Pointer(&in)), 4,
		(*byte)(unsafe.Pointer(&uit)), 4,
		&teruggegeven, nil, 0); err != nil {
		return fmt.Errorf("promiscuous modus geweigerd (%w) — start de app als administrator", err)
	}

	// Een korte leestimeout houdt de lus responsief voor annulering.
	tv := windows.Timeval{Sec: 1}
	windows.SetsockoptTimeval(fd, windows.SOL_SOCKET, windows.SO_RCVTIMEO, &tv)

	s.Store.Log(model.TagScan, "", "ev.passiveStarted", "iface", s.Iface.Name)
	defer s.Store.Log(model.TagScan, "", "ev.passiveStopped")

	tellers := map[string]*verkeer{}
	var mu sync.Mutex
	laatsteFlush := time.Now()

	buf := make([]byte, 65535)
	for {
		if ctx.Err() != nil {
			s.flush(tellers, &mu)
			return nil
		}
		n, _, err := windows.Recvfrom(fd, buf, 0)
		if err != nil || n < 20 {
			if time.Since(laatsteFlush) >= s.FlushInterval {
				s.flush(tellers, &mu)
				laatsteFlush = time.Now()
			}
			continue
		}

		s.verwerk(buf[:n], pfx, zelf, tellers, &mu)

		if time.Since(laatsteFlush) >= s.FlushInterval {
			s.flush(tellers, &mu)
			laatsteFlush = time.Now()
		}
	}
}

// verwerk ontleedt één IPv4-pakket.
func (s *Sniffer) verwerk(p []byte, pfx netip.Prefix, zelf netip.Addr, tellers map[string]*verkeer, mu *sync.Mutex) {
	hl := int(p[0]&0x0f) * 4
	if hl < 20 || len(p) < hl {
		return
	}
	src := netip.AddrFrom4([4]byte{p[12], p[13], p[14], p[15]})
	dst := netip.AddrFrom4([4]byte{p[16], p[17], p[18], p[19]})
	proto := p[9]

	// Verkeersvolume bijhouden voor hosts in ons eigen subnet.
	mu.Lock()
	if pfx.Contains(src) && src != zelf {
		t := tellers[src.String()]
		if t == nil {
			t = &verkeer{}
			tellers[src.String()] = t
		}
		t.tx += uint64(len(p))
	}
	if pfx.Contains(dst) && dst != zelf && !dst.IsMulticast() {
		t := tellers[dst.String()]
		if t == nil {
			t = &verkeer{}
			tellers[dst.String()] = t
		}
		t.rx += uint64(len(p))
	}
	mu.Unlock()

	if proto != 17 || len(p) < hl+8 {
		return
	}
	sp := binary.BigEndian.Uint16(p[hl : hl+2])
	dp := binary.BigEndian.Uint16(p[hl+2 : hl+4])
	lading := p[hl+8:]
	bron := src.String()

	switch {
	case dp == 67 || dp == 68 || sp == 67 || sp == 68:
		s.dhcp(lading)
	case dp == 5353 || sp == 5353:
		s.mdns(lading, bron)
	case dp == 5355 || sp == 5355:
		s.llmnr(lading, bron)
	case dp == 1900 || sp == 1900:
		s.ssdp(lading, bron)
	case dp == 137 || sp == 137 || dp == 138 || sp == 138:
		s.netbios(lading, bron)
	}
}

// dhcp is de belangrijkste bron: hier noemt een apparaat zijn eigen naam.
func (s *Sniffer) dhcp(b []byte) {
	d, ok := ParseDHCP(b)
	if !ok || (d.Name == "" && d.MAC == "") {
		return
	}
	f := store.Fact{MAC: d.MAC, IP: d.IP}
	if d.Name != "" {
		f.Name, f.Origin = d.Name, model.OriginDHCP
	}
	if d.VendorClass != "" {
		f.Model = d.VendorClass
	}
	s.Store.Observe(f)

	if d.Name != "" {
		wat := d.Type
		if wat == "" {
			wat = "dhcp.announce"
		}
		// wat is een tekstsleutel, geen zin: de frontend vertaalt hem mee.
		s.Store.Log(model.TagDHCP, d.MAC, "ev.dhcpName", "name", d.Name, "what", wat)
	}
}

func (s *Sniffer) mdns(b []byte, bron string) {
	discover.ParseMDNS(b, bron, func(r discover.MDNSResult) {
		if r.Name == "" {
			return
		}
		herkomst := model.OriginMDNSHost
		if r.Service != "" {
			herkomst = model.OriginMDNS
		}
		s.Store.Observe(store.Fact{IP: r.IP, Name: r.Name, Origin: herkomst})
	})
}

// llmnr spreekt hetzelfde formaat als DNS, dus dezelfde ontleder volstaat.
func (s *Sniffer) llmnr(b []byte, bron string) {
	discover.ParseMDNS(b, bron, func(r discover.MDNSResult) {
		if r.Name == "" {
			return
		}
		s.Store.Observe(store.Fact{IP: r.IP, Name: r.Name, Origin: model.OriginMDNSHost})
	})
}

// ssdp vangt de NOTIFY-berichten waarmee UPnP-apparaten zichzelf
// aankondigen. Anders dan bij een M-SEARCH hoeven we hier niets te vragen.
func (s *Sniffer) ssdp(b []byte, bron string) {
	tekst := string(b)
	if !strings.HasPrefix(tekst, "NOTIFY") && !strings.HasPrefix(tekst, "HTTP/1.1") {
		return
	}
	var server string
	for _, regel := range strings.Split(tekst, "\n") {
		regel = strings.TrimRight(regel, "\r")
		i := strings.IndexByte(regel, ':')
		if i <= 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(regel[:i]), "SERVER") {
			server = strings.TrimSpace(regel[i+1:])
		}
	}
	if server == "" {
		return
	}
	// De SERVER-kop is een modelaanduiding, geen naam — vandaar Model.
	s.Store.Observe(store.Fact{IP: bron, Model: schoonNaam(server)})
}

// netbios pikt de naam uit een NetBIOS-datagram op. Die staat op een vaste
// plek in de kop, in dezelfde gecodeerde vorm als bij een node status query.
func (s *Sniffer) netbios(b []byte, bron string) {
	naam := netbiosNaamUitDatagram(b)
	if naam == "" {
		return
	}
	s.Store.Observe(store.Fact{IP: bron, Name: naam, Origin: model.OriginNetBIOS})
}

// flush schrijft de opgetelde bytes weg en begint opnieuw.
func (s *Sniffer) flush(tellers map[string]*verkeer, mu *sync.Mutex) {
	mu.Lock()
	if len(tellers) == 0 {
		mu.Unlock()
		return
	}
	kopie := make(map[string]verkeer, len(tellers))
	for ip, t := range tellers {
		kopie[ip] = *t
		delete(tellers, ip)
	}
	mu.Unlock()

	for ip, t := range kopie {
		s.Store.Observe(store.Fact{IP: ip, Rx: t.rx, Tx: t.tx})
	}
}
