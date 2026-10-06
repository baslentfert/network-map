package discover

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// mDNSResult koppelt een adres aan wat het over zichzelf vertelt.
type mDNSResultKind int

// MDNSResult is één waarneming uit het mDNS-verkeer.
type MDNSResult struct {
	IP   string
	Name string
	// Service is het geadverteerde diensttype, bijvoorbeeld
	// "_googlecast._tcp". Leeg als de naam uit een A- of PTR-record komt.
	Service string
}

var mdnsAddr = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

// Diensttypes die op een thuisnetwerk daadwerkelijk iets opleveren. De
// meta-query _services._dns-sd._udp somt alles op wat er ís, de rest
// vraagt gericht naar de dingen die een naam dragen.
var mdnsDiensten = []string{
	"_services._dns-sd._udp.local.",
	"_device-info._tcp.local.",
	"_workstation._tcp.local.",
	"_http._tcp.local.",
	"_https._tcp.local.",
	"_ssh._tcp.local.",
	"_smb._tcp.local.",
	"_afpovertcp._tcp.local.",
	"_ipp._tcp.local.",
	"_ipps._tcp.local.",
	"_printer._tcp.local.",
	"_pdl-datastream._tcp.local.",
	"_scanner._tcp.local.",
	"_googlecast._tcp.local.",
	"_airplay._tcp.local.",
	"_raop._tcp.local.",
	"_spotify-connect._tcp.local.",
	"_sonos._tcp.local.",
	"_hap._tcp.local.",
	"_esphomelib._tcp.local.",
	"_homeassistant._tcp.local.",
	"_companion-link._tcp.local.",
	"_nvstream._tcp.local.",
	"_hue._tcp.local.",
}

// mdnsGericht gaat mee in elke unicastvraag aan één host. Korter dan de
// volledige lijst, want dit pakket gaat per host de deur uit en moet in
// één datagram passen.
var mdnsGericht = []string{
	"_services._dns-sd._udp.local.",
	"_device-info._tcp.local.",
	"_workstation._tcp.local.",
	"_http._tcp.local.",
	"_ipp._tcp.local.",
	"_printer._tcp.local.",
	"_smb._tcp.local.",
	"_googlecast._tcp.local.",
	"_airplay._tcp.local.",
	"_raop._tcp.local.",
	"_hap._tcp.local.",
	"_esphomelib._tcp.local.",
}

// reversNaam maakt van 192.168.0.1 het PTR-label 1.0.168.192.in-addr.arpa.
func reversNaam(ip string) string {
	d := strings.Split(ip, ".")
	if len(d) != 4 {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.%s.in-addr.arpa.", d[3], d[2], d[1], d[0])
}

// bouwVraag zet een lijst namen om in één mDNS-query.
//
// De klasse krijgt bit 15 gezet — de "QU"-vlag, unicast response
// requested. Daarmee antwoorden responders rechtstreeks aan onze
// ephemeral poort in plaats van naar de multicastgroep, en hoeven we
// poort 5353 niet te claimen. Die is op Windows vaak al bezet door
// Bonjour of door Windows' eigen resolver.
func bouwVraag(namen []string, type_ dnsmessage.Type) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	for _, n := range namen {
		naam, err := dnsmessage.NewName(n)
		if err != nil {
			continue
		}
		q := dnsmessage.Question{
			Name:  naam,
			Type:  type_,
			Class: dnsmessage.ClassINET | 0x8000,
		}
		if err := b.Question(q); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

// ParseMDNS haalt uit een mDNS- of LLMNR-bericht alles wat een naam aan
// een adres koppelt. Ook bruikbaar op berichten die we passief opvangen,
// niet alleen op antwoorden die we zelf uitlokten.
func ParseMDNS(data []byte, bron string, onResult func(MDNSResult)) {
	verwerkAntwoord(data, bron, onResult)
}

// verwerkAntwoord haalt uit een mDNS-bericht alles wat een naam aan een
// adres koppelt.
func verwerkAntwoord(data []byte, bron string, onResult func(MDNSResult)) {
	var p dnsmessage.Parser
	if _, err := p.Start(data); err != nil {
		return
	}
	p.SkipAllQuestions()

	// hostnaam onthoudt de naam uit PTR/SRV-records, zodat een A-record
	// dat er later in hetzelfde bericht op volgt hem kan bevestigen.
	var diensten []string

	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break
		}
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				continue
			}
			ip := net.IP(r.A[:]).String()
			naam := kortNaam(h.Name.String())
			if naam != "" {
				onResult(MDNSResult{IP: ip, Name: naam})
			}
		case dnsmessage.TypePTR:
			r, err := p.PTRResource()
			if err != nil {
				continue
			}
			doel := r.PTR.String()
			vraag := h.Name.String()
			if strings.HasSuffix(vraag, ".in-addr.arpa.") {
				// Omgekeerde lookup: dit is precies de koppeling die we
				// zoeken, en hij komt van het apparaat zelf.
				if naam := kortNaam(doel); naam != "" {
					onResult(MDNSResult{IP: bron, Name: naam})
				}
				continue
			}
			if strings.HasPrefix(vraag, "_") {
				diensten = append(diensten, dienstVan(vraag))
				if inst := instantieNaam(doel, vraag); inst != "" {
					onResult(MDNSResult{IP: bron, Name: inst, Service: dienstVan(vraag)})
				}
			}
		case dnsmessage.TypeSRV:
			r, err := p.SRVResource()
			if err != nil {
				continue
			}
			_ = r
		default:
			if err := p.SkipAnswer(); err != nil {
				return
			}
			continue
		}
	}
	// Extra secties bevatten vaak het A-record bij een SRV.
	p.SkipAllAuthorities()
	for {
		h, err := p.AdditionalHeader()
		if err != nil {
			return
		}
		if h.Type == dnsmessage.TypeA {
			r, err := p.AResource()
			if err != nil {
				continue
			}
			if naam := kortNaam(h.Name.String()); naam != "" {
				onResult(MDNSResult{IP: net.IP(r.A[:]).String(), Name: naam})
			}
			continue
		}
		if err := p.SkipAdditional(); err != nil {
			return
		}
	}
}

// kortNaam maakt van "woonkamer.local." gewoon "woonkamer".
func kortNaam(n string) string {
	n = strings.TrimSuffix(n, ".")
	n = strings.TrimSuffix(n, ".local")
	if n == "" || strings.HasPrefix(n, "_") || strings.HasSuffix(n, ".in-addr.arpa") {
		return ""
	}
	return n
}

// instantieNaam haalt uit "Woonkamer TV._googlecast._tcp.local." het
// stuk dat een mens bedacht heeft.
func instantieNaam(doel, dienst string) string {
	doel = strings.TrimSuffix(doel, ".")
	dienst = strings.TrimSuffix(dienst, ".")
	if !strings.HasSuffix(doel, dienst) {
		return ""
	}
	inst := strings.TrimSuffix(doel, "."+dienst)
	inst = strings.ReplaceAll(inst, `\ `, " ")
	inst = strings.ReplaceAll(inst, `\.`, ".")

	// AirPlay-audio (_raop) zet het hardware-adres vóór de naam, als
	// "1EB62B3856F6@Alex's MacBook Pro". Die prefix is ruis voor een mens.
	if i := strings.IndexByte(inst, '@'); i > 0 && isHex(inst[:i]) {
		inst = inst[i+1:]
	}
	if inst == doel || inst == "" {
		return ""
	}
	return inst
}

func isHex(s string) bool {
	if len(s) < 6 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func dienstVan(n string) string {
	n = strings.TrimSuffix(n, ".")
	return strings.TrimSuffix(n, ".local")
}

// MDNS bevraagt het netwerk over multicast en verzamelt de antwoorden.
//
// Twee soorten vragen gaan de deur uit: een gerichte PTR per diensttype
// (dat levert de zelfbedachte namen op, zoals "Woonkamer TV"), en een
// omgekeerde lookup per bekend adres (dat levert de hostnaam op, ook bij
// apparaten die geen enkele dienst adverteren).
func MDNS(ctx context.Context, ips []string, wacht time.Duration, onResult func(MDNSResult)) error {
	if wacht <= 0 {
		wacht = 3 * time.Second
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return fmt.Errorf("kon geen UDP-socket openen voor mDNS: %w", err)
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

	// Eén multicastvraag als bonus. Op Windows levert die meestal niets
	// op: het antwoord komt van een host-adres terwijl wij naar een
	// multicastadres stuurden, en de stateful firewall ziet dat niet als
	// antwoord op onze vraag en laat het vallen.
	if vraag, err := bouwVraag(mdnsDiensten, dnsmessage.TypePTR); err == nil {
		conn.WriteToUDP(vraag, mdnsAddr)
	}

	// Daarom het echte werk unicast: rechtstreeks naar poort 5353 van elke
	// bekende host. RFC 6762 §5.5 staat dat expliciet toe, en omdat het
	// antwoord van hetzelfde adres terugkomt herkent de firewall het wel.
	for _, ip := range ips {
		doel := &net.UDPAddr{IP: net.ParseIP(ip), Port: 5353}
		if doel.IP == nil {
			continue
		}
		vragen := make([]string, 0, len(mdnsGericht)+1)
		if n := reversNaam(ip); n != "" {
			vragen = append(vragen, n)
		}
		vragen = append(vragen, mdnsGericht...)
		if pakket, err := bouwVraag(vragen, dnsmessage.TypePTR); err == nil {
			conn.WriteToUDP(pakket, doel)
		}
		time.Sleep(time.Millisecond)
	}

	conn.SetReadDeadline(time.Now().Add(wacht))
	buf := make([]byte, 9000)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil
		}
		verwerkAntwoord(buf[:n], from.IP.String(), func(r MDNSResult) {
			if r.Name != "" && onResult != nil {
				onResult(r)
			}
		})
	}
}
