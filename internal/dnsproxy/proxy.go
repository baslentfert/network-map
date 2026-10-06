// Package dnsproxy draait een DNS-doorgeefluik voor je eigen netwerk.
//
// Waarom dit bestaat: op een geswitcht netwerk zie je het verkeer van
// andere apparaten niet. Maar als je in je router de DNS-server op deze
// machine zet, stuurt elk apparaat zijn naamvragen uit zichzelf hierheen —
// gewoon unicast, aan ons gericht. Zo zie je waar elk apparaat naartoe
// praat zonder promiscuous socket, zonder Npcap en zonder admin.
//
// Veiligheidsregel: we sturen het antwoord byte voor byte door zoals we
// het kregen. Ontleden doen we alleen voor het logboek. Een fout in de
// ontleder mag nooit iemands internet breken.
package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Vraag is één DNS-opzoeking zoals wij hem zagen.
type Vraag struct {
	At     time.Time     `json:"at"`
	Client string        `json:"client"`
	Name   string        `json:"name"`
	Type   string        `json:"type"`
	Rcode  string        `json:"rcode"`
	Duur   time.Duration `json:"-"`
	MS     int64         `json:"ms"`
	// Antwoorden zijn de IP-adressen die terugkwamen. Leeg bij een
	// mislukte opzoeking of bij een type dat geen adres oplevert.
	Antwoorden []string `json:"answers,omitempty"`
}

// Opties stuurt de proxy aan.
type Opties struct {
	// Luister is het adres waarop we DNS aannemen. Het LAN-adres van deze
	// machine, niet 0.0.0.0: dat laatste botst vaak met Docker, WSL of
	// Hyper-V, die poort 53 al bezet houden.
	Luister string
	// Upstream zijn de servers waar we de vragen naartoe sturen.
	//
	// Let op: niet je eigen router invullen. Zodra die jou als DNS-server
	// aanwijst, stuur je de vraag naar degene die hem net aan jou gaf.
	Upstream []string
	Timeout  time.Duration
}

func (o Opties) metStandaarden() Opties {
	if len(o.Upstream) == 0 {
		// Publieke resolvers, bewust niet de router: zie hierboven.
		o.Upstream = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	for i, u := range o.Upstream {
		if !strings.Contains(u, ":") {
			o.Upstream[i] = u + ":53"
		}
	}
	if o.Timeout <= 0 {
		o.Timeout = 4 * time.Second
	}
	return o
}

// Proxy neemt DNS-vragen aan en stuurt ze door.
type Proxy struct {
	opt Opties
	// OnVraag wordt aangeroepen voor elke opzoeking, ook de mislukte.
	OnVraag func(Vraag)

	mu       sync.Mutex
	aantal   int64
	mislukt  int64
	gestart  time.Time
	actief   bool
	luisterA string
}

func Nieuw(opt Opties, onVraag func(Vraag)) *Proxy {
	return &Proxy{opt: opt.metStandaarden(), OnVraag: onVraag}
}

// Status beschrijft of de proxy loopt en wat hij tot nu toe deed.
type Status struct {
	Actief   bool      `json:"active"`
	Adres    string    `json:"address"`
	Upstream []string  `json:"upstream"`
	Vragen   int64     `json:"queries"`
	Mislukt  int64     `json:"failed"`
	Sinds    time.Time `json:"since"`
}

func (p *Proxy) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return Status{
		Actief: p.actief, Adres: p.luisterA, Upstream: p.opt.Upstream,
		Vragen: p.aantal, Mislukt: p.mislukt, Sinds: p.gestart,
	}
}

// Run luistert tot de context afloopt.
//
// De fout die je hier het vaakst krijgt is dat poort 53 al bezet is. Op
// Windows houden Docker, WSL en Hyper-V hem graag vast; de melding zegt
// dat erbij in plaats van alleen "address in use".
func (p *Proxy) Run(ctx context.Context) error {
	adres, err := net.ResolveUDPAddr("udp4", p.opt.Luister)
	if err != nil {
		return fmt.Errorf("luisteradres %q is onbruikbaar: %w", p.opt.Luister, err)
	}

	conn, err := net.ListenUDP("udp4", adres)
	if err != nil {
		return fmt.Errorf("kon poort %d niet openen op %s: %w — "+
			"op Windows houden Docker, WSL of Hyper-V poort 53 vaak al bezet; "+
			"kies een ander adres of stop die dienst", adres.Port, adres.IP, err)
	}
	defer conn.Close()

	p.mu.Lock()
	p.actief, p.gestart, p.luisterA = true, time.Now(), conn.LocalAddr().String()
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.actief = false
		p.mu.Unlock()
	}()

	go func() {
		<-ctx.Done()
		conn.SetReadDeadline(time.Now())
	}()

	buf := make([]byte, 4096)
	for {
		n, van, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return fmt.Errorf("lezen mislukt: %w", err)
		}
		// Kopie maken: de volgende lezing overschrijft de buffer.
		vraag := make([]byte, n)
		copy(vraag, buf[:n])
		go p.behandel(ctx, conn, van, vraag)
	}
}

func (p *Proxy) behandel(ctx context.Context, conn *net.UDPConn, van *net.UDPAddr, vraag []byte) {
	start := time.Now()
	naam, soort := leesVraag(vraag)

	antwoord, err := p.doorsturen(ctx, vraag)

	p.mu.Lock()
	p.aantal++
	if err != nil {
		p.mislukt++
	}
	p.mu.Unlock()

	v := Vraag{
		At: start, Client: van.IP.String(), Name: naam, Type: soort,
		Duur: time.Since(start),
	}
	v.MS = v.Duur.Milliseconds()

	if err != nil {
		v.Rcode = "geen antwoord"
		if p.OnVraag != nil {
			p.OnVraag(v)
		}
		return
	}

	// Terugsturen gaat vóór het ontleden: de klant wacht, en het logboek
	// kan wel een microseconde later.
	conn.WriteToUDP(antwoord, van)

	v.Rcode, v.Antwoorden = leesAntwoord(antwoord)
	if p.OnVraag != nil {
		p.OnVraag(v)
	}
}

// doorsturen probeert elke upstream op volgorde.
func (p *Proxy) doorsturen(ctx context.Context, vraag []byte) ([]byte, error) {
	var laatste error
	for _, up := range p.opt.Upstream {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		c, err := net.DialTimeout("udp4", up, p.opt.Timeout)
		if err != nil {
			laatste = err
			continue
		}
		c.SetDeadline(time.Now().Add(p.opt.Timeout))
		if _, err := c.Write(vraag); err != nil {
			c.Close()
			laatste = err
			continue
		}
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		c.Close()
		if err != nil {
			laatste = err
			continue
		}
		return buf[:n], nil
	}
	if laatste == nil {
		laatste = errors.New("geen upstream geconfigureerd")
	}
	return nil, laatste
}

// --- ontleden, uitsluitend voor het logboek -------------------------------

func leesVraag(b []byte) (naam, soort string) {
	var p dnsmessage.Parser
	if _, err := p.Start(b); err != nil {
		return "", ""
	}
	q, err := p.Question()
	if err != nil {
		return "", ""
	}
	return strings.TrimSuffix(q.Name.String(), "."), typeNaam(q.Type)
}

func leesAntwoord(b []byte) (rcode string, adressen []string) {
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil {
		return "", nil
	}
	rcode = rcodeNaam(h.RCode)
	p.SkipAllQuestions()

	for {
		ah, err := p.AnswerHeader()
		if err != nil {
			break
		}
		switch ah.Type {
		case dnsmessage.TypeA:
			if r, err := p.AResource(); err == nil {
				adressen = append(adressen, net.IP(r.A[:]).String())
			}
		case dnsmessage.TypeAAAA:
			if r, err := p.AAAAResource(); err == nil {
				adressen = append(adressen, net.IP(r.AAAA[:]).String())
			}
		case dnsmessage.TypeCNAME:
			if r, err := p.CNAMEResource(); err == nil {
				adressen = append(adressen, strings.TrimSuffix(r.CNAME.String(), "."))
			}
		default:
			if p.SkipAnswer() != nil {
				return
			}
		}
	}
	return rcode, adressen
}

func typeNaam(t dnsmessage.Type) string {
	switch t {
	case dnsmessage.TypeA:
		return "A"
	case dnsmessage.TypeAAAA:
		return "AAAA"
	case dnsmessage.TypeCNAME:
		return "CNAME"
	case dnsmessage.TypePTR:
		return "PTR"
	case dnsmessage.TypeMX:
		return "MX"
	case dnsmessage.TypeTXT:
		return "TXT"
	case dnsmessage.TypeSRV:
		return "SRV"
	case dnsmessage.TypeNS:
		return "NS"
	case dnsmessage.TypeSOA:
		return "SOA"
	case 65:
		return "HTTPS"
	default:
		return fmt.Sprintf("type%d", t)
	}
}

func rcodeNaam(r dnsmessage.RCode) string {
	switch r {
	case dnsmessage.RCodeSuccess:
		return "ok"
	case dnsmessage.RCodeNameError:
		return "bestaat niet"
	case dnsmessage.RCodeServerFailure:
		return "serverfout"
	case dnsmessage.RCodeFormatError:
		return "formaatfout"
	case dnsmessage.RCodeRefused:
		return "geweigerd"
	default:
		return fmt.Sprintf("rcode%d", r)
	}
}
