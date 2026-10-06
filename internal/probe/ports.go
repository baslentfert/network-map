package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"netwerksniffer/internal/model"
)

// service koppelt een poort aan de dienst erachter, en aan wat die dienst
// verraadt over het soort apparaat. hint mag leeg zijn: de meeste poorten
// zeggen niets over de aard van het apparaat.
type service struct {
	name string
	hint model.Kind
}

// Diensten die we herkennen. De hints zijn bewust terughoudend: poort 80
// staat op vrijwel alles, dus die krijgt er geen.
var services = map[int]service{
	21:    {"ftp", ""},
	22:    {"ssh", ""},
	23:    {"telnet", ""},
	25:    {"smtp", ""},
	53:    {"dns", ""},
	80:    {"http", ""},
	110:   {"pop3", ""},
	111:   {"rpcbind", ""},
	135:   {"msrpc", model.KindPC},
	139:   {"netbios-ssn", model.KindPC},
	143:   {"imap", ""},
	443:   {"https", ""},
	445:   {"smb", model.KindPC},
	515:   {"lpd", model.KindIoT},
	548:   {"afp", model.KindNAS},
	554:   {"rtsp", model.KindIoT},
	587:   {"submission", ""},
	631:   {"ipp", model.KindIoT},
	873:   {"rsync", model.KindNAS},
	902:   {"vmware", ""},
	993:   {"imaps", ""},
	995:   {"pop3s", ""},
	1194:  {"openvpn", ""},
	1433:  {"mssql", ""},
	1723:  {"pptp", ""},
	1883:  {"mqtt", model.KindIoT},
	2049:  {"nfs", model.KindNAS},
	2375:  {"docker", ""},
	2376:  {"docker-tls", ""},
	3000:  {"http-dev", ""},
	3128:  {"squid", ""},
	3306:  {"mysql", ""},
	3389:  {"rdp", model.KindPC},
	5000:  {"upnp/dsm", ""},
	5001:  {"dsm-tls", model.KindNAS},
	5060:  {"sip", ""},
	5222:  {"xmpp", ""},
	5432:  {"postgres", ""},
	5555:  {"adb", model.KindPhone},
	5900:  {"vnc", ""},
	6379:  {"redis", ""},
	8000:  {"http-alt", ""},
	8006:  {"proxmox", ""},
	8008:  {"cast", model.KindTV},
	8009:  {"cast-tls", model.KindTV},
	8080:  {"http-proxy", ""},
	8081:  {"http-alt", ""},
	8096:  {"jellyfin", model.KindTV},
	8123:  {"home-assistant", model.KindIoT},
	8443:  {"https-alt", ""},
	8554:  {"rtsp-alt", model.KindIoT},
	8883:  {"mqtt-tls", model.KindIoT},
	9000:  {"portainer", ""},
	9100:  {"jetdirect", model.KindIoT},
	9200:  {"elasticsearch", ""},
	10000: {"webmin", ""},
	11211: {"memcached", ""},
	27017: {"mongodb", ""},
	32400: {"plex", model.KindTV},
	49152: {"upnp", ""},
}

// Profielen. Snel is bedoeld om over een heel subnet te draaien; grondig
// op één host waar je iets van wilt weten.
var (
	portsQuick = []int{21, 22, 23, 53, 80, 135, 139, 443, 445, 554, 631,
		1883, 3389, 5000, 5001, 8008, 8080, 8123, 8443, 9100}

	portsNormal = func() []int {
		out := make([]int, 0, len(services))
		for p := range services {
			out = append(out, p)
		}
		sort.Ints(out)
		return out
	}()
)

// Ports zet een profielnaam of een eigen opgave om in een lijst poorten.
// Toegestaan: "snel", "normaal", "grondig", of iets als "22,80,8000-8100".
func Ports(spec string) ([]int, error) {
	switch strings.ToLower(strings.TrimSpace(spec)) {
	case "", "snel":
		return append([]int(nil), portsQuick...), nil
	case "normaal":
		return append([]int(nil), portsNormal...), nil
	case "grondig":
		out := make([]int, 0, 1024+len(portsNormal))
		for p := 1; p <= 1024; p++ {
			out = append(out, p)
		}
		for _, p := range portsNormal {
			if p > 1024 {
				out = append(out, p)
			}
		}
		return out, nil
	}
	return parsePortSpec(spec)
}

func parsePortSpec(spec string) ([]int, error) {
	seen := map[int]bool{}
	var out []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi := part, part
		if i := strings.IndexByte(part, '-'); i >= 0 {
			lo, hi = strings.TrimSpace(part[:i]), strings.TrimSpace(part[i+1:])
		}
		a, err := strconv.Atoi(lo)
		if err != nil {
			return nil, fmt.Errorf("%q is geen poortnummer", lo)
		}
		b, err := strconv.Atoi(hi)
		if err != nil {
			return nil, fmt.Errorf("%q is geen poortnummer", hi)
		}
		if a > b {
			a, b = b, a
		}
		if a < 1 || b > 65535 {
			return nil, fmt.Errorf("poorten moeten tussen 1 en 65535 liggen, kreeg %d-%d", a, b)
		}
		for p := a; p <= b; p++ {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("geen poorten opgegeven")
	}
	sort.Ints(out)
	return out, nil
}

// ServiceName geeft de naam van de dienst achter een poort, of "?" als we
// hem niet kennen. Een open poort die we niet thuisbrengen is nog steeds
// informatie.
func ServiceName(port int) string {
	if s, ok := services[port]; ok {
		return s.name
	}
	return "?"
}

// Target is één te scannen combinatie van host en poort.
type Target struct {
	IP   string
	Port int
}

// PortScanOptions stuurt de scan aan.
type PortScanOptions struct {
	// Workers is het totale aantal gelijktijdige verbindingspogingen.
	Workers int
	// PerHost begrenst hoeveel daarvan op dezelfde host gericht mogen
	// zijn. Bedoeld als beleefdheid tegenover kleine apparaten: een
	// IoT-stack met een handvol sockets krijgt zestig gelijktijdige SYN's
	// niet netjes verwerkt. Op gewone hosts is geen effect gemeten, dus
	// houd de waarde niet onnodig laag — dat maakt de scan alleen trager.
	PerHost int
	Timeout time.Duration
}

func (o PortScanOptions) withDefaults() PortScanOptions {
	if o.Workers <= 0 {
		o.Workers = 96
	}
	if o.PerHost <= 0 {
		o.PerHost = 16
	}
	if o.PerHost > o.Workers {
		o.PerHost = o.Workers
	}
	if o.Timeout <= 0 {
		o.Timeout = time.Second
	}
	return o
}

// interleave herschikt de targets zodat opeenvolgende opdrachten steeds
// een ándere host raken. Zonder dit werkt de pool host voor host af en
// krijgt elk apparaat toch de volle lading tegelijk.
func interleave(targets []Target) []Target {
	byHost := map[string][]Target{}
	var order []string
	for _, t := range targets {
		if _, ok := byHost[t.IP]; !ok {
			order = append(order, t.IP)
		}
		byHost[t.IP] = append(byHost[t.IP], t)
	}
	out := make([]Target, 0, len(targets))
	for n := 0; len(out) < len(targets); n++ {
		for _, ip := range order {
			if n < len(byHost[ip]) {
				out = append(out, byHost[ip][n])
			}
		}
	}
	return out
}

// definitiefDicht scheidt "deze poort is echt dicht" van "ik weet het niet".
//
// Een geweigerde of gereset verbinding is een antwoord: daar luistert
// niets. Een time-out of een fout uit de netwerkstack zelf is géén
// antwoord — bij te veel gelijktijdige verbindingen raakt Windows door
// z'n dynamische poortrange heen en faalt een connect naar een poort die
// wel degelijk openstaat. Zulke gevallen gaan naar een tweede, rustiger
// ronde; ze als "dicht" boeken zou stilletjes poorten laten verdwijnen.
func definitiefDicht(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	for _, e := range []error{
		windows.WSAECONNREFUSED, windows.WSAECONNRESET, windows.WSAEHOSTUNREACH,
		windows.WSAENETUNREACH, syscall.ECONNREFUSED, syscall.ECONNRESET,
	} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// ScanPorts probeert een TCP-verbinding op te zetten naar elke target.
//
// Een volledige connect, geen half-open SYN-scan: dat laatste zou raw
// sockets vereisen, en de winst is op een thuisnetwerk verwaarloosbaar.
// De keerzijde is dat de verbinding in de logs van de host verschijnt —
// op je eigen netwerk geen bezwaar.
//
// onOpen wordt aangeroepen zodra een poort open blijkt, dus de UI kan
// meegroeien tijdens de scan. De aanroep gebeurt vanuit meerdere
// goroutines en is intern geserialiseerd.
func ScanPorts(ctx context.Context, targets []Target, opt PortScanOptions, onOpen func(ip string, p model.Port)) {
	opt = opt.withDefaults()

	twijfel, sprak := scanPass(ctx, targets, opt, onOpen)
	if ctx.Err() != nil {
		return
	}

	// Alleen opnieuw proberen bij hosts die tijdens de eerste ronde
	// mínstens één keer duidelijk antwoord gaven — open of geweigerd.
	// Een host die overal stil op blijft is uit of volledig dichtgezet;
	// die nog eens met het dubbele geduld aflopen kost minuten en levert
	// per definitie niets op.
	var hertest []Target
	for _, t := range twijfel {
		if sprak[t.IP] {
			hertest = append(hertest, t)
		}
	}
	if len(hertest) == 0 {
		return
	}

	kalm := opt
	kalm.Workers = opt.Workers / 4
	if kalm.Workers < 8 {
		kalm.Workers = 8
	}
	kalm.Timeout = opt.Timeout * 2
	scanPass(ctx, hertest, kalm, onOpen)
}

// scanPass doet één ronde. Het geeft terug welke targets geen uitsluitsel
// gaven, en welke hosts überhaupt van zich lieten horen.
func scanPass(ctx context.Context, targets []Target, opt PortScanOptions, onOpen func(ip string, p model.Port)) ([]Target, map[string]bool) {
	targets = interleave(targets)

	// Eén doorlaatbewijs-kanaal per host, zodat nooit meer dan PerHost
	// verbindingen tegelijk op hetzelfde apparaat afkomen.
	perHost := make(map[string]chan struct{}, 32)
	for _, t := range targets {
		if _, ok := perHost[t.IP]; !ok {
			perHost[t.IP] = make(chan struct{}, opt.PerHost)
		}
	}

	jobs := make(chan Target, opt.Workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var twijfel []Target
	sprak := map[string]bool{}
	d := net.Dialer{Timeout: opt.Timeout}

	for w := 0; w < opt.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				if ctx.Err() != nil {
					return
				}
				sem := perHost[t.IP]
				sem <- struct{}{}
				addr := net.JoinHostPort(t.IP, strconv.Itoa(t.Port))
				conn, err := d.DialContext(ctx, "tcp", addr)
				<-sem
				if err != nil {
					mu.Lock()
					if definitiefDicht(err) {
						sprak[t.IP] = true
					} else if ctx.Err() == nil {
						twijfel = append(twijfel, t)
					}
					mu.Unlock()
					continue
				}
				conn.Close()
				mu.Lock()
				sprak[t.IP] = true
				if onOpen != nil {
					onOpen(t.IP, model.Port{Number: t.Port, Service: ServiceName(t.Port)})
				}
				mu.Unlock()
			}
		}()
	}

	for _, t := range targets {
		select {
		case jobs <- t:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return nil, sprak
		}
	}
	close(jobs)
	wg.Wait()
	return twijfel, sprak
}

// hintWeight geeft specifieke poorten meer stem. Zonder dit verliest een
// Synology van z'n eigen bestandsdeling: 5001 (DSM) zegt heel precies
// "NAS", terwijl 139 en 445 samen luider "PC" roepen — terwijl elke NAS
// nu eenmaal ook SMB draait. Poorten die hier niet in staan wegen 1.
var hintWeight = map[int]int{
	// NAS-specifiek
	5001: 3, 2049: 3, 548: 3, 873: 2,
	// Randapparatuur en huisautomatisering
	631: 3, 9100: 3, 515: 2, 554: 3, 8554: 3, 8123: 3, 1883: 2, 8883: 2,
	// Mediaspelers
	32400: 3, 8096: 3, 8008: 2, 8009: 2,
	// RDP is een sterk signaal voor een echte werkplek
	3389: 2,
}

// GuessKind leidt uit de open poorten af wat voor apparaat dit is.
//
// Meerdere hints kunnen tegelijk gelden, dus we tellen gewogen en laten
// de sterkste winnen. Bij gelijke stand gaat het specifiekere soort voor.
func GuessKind(ports []model.Port) model.Kind {
	score := map[model.Kind]int{}
	for _, p := range ports {
		s, ok := services[p.Number]
		if !ok || s.hint == "" {
			continue
		}
		w := hintWeight[p.Number]
		if w == 0 {
			w = 1
		}
		score[s.hint] += w
	}
	if len(score) == 0 {
		return model.KindUnknown
	}
	order := []model.Kind{model.KindNAS, model.KindIoT, model.KindTV, model.KindPhone, model.KindPC}
	best, bestN := model.KindUnknown, 0
	for _, k := range order {
		if score[k] > bestN {
			best, bestN = k, score[k]
		}
	}
	return best
}
