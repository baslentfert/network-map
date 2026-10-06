package probe

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"netwerksniffer/internal/discover"
	"netwerksniffer/internal/model"
	"netwerksniffer/internal/netif"
	"netwerksniffer/internal/store"
)

// Scanner voert een actieve ronde uit over één subnet. Alles wat hij
// vindt gaat als Fact de store in; de scanner houdt zelf geen staat bij.
//
// Geen enkel onderdeel hiervan heeft Npcap of administratorrechten nodig.
type Scanner struct {
	Iface netif.Adapter
	Store *store.Store

	PingWorkers int
	PingTimeout time.Duration
	Ports       []int
	PortOpts    PortScanOptions

	// SkipPorts slaat de poortscan over. Handig voor de snelle
	// achtergrondronde die alleen wil weten wie er nog is.
	SkipPorts bool
}

// Progress meldt hoe ver een ronde is, zodat de UI een balk kan tonen.
type Progress struct {
	Phase string `json:"phase"`
	Done  int    `json:"done"`
	Total int    `json:"total"`
}

// Run doet een volledige ronde: wie leeft er, wat is hun MAC, hoe heten
// ze, en welke poorten staan open.
func (s *Scanner) Run(ctx context.Context, onProgress func(Progress)) error {
	report := func(p Progress) {
		if onProgress != nil {
			onProgress(p)
		}
	}

	s.registerSelfAndGateway()

	// 1. Wie reageert er? Dit vult meteen de ARP-cache van Windows,
	//    waardoor stap 2 gratis aan de MAC-adressen komt.
	targets := s.Iface.Hosts()
	report(Progress{Phase: "ping", Total: len(targets)})

	var mu sync.Mutex
	alive := make([]string, 0, 32)
	done := 0
	PingSweep(targets, s.PingWorkers, s.PingTimeout, func(r PingResult) {
		mu.Lock()
		done++
		if r.Alive {
			alive = append(alive, r.IP)
		}
		mu.Unlock()

		if r.Alive {
			s.Store.Observe(store.Fact{IP: r.IP, TTL: r.TTL})
		}
		report(Progress{Phase: "ping", Done: done, Total: len(targets)})
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// 2. De ARP-cache uitlezen. Hosts die niet op ping antwoorden maar wel
	//    een ARP-entry hebben zijn ook echt aanwezig — veel apparaten
	//    negeren ICMP maar kunnen ARP niet negeren.
	report(Progress{Phase: "arp"})
	if entries, err := ARPCache(); err == nil {
		known := map[string]bool{}
		for _, ip := range alive {
			known[ip] = true
		}
		for _, e := range entries {
			if e.IfIdx != s.Iface.Index {
				continue
			}
			s.Store.Observe(store.Fact{IP: e.IP, MAC: e.MAC, Origin: model.OriginARP})
			if !known[e.IP] {
				known[e.IP] = true
				alive = append(alive, e.IP)
			}
		}
	} else {
		s.Store.Log(model.TagScan, "", "ev.arpFailed", "err", err.Error())
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// 3. Namen. Eerst reverse DNS — gratis, maar levert alleen iets op als
	//    de router z'n DHCP-namen aan de DNS doorgeeft.
	report(Progress{Phase: "dns", Total: len(alive)})
	s.reverseDNS(ctx, alive, func(n int) {
		report(Progress{Phase: "dns", Done: n, Total: len(alive)})
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// 4. De apparaten zelf vragen hoe ze heten, via NetBIOS, mDNS en SSDP.
	//    Dit is verreweg de rijkste naambron: hier komen de namen vandaan
	//    die mensen zelf aan hun apparaten gaven.
	report(Progress{Phase: "namen", Total: len(alive)})
	s.zoekNamen(ctx, alive)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if s.SkipPorts || len(s.Ports) == 0 {
		report(Progress{Phase: "klaar"})
		return nil
	}

	// 5. Poortscan over de gevonden hosts.
	tg := make([]Target, 0, len(alive)*len(s.Ports))
	for _, ip := range alive {
		for _, p := range s.Ports {
			tg = append(tg, Target{IP: ip, Port: p})
		}
	}
	report(Progress{Phase: "poorten", Total: len(tg)})

	found := map[string][]model.Port{}
	var pmu sync.Mutex
	scanned := 0
	ScanPorts(ctx, tg, s.PortOpts, func(ip string, p model.Port) {
		pmu.Lock()
		found[ip] = append(found[ip], p)
		list := append([]model.Port(nil), found[ip]...)
		pmu.Unlock()

		s.Store.Observe(store.Fact{IP: ip, Ports: []model.Port{p}, Kind: GuessKind(list)})
	})
	scanned = len(tg)
	report(Progress{Phase: "klaar", Done: scanned, Total: scanned})
	return ctx.Err()
}

// registerSelfAndGateway zet de twee hosts vast die we zonder scannen al
// kennen: deze machine en de router.
func (s *Scanner) registerSelfAndGateway() {
	if s.Iface.IP != "" {
		s.Store.Observe(store.Fact{
			IP: s.Iface.IP, MAC: s.Iface.MAC, Self: true,
			Name: hostname(), Origin: model.OriginRDNS,
			Kind: model.KindPC,
		})
	}
	if s.Iface.Gateway != "" {
		s.Store.Observe(store.Fact{IP: s.Iface.Gateway, Gateway: true})
	}
	s.Store.SetSubnet(s.Iface.CIDR, s.Iface.Gateway)
}

// zoekNamen vraagt de apparaten zelf hoe ze heten.
//
// De drie protocollen kunnen dezelfde host een andere naam geven — een
// Synology heet via NetBIOS "DISKSTATION" en via mDNS "DiskStation".
// Beide gaan de store in met hun herkomst erbij; die kiest welke wint en
// bewaart de rest, zodat in het detailpaneel te zien blijft wie wat zei.
func (s *Scanner) zoekNamen(ctx context.Context, ips []string) {
	discover.Namen(ctx, ips, discover.Opties{}, func(v discover.Naamvondst) {
		// Bewust zonder v.MAC. Een NBSTAT-antwoord bevat achter de
		// namenlijst een adapteradres, maar dat blijkt in de praktijk
		// onbetrouwbaar — Windows' eigen nbtstat laat het bij deze
		// apparaten ook weg. Eén verkeerd MAC laat de store twee
		// apparaten als één zien, en ARP levert de koppeling toch al.
		f := store.Fact{IP: v.IP, Name: v.Name, Origin: v.Origin, Model: v.Model}
		// Een geadverteerd diensttype zegt vaak meer over het soort
		// apparaat dan de open poorten.
		if k := kindUitDienst(v.Detail); k != model.KindUnknown {
			f.Kind = k
		}
		s.Store.Observe(f)
	})
}

// kindUitDienst leidt het soort apparaat af uit een mDNS-diensttype of
// een UPnP-modelnaam.
func kindUitDienst(detail string) model.Kind {
	d := strings.ToLower(detail)
	switch {
	case d == "":
		return model.KindUnknown
	// Bewust zonder _airplay en _raop: elke Mac en iPhone adverteert die,
	// dus ze zeggen niets over het soort apparaat. Ze maakten eerder van
	// een MacBook een televisie.
	case strings.Contains(d, "googlecast"), strings.Contains(d, "spotify-connect"),
		strings.Contains(d, "sonos"), strings.Contains(d, "nvstream"):
		return model.KindTV
	case strings.Contains(d, "ipp"), strings.Contains(d, "printer"),
		strings.Contains(d, "pdl-datastream"), strings.Contains(d, "scanner"):
		return model.KindIoT
	case strings.Contains(d, "hap"), strings.Contains(d, "esphome"),
		strings.Contains(d, "homeassistant"), strings.Contains(d, "hue"):
		return model.KindIoT
	case strings.Contains(d, "smb"), strings.Contains(d, "afpovertcp"):
		return model.KindNAS
	case strings.Contains(d, "workstation"), strings.Contains(d, "werkgroep"):
		return model.KindPC
	}
	return model.KindUnknown
}

// reverseDNS vraagt voor elk levend adres een PTR-record op.
func (s *Scanner) reverseDNS(ctx context.Context, ips []string, onDone func(int)) {
	const workers = 24
	jobs := make(chan string, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	n := 0

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				c, cancel := context.WithTimeout(ctx, 900*time.Millisecond)
				names, err := net.DefaultResolver.LookupAddr(c, ip)
				cancel()

				mu.Lock()
				n++
				cur := n
				mu.Unlock()
				if onDone != nil {
					onDone(cur)
				}
				if err != nil || len(names) == 0 {
					continue
				}
				s.Store.Observe(store.Fact{
					IP: ip, Name: trimDot(names[0]), Origin: model.OriginRDNS,
				})
			}
		}()
	}
	for _, ip := range ips {
		select {
		case jobs <- ip:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		}
	}
	close(jobs)
	wg.Wait()
}

func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

// ParseAddrs zet een lijst tekstadressen om, en slaat onzin stil over.
func ParseAddrs(ips []string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ips))
	for _, s := range ips {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out
}
