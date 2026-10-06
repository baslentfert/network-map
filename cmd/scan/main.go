// Command scan draait één actieve ronde over je netwerk en drukt het
// resultaat af. Het is de backend van de app zonder de app eromheen:
// handig om te zien wat de scanner werkelijk vindt, en om te draaien
// voordat Npcap geïnstalleerd is — dit deel heeft het niet nodig.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"netwerksniffer/internal/capture"
	"netwerksniffer/internal/i18n"
	"netwerksniffer/internal/model"
	"netwerksniffer/internal/netif"
	"netwerksniffer/internal/probe"
	"netwerksniffer/internal/store"
)

var taal = i18n.Standaard

func main() {
	var (
		ifaceName = flag.String("iface", "", "adapter (naam, IP of \\Device\\NPF_{...}); leeg = automatisch")
		portSpec  = flag.String("ports", "snel", "poorten: snel, normaal, grondig, of bijv. 22,80,8000-8100")
		noPorts   = flag.Bool("no-ports", false, "alleen hosts zoeken, geen poortscan")
		pingTO    = flag.Duration("ping-timeout", 700*time.Millisecond, "hoe lang op een ping wachten")
		portTO    = flag.Duration("port-timeout", 600*time.Millisecond, "hoe lang op een TCP-verbinding wachten")
		workers   = flag.Int("workers", 96, "aantal gelijktijdige verbindingen")
		perHost   = flag.Int("per-host", 6, "hoeveel verbindingen tegelijk naar dezelfde host")
		list      = flag.Bool("list", false, "alleen de adapters tonen en stoppen")
		quiet     = flag.Bool("quiet", false, "geen voortgang tonen")
		lang      = flag.String("lang", i18n.Standaard, "taal voor meldingen (nl, en)")
		listen    = flag.Duration("listen", 0, "na de scan zo lang passief meeluisteren (vraagt administratorrechten)")
	)
	flag.Parse()
	taal = *lang

	if *list {
		listInterfaces()
		return
	}

	iface, err := pickInterface(*ifaceName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fout:", err)
		os.Exit(1)
	}

	ports, err := probe.Ports(*portSpec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fout in -ports:", err)
		os.Exit(1)
	}

	fmt.Printf("Adapter   %s (%s)\n", iface.Name, iface.Description)
	fmt.Printf("Adres     %s in %s, gateway %s\n", iface.IP, iface.CIDR, iface.Gateway)
	if len(iface.DNS) > 0 {
		fmt.Printf("DNS       %s\n", strings.Join(iface.DNS, ", "))
	}
	if *noPorts {
		fmt.Printf("Scan      %d adressen, geen poortscan\n\n", iface.HostCount())
	} else {
		fmt.Printf("Scan      %d adressen, %d poorten per host\n\n", iface.HostCount(), len(ports))
	}

	st := store.New(nil)
	sc := &probe.Scanner{
		Iface:       iface,
		Store:       st,
		PingTimeout: *pingTO,
		Ports:       ports,
		SkipPorts:   *noPorts,
		PortOpts:    probe.PortScanOptions{Workers: *workers, PerHost: *perHost, Timeout: *portTO},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	start := time.Now()
	lastPhase := ""
	lastDraw := time.Time{}
	err = sc.Run(ctx, func(p probe.Progress) {
		if *quiet {
			return
		}
		newPhase := p.Phase != lastPhase
		if newPhase {
			if lastPhase != "" {
				fmt.Fprintln(os.Stderr)
			}
			lastPhase = p.Phase
		}
		// Niet bij elk van de 253 adressen opnieuw tekenen: dat vult een
		// weggepijpte uitvoer met duizenden regels.
		done := p.Total > 0 && p.Done == p.Total
		if !newPhase && !done && time.Since(lastDraw) < 100*time.Millisecond {
			return
		}
		lastDraw = time.Now()

		if p.Total > 0 {
			fmt.Fprintf(os.Stderr, "\r  %-9s %d/%d   ", p.Phase, p.Done, p.Total)
		} else {
			fmt.Fprintf(os.Stderr, "\r  %-9s          ", p.Phase)
		}
	})
	if !*quiet {
		fmt.Fprintln(os.Stderr)
	}
	if err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, "fout:", err)
	}

	printResults(st, time.Since(start))

	if *listen > 0 {
		luister(ctx, iface, st, *listen)
		fmt.Println("\n=== na passief meeluisteren ===")
		printResults(st, time.Since(start))
	}
}

// luister draait de passieve meeluisteraar en toont wat er binnenkomt.
func luister(ctx context.Context, iface netif.Adapter, st *store.Store, duur time.Duration) {
	fmt.Printf("\nPassief meeluisteren op %s gedurende %s...\n", iface.Name, duur)
	voor := len(st.Events())

	c, annuleer := context.WithTimeout(ctx, duur)
	defer annuleer()

	sn := &capture.Sniffer{Iface: iface, Store: st}
	if err := sn.Run(c); err != nil {
		fmt.Fprintln(os.Stderr, "fout:", err)
		return
	}

	evs := st.Events()
	nieuw := 0
	for _, e := range evs[min(voor, len(evs)):] {
		if e.Tag == model.TagDHCP || e.Tag == model.TagNew {
			fmt.Printf("  [%s] %s\n", e.Tag, zin(e))
			nieuw++
		}
	}
	if nieuw == 0 {
		fmt.Println("  (niets nieuws opgevangen in dit venster)")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func pickInterface(name string) (netif.Adapter, error) {
	if name != "" {
		return netif.ByName(name)
	}
	return netif.Primary()
}

func listInterfaces() {
	all, err := netif.List()
	if err != nil {
		fmt.Fprintln(os.Stderr, "fout:", err)
		os.Exit(1)
	}
	primary, _ := netif.Primary()
	for _, i := range all {
		mark := " "
		if i.Name == primary.Name && i.IP == primary.IP {
			mark = "*"
		}
		state := "uit"
		if i.Up {
			state = "aan"
		}
		gw := i.Gateway
		if gw == "" {
			gw = "geen gateway"
		}
		fmt.Printf("%s %-22s %-18s %-18s %s\n", mark, i.Name, i.CIDR, gw, state)
		fmt.Printf("  %-22s %s\n", "", i.Description)
	}
	fmt.Println("\n* = wordt automatisch gekozen")
}

func printResults(st *store.Store, took time.Duration) {
	g := st.Graph()
	hosts := g.Hosts
	sort.Slice(hosts, func(a, b int) bool { return ipLess(hosts[a].IP, hosts[b].IP) })

	fmt.Printf("\n%d apparaten gevonden in %s\n\n", len(hosts), took.Round(time.Millisecond))

	fmt.Printf("%-15s %-18s %-26s %-22s %s\n", "IP", "MAC", "FABRIKANT", "NAAM", "OPEN POORTEN")
	fmt.Println(strings.Repeat("-", 110))

	for _, h := range hosts {
		mac := h.MAC
		if mac == "" {
			mac = "—"
		}
		vendor := h.Vendor
		if vendor == "" {
			vendor = "—"
		}
		// Zonder naam de modelaanduiding tonen, tussen haakjes zodat
		// zichtbaar blijft dat het apparaat zelf geen naam prijsgaf.
		name := h.Name
		if name == "" && h.Model != "" {
			name = "(" + h.Model + ")"
		}
		if name == "" {
			name = "—"
		}

		var ports []string
		for _, p := range h.Ports {
			ports = append(ports, fmt.Sprintf("%d/%s", p.Number, p.Service))
		}
		portStr := strings.Join(ports, " ")
		if portStr == "" {
			portStr = "—"
		}

		tag := ""
		switch {
		case h.IsSelf:
			tag = "  <- deze machine"
		case h.IsGateway:
			tag = "  <- gateway"
		}

		fmt.Printf("%-15s %-18s %-26s %-22s %s%s\n",
			h.IP, mac, trunc(vendor, 26), trunc(name, 22), portStr, tag)

		if h.OSHint != "" || h.Kind != model.KindUnknown {
			var bits []string
			if h.Kind != model.KindUnknown {
				bits = append(bits, string(h.Kind))
			}
			if h.OSHint != "" {
				bits = append(bits, fmt.Sprintf("TTL %d → %s", h.TTL, h.OSHint))
			}
			if h.RandomMAC {
				bits = append(bits, "privé-MAC, roteert")
			}
			fmt.Printf("%-15s %s\n", "", strings.Join(bits, " · "))
		}
	}

	if evs := st.Events(); len(evs) > 0 {
		notable := 0
		for _, e := range evs {
			if e.Tag == model.TagAlert || e.Tag == model.TagScan {
				if notable == 0 {
					fmt.Println("\nMeldingen:")
				}
				notable++
				fmt.Printf("  [%s] %s\n", e.Tag, zin(e))
			}
		}
	}
}

// zin maakt van een gebeurtenis een leesbare regel in de gekozen taal.
func zin(e model.Event) string {
	var args []string
	for k, v := range e.Args {
		args = append(args, k, v)
	}
	return i18n.T(taal, e.Key, args...)
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// ipLess sorteert IPv4-adressen numeriek in plaats van alfabetisch, zodat
// .9 vóór .10 komt.
func ipLess(a, b string) bool {
	pa, pb := ipParts(a), ipParts(b)
	for i := 0; i < 4; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return a < b
}

func ipParts(s string) [4]int {
	var out [4]int
	part, idx := 0, 0
	for i := 0; i < len(s) && idx < 4; i++ {
		if s[i] == '.' {
			out[idx] = part
			part, idx = 0, idx+1
			continue
		}
		if s[i] >= '0' && s[i] <= '9' {
			part = part*10 + int(s[i]-'0')
		}
	}
	if idx < 4 {
		out[idx] = part
	}
	return out
}
