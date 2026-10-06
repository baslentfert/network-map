// Command dnslog draait het DNS-doorgeefluik en toont live wat elk
// apparaat opvraagt.
//
// Zet in je router de DNS-server op het adres dat dit programma noemt.
// Vanaf dat moment komt elke naamvraag van elk apparaat hier langs, en
// zie je waar je netwerk met praat — zonder pakketopname.
//
// Stoppen met Ctrl-C; je ziet dan een overzicht per apparaat.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"netwerksniffer/internal/dnsproxy"
	"netwerksniffer/internal/netif"
)

func main() {
	var (
		adres    = flag.String("listen", "", "luisteradres; leeg = het LAN-adres van deze machine")
		poort    = flag.Int("port", 53, "poort (53 is de echte; een andere poort is handig om te testen)")
		upstream = flag.String("upstream", "1.1.1.1:53,8.8.8.8:53", "waar we de vragen naartoe sturen")
		stil     = flag.Bool("quiet", false, "alleen nieuwe domeinen tonen, niet elke vraag")
	)
	flag.Parse()

	luister := *adres
	if luister == "" {
		iface, err := netif.Primary()
		if err != nil {
			fmt.Fprintln(os.Stderr, "fout:", err)
			os.Exit(1)
		}
		luister = iface.IP
	}
	luister = fmt.Sprintf("%s:%d", luister, *poort)

	logboek := dnsproxy.NieuwLogboek(5000)
	proxy := dnsproxy.Nieuw(dnsproxy.Opties{
		Luister:  luister,
		Upstream: strings.Split(*upstream, ","),
	}, func(v dnsproxy.Vraag) {
		nieuw := logboek.Noteer(v)
		if *stil && !nieuw {
			return
		}
		merk := " "
		if nieuw {
			merk = "+"
		}
		antw := strings.Join(v.Antwoorden, " ")
		if len(antw) > 40 {
			antw = antw[:39] + "…"
		}
		fmt.Printf("%s %s  %-15s %-45s %-6s %s\n",
			merk, v.At.Format("15:04:05"), v.Client, kort(v.Name, 45), v.Type, antw)
	})

	st := proxy.Status()
	fmt.Printf("DNS-doorgeefluik op %s, stuurt door naar %s\n", luister, strings.Join(st.Upstream, ", "))
	fmt.Printf("Zet in je router de DNS-server op dit adres. Ctrl-C om te stoppen.\n\n")
	fmt.Printf("%s %-8s  %-15s %-45s %-6s %s\n", " ", "TIJD", "APPARAAT", "DOMEIN", "TYPE", "ANTWOORD")
	fmt.Println(strings.Repeat("-", 118))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	klaar := make(chan error, 1)
	go func() { klaar <- proxy.Run(ctx) }()

	select {
	case err := <-klaar:
		if err != nil {
			fmt.Fprintln(os.Stderr, "\nfout:", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		time.Sleep(150 * time.Millisecond)
	}

	samenvatting(logboek, proxy)
}

func samenvatting(l *dnsproxy.Logboek, p *dnsproxy.Proxy) {
	st := p.Status()
	fmt.Printf("\n\n%d vragen behandeld, %d mislukt\n\n", st.Vragen, st.Mislukt)

	app := l.Apparaten()
	if len(app) == 0 {
		fmt.Println("Geen vragen ontvangen.")
		fmt.Println("Staat de DNS-server in je router al op dit adres?")
		return
	}

	fmt.Printf("%-16s %8s %9s\n", "APPARAAT", "VRAGEN", "DOMEINEN")
	fmt.Println(strings.Repeat("-", 36))
	for _, a := range app {
		fmt.Printf("%-16s %8d %9d\n", a.Client, a.Vragen, a.Domeinen)
	}

	fmt.Printf("\nDrukste domeinen:\n")
	fmt.Printf("%-16s %-50s %6s\n", "APPARAAT", "DOMEIN", "AANTAL")
	fmt.Println(strings.Repeat("-", 76))
	for _, t := range l.Drukste(20, "") {
		fmt.Printf("%-16s %-50s %6d\n", t.Client, kort(t.Name, 50), t.Count)
	}
}

func kort(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
