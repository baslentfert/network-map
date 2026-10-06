// Command ports toont wat er op deze machine naar het netwerk luistert,
// en zegt per regel wat het is en of het open staat naar je hele netwerk.
//
// Zonder administratorrechten blijft een deel van de procesnamen leeg:
// Windows laat je niet in systeemprocessen kijken. Het programma meldt
// hoeveel dat er zijn in plaats van stilletjes lege kolommen te tonen.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"netwerksniffer/internal/i18n"
	"netwerksniffer/internal/listen"
)

func main() {
	var (
		taal    = flag.String("lang", i18n.Standaard, "taal van de uitleg (nl, en)")
		alles   = flag.Bool("all", false, "ook de regels zonder opmerking tonen")
		verbind = flag.Bool("connections", false, "actieve verbindingen tonen in plaats van luisteraars")
		breed   = flag.Bool("wide", false, "uitleg per regel tonen")
	)
	flag.Parse()

	ctx, annuleer := context.WithTimeout(context.Background(), 30*time.Second)
	defer annuleer()

	ov, err := listen.Scan(ctx, *taal)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fout:", err)
		os.Exit(1)
	}

	if *verbind {
		toonVerbindingen(ov)
		return
	}
	toonLuisteraars(ov, *alles, *breed)
}

func toonLuisteraars(ov *listen.Overzicht, alles, breed bool) {
	netwerk, lokaal := 0, 0
	telling := map[listen.Oordeel]int{}
	for _, l := range ov.Luisteraars {
		telling[l.Oordeel]++
		if l.Bereik == listen.BereikNetwerk {
			netwerk++
		} else if l.Bereik == listen.BereikLokaal {
			lokaal++
		}
	}

	fmt.Printf("%d open poorten: %d naar je hele netwerk, %d alleen lokaal\n",
		len(ov.Luisteraars), netwerk, lokaal)
	fmt.Printf("%d vragen aandacht, %d niet herkend\n\n",
		telling[listen.OordeelLetOp], telling[listen.OordeelOnbekend])

	if ov.ZonderNaam > 0 {
		fmt.Printf("Let op: van %d regels konden we het proces niet achterhalen.\n", ov.ZonderNaam)
		fmt.Printf("Dat zijn systeemprocessen; start als administrator om ze te zien.\n\n")
	}

	fmt.Printf("%-9s %-22s %-20s %-24s %s\n", "", "ADRES", "PROCES", "DIENST", "OORDEEL")
	fmt.Println(strings.Repeat("-", 104))

	getoond := 0
	for _, l := range ov.Luisteraars {
		if !alles && l.Oordeel == listen.OordeelNormaal {
			continue
		}
		getoond++

		proces := l.Process
		if proces == "" {
			proces = fmt.Sprintf("? (pid %d)", l.PID)
		}
		merk := map[listen.Oordeel]string{
			listen.OordeelLetOp:    "  let op ",
			listen.OordeelOnbekend: " onbekend",
			listen.OordeelNormaal:  "         ",
		}[l.Oordeel]

		fmt.Printf("%-9s %-22s %-20s %-24s %s\n",
			merk, l.Proto+" "+l.Adres(), kort(proces, 20), kort(l.Dienst, 24), string(l.Bereik))

		if breed {
			fmt.Printf("%-9s %s\n", "", l.Uitleg)
			if l.Waarom != "" {
				fmt.Printf("%-9s → %s\n", "", l.Waarom)
			}
			if l.Path != "" {
				fmt.Printf("%-9s %s\n", "", l.Path)
			}
			fmt.Println()
		}
	}

	if getoond == 0 {
		fmt.Println("(niets dat aandacht vraagt)")
	}
	if !alles {
		fmt.Printf("\nAlleen regels met een opmerking. Gebruik -all voor de volledige lijst,\n")
		fmt.Printf("-wide voor de uitleg per regel.\n")
	}
}

func toonVerbindingen(ov *listen.Overzicht) {
	// Per proces samenvatten: honderden losse regels zeggen minder dan
	// "deze browser heeft veertig verbindingen open".
	type groep struct {
		proces string
		aantal int
		naar   map[string]bool
	}
	groepen := map[string]*groep{}
	for _, v := range ov.Verbindingen {
		naam := v.Process
		if naam == "" {
			naam = fmt.Sprintf("? (pid %d)", v.PID)
		}
		g := groepen[naam]
		if g == nil {
			g = &groep{proces: naam, naar: map[string]bool{}}
			groepen[naam] = g
		}
		g.aantal++
		if i := strings.LastIndex(v.Extern, ":"); i > 0 {
			g.naar[v.Extern[:i]] = true
		}
	}

	var lijst []*groep
	for _, g := range groepen {
		lijst = append(lijst, g)
	}
	sort.Slice(lijst, func(a, b int) bool { return lijst[a].aantal > lijst[b].aantal })

	fmt.Printf("%d actieve verbindingen, %d processen\n\n", len(ov.Verbindingen), len(lijst))
	fmt.Printf("%-28s %12s %s\n", "PROCES", "VERBINDINGEN", "UNIEKE ADRESSEN")
	fmt.Println(strings.Repeat("-", 68))
	for _, g := range lijst {
		fmt.Printf("%-28s %12d %d\n", kort(g.proces, 28), g.aantal, len(g.naar))
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
