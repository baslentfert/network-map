// Command opname neemt het netwerkverkeer op in een pcap-bestand dat je
// in Wireshark kunt openen.
//
// Vereist administratorrechten: raw sockets zijn dat op Windows nu eenmaal.
// Reken er ook op dat je virusscanner hierop aanslaat — een onbekend
// programma dat de netwerkkaart in promiscuous modus zet is precies het
// patroon waar heuristiek voor gemaakt is.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"netwerksniffer/internal/capture"
	"netwerksniffer/internal/netif"
)

func main() {
	var (
		uit     = flag.String("out", "", "bestandsnaam; leeg = opname-<datum>.pcap in de huidige map")
		duur    = flag.Duration("duration", 60*time.Second, "hoe lang opnemen")
		maxMB   = flag.Int("max-mb", 256, "stop bij deze bestandsgrootte")
		snaplen = flag.Int("snaplen", 65535, "hoeveel van elk pakket bewaren; 128 = alleen de koppen")
		ifnaam  = flag.String("iface", "", "adapter; leeg = automatisch")
	)
	flag.Parse()

	iface, err := kiesAdapter(*ifnaam)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fout:", err)
		os.Exit(1)
	}

	bestand := *uit
	if bestand == "" {
		bestand = fmt.Sprintf("opname-%s.pcap", time.Now().Format("20060102-150405"))
	}
	if abs, err := filepath.Abs(bestand); err == nil {
		bestand = abs
	}

	op := capture.NieuweOpname(capture.OpnameOpties{
		Bestand:  bestand,
		Iface:    iface,
		MaxDuur:  *duur,
		MaxBytes: uint64(*maxMB) << 20,
		Snaplen:  uint32(*snaplen),
	})

	fmt.Printf("Adapter   %s (%s)\n", iface.Name, iface.IP)
	fmt.Printf("Bestand   %s\n", bestand)
	fmt.Printf("Grenzen   %s, %d MB, %d bytes per pakket\n\n", *duur, *maxMB, *snaplen)
	fmt.Println("Opnemen... Ctrl-C om eerder te stoppen.")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	klaar := make(chan error, 1)
	go func() { klaar <- op.Run(ctx) }()

	tik := time.NewTicker(time.Second)
	defer tik.Stop()
	for {
		select {
		case err := <-klaar:
			st := op.Stand()
			fmt.Printf("\r%-60s\n", "")
			if err != nil {
				fmt.Fprintln(os.Stderr, "fout:", err)
				os.Exit(1)
			}
			fmt.Printf("Klaar: %s\n", st.Reden)
			fmt.Printf("%d pakketten, %.1f MB\n\n", st.Pakketten, float64(st.Bytes)/(1<<20))
			fmt.Printf("Openen in Wireshark:\n  %s\n", bestand)
			return
		case <-tik.C:
			st := op.Stand()
			fmt.Printf("\r  %d pakketten, %.1f MB   ", st.Pakketten, float64(st.Bytes)/(1<<20))
		}
	}
}

func kiesAdapter(naam string) (netif.Adapter, error) {
	if naam != "" {
		return netif.ByName(naam)
	}
	return netif.Primary()
}
