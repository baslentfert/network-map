package capture

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"netwerksniffer/internal/netif"
	"netwerksniffer/internal/pcapfile"
)

// OpnameOpties begrenst een opname. Zonder grenzen vult een opname op een
// druk netwerk in een kwartier je schijf.
type OpnameOpties struct {
	Bestand string
	Iface   netif.Adapter

	// MaxDuur stopt de opname na deze tijd. 0 = geen grens.
	MaxDuur time.Duration
	// MaxBytes stopt zodra het bestand zo groot is. 0 = geen grens.
	MaxBytes uint64
	// MaxPakketten stopt na zoveel pakketten. 0 = geen grens.
	MaxPakketten uint64
	// Snaplen is hoeveel van elk pakket bewaard wordt. Zet dit op 128 als
	// je alleen wilt zien wie met wie praat: dan blijven de koppen over en
	// blijft de inhoud buiten het bestand.
	Snaplen uint32
}

func (o OpnameOpties) metStandaarden() OpnameOpties {
	if o.Snaplen == 0 {
		o.Snaplen = 65535
	}
	if o.MaxBytes == 0 {
		o.MaxBytes = 256 << 20 // 256 MB
	}
	if o.MaxDuur == 0 {
		o.MaxDuur = 10 * time.Minute
	}
	return o
}

// OpnameStand is de voortgang, voor een teller op het scherm.
type OpnameStand struct {
	Bezig     bool      `json:"running"`
	Bestand   string    `json:"file"`
	Pakketten uint64    `json:"packets"`
	Bytes     uint64    `json:"bytes"`
	Gestart   time.Time `json:"started"`
	Reden     string    `json:"stopReason,omitempty"`
}

// Opname schrijft het netwerkverkeer naar een pcap-bestand.
type Opname struct {
	opt OpnameOpties

	mu    sync.Mutex
	stand OpnameStand
}

func NieuweOpname(opt OpnameOpties) *Opname {
	return &Opname{opt: opt.metStandaarden()}
}

func (o *Opname) Stand() OpnameStand {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.stand
}

// Run neemt op tot een grens bereikt is of de context afloopt.
//
// Wat je krijgt zijn kale IP-pakketten zonder ethernetkop — dat is alles
// wat een raw socket op Windows geeft. Wireshark leest dat prima; alleen
// ARP en LLDP zitten er niet in, want die leven onder de IP-laag.
func (o *Opname) Run(ctx context.Context) error {
	zelf, _ := netip.ParseAddr(o.opt.Iface.IP)

	fd, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_IP)
	if err != nil {
		return fmt.Errorf("raw socket openen mislukt (%w) — opnemen vraagt administratorrechten", err)
	}
	defer windows.Closesocket(fd)

	var adres [4]byte
	if zelf.Is4() {
		adres = zelf.As4()
	}
	if err := windows.Bind(fd, &windows.SockaddrInet4{Addr: adres}); err != nil {
		return fmt.Errorf("binden aan %s mislukt: %w", o.opt.Iface.IP, err)
	}

	var in uint32 = rcvallOn
	var uit, teruggegeven uint32
	if err := windows.WSAIoctl(fd, sioRcvAll,
		(*byte)(unsafe.Pointer(&in)), 4,
		(*byte)(unsafe.Pointer(&uit)), 4,
		&teruggegeven, nil, 0); err != nil {
		return fmt.Errorf("promiscuous modus geweigerd (%w) — start de app als administrator", err)
	}

	schrijver, err := pcapfile.Maak(o.opt.Bestand, pcapfile.LinkRaw, o.opt.Snaplen)
	if err != nil {
		return err
	}
	// Sluiten gebeurt altijd: zonder flush mist het laatste stuk van het
	// bestand en opent Wireshark het als beschadigd.
	defer schrijver.Sluit()

	o.mu.Lock()
	o.stand = OpnameStand{Bezig: true, Bestand: o.opt.Bestand, Gestart: time.Now()}
	o.mu.Unlock()

	stop := func(reden string) {
		o.mu.Lock()
		o.stand.Bezig, o.stand.Reden = false, reden
		o.mu.Unlock()
	}

	tv := windows.Timeval{Sec: 1}
	windows.SetsockoptTimeval(fd, windows.SOL_SOCKET, windows.SO_RCVTIMEO, &tv)

	eind := time.Now().Add(o.opt.MaxDuur)
	buf := make([]byte, 65535)

	for {
		if ctx.Err() != nil {
			stop("gestopt")
			return nil
		}
		if time.Now().After(eind) {
			stop("tijdgrens bereikt")
			return nil
		}

		n, _, err := windows.Recvfrom(fd, buf, 0)
		if err != nil || n <= 0 {
			continue // leestimeout; de lus controleert de grenzen opnieuw
		}

		if err := schrijver.Schrijf(time.Now(), buf[:n], n); err != nil {
			stop("schrijffout")
			return fmt.Errorf("wegschrijven mislukt: %w", err)
		}

		p, b := schrijver.Stand()
		o.mu.Lock()
		o.stand.Pakketten, o.stand.Bytes = p, b
		o.mu.Unlock()

		if o.opt.MaxBytes > 0 && b >= o.opt.MaxBytes {
			stop("maximale grootte bereikt")
			return nil
		}
		if o.opt.MaxPakketten > 0 && p >= o.opt.MaxPakketten {
			stop("maximaal aantal pakketten bereikt")
			return nil
		}
	}
}
