// Package discover vraagt apparaten naar hun eigen naam.
//
// Drie protocollen, omdat geen enkel apparaat ze alle drie spreekt:
// NetBIOS pakt Windows-machines, mDNS pakt Apple, printers en IoT, en
// SSDP pakt tv's, mediaspelers en NAS-apparaten. Alles gaat over gewone
// UDP-sockets — geen Npcap, geen administratorrechten.
//
// De passieve capture-laag vult dit later aan met namen die je actief
// niet kunt opvragen: de hostnaam in een DHCP-request, en de multicast
// aankondigingen van apparaten die directe vragen negeren.
package discover

import (
	"context"
	"sync"
	"time"
)

// Naamvondst is één naam met de bron die hem leverde.
type Naamvondst struct {
	IP     string
	Name   string
	Origin string
	// MAC is alleen gevuld door NetBIOS, dat het adres meestuurt.
	MAC string
	// Detail is extra context voor het detailpaneel: een diensttype, of
	// fabrikant en model uit een UPnP-beschrijving.
	Detail string
	// Model is een modelaanduiding zonder naam, bijvoorbeeld uit een
	// TLS-certificaat. Vult de kaart voor apparaten die niets adverteren.
	Model string
}

// Opties stelt in hoe lang we op antwoorden wachten. De protocollen
// draaien parallel, dus de totale duur is de langste van de drie.
type Opties struct {
	NetBIOS time.Duration
	MDNS    time.Duration
	SSDP    time.Duration
}

func (o Opties) metStandaarden() Opties {
	if o.NetBIOS <= 0 {
		o.NetBIOS = 2 * time.Second
	}
	if o.MDNS <= 0 {
		o.MDNS = 3 * time.Second
	}
	if o.SSDP <= 0 {
		o.SSDP = 4 * time.Second
	}
	return o
}

// Namen bevraagt alle drie de protocollen tegelijk en meldt elke vondst
// zodra hij binnen is, zodat de kaart al invult terwijl de rest nog loopt.
//
// Fouten van een enkel protocol zijn geen reden om te stoppen: als
// bijvoorbeeld poort 137 door een firewall wordt geblokkeerd, blijven
// mDNS en SSDP gewoon hun werk doen.
func Namen(ctx context.Context, ips []string, opt Opties, onVondst func(Naamvondst)) {
	opt = opt.metStandaarden()

	var mu sync.Mutex
	meld := func(v Naamvondst) {
		if (v.Name == "" && v.Model == "") || onVondst == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		onVondst(v)
	}

	var wg sync.WaitGroup
	wg.Add(5)

	go func() {
		defer wg.Done()
		NetBIOS(ctx, ips, opt.NetBIOS, func(r NetBIOSResult) {
			d := ""
			if r.Workgroup != "" {
				d = "werkgroep " + r.Workgroup
			}
			meld(Naamvondst{IP: r.IP, Name: r.Name, Origin: "netbios", MAC: r.MAC, Detail: d})
		})
	}()

	go func() {
		defer wg.Done()
		MDNS(ctx, ips, opt.MDNS, func(r MDNSResult) {
			// Een instantienaam hoort bij een dienst en is door een mens
			// gekozen; een kale hostnaam komt uit een A- of PTR-record. Ze
			// krijgen een eigen herkomst zodat de store de mooiste kan kiezen.
			herkomst := "mdns-host"
			if r.Service != "" {
				herkomst = "mdns"
			}
			meld(Naamvondst{IP: r.IP, Name: r.Name, Origin: herkomst, Detail: r.Service})
		})
	}()

	go func() {
		defer wg.Done()
		SSDP(ctx, ips, opt.SSDP, func(r SSDPResult) {
			naam := r.Name
			if naam == "" {
				naam = r.Model
			}
			var detail string
			switch {
			case r.Manufacturer != "" && r.Model != "":
				detail = r.Manufacturer + " " + r.Model
			case r.Model != "":
				detail = r.Model
			default:
				detail = r.Server
			}
			meld(Naamvondst{IP: r.IP, Name: naam, Origin: "ssdp", Detail: detail})
		})
	}()

	go func() {
		defer wg.Done()
		// Webinterfaces: veel IoT-apparaten antwoorden op geen enkel
		// naamprotocol maar vertellen via HTTP precies wat ze zijn.
		HTTPIdentificatie(ctx, ips, func(r HTTPResult) {
			meld(Naamvondst{IP: r.IP, Name: r.Name, Model: r.Model, Origin: "http"})
		})
	}()

	go func() {
		defer wg.Done()
		Certificaten(ctx, ips, func(r CertResult) {
			meld(Naamvondst{IP: r.IP, Model: r.Model, Origin: "tls"})
		})
	}()

	wg.Wait()
}
