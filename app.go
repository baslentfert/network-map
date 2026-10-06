package main

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"netwerksniffer/internal/baseline"
	"netwerksniffer/internal/capture"
	"netwerksniffer/internal/config"
	"netwerksniffer/internal/dnsproxy"
	"netwerksniffer/internal/i18n"
	"netwerksniffer/internal/listen"
	"netwerksniffer/internal/model"
	"netwerksniffer/internal/netif"
	"netwerksniffer/internal/probe"
	"netwerksniffer/internal/store"
)

// App is de brug tussen de scanner en de frontend. Alle exported methodes
// hier worden door Wails als TypeScript-functies beschikbaar gesteld.
type App struct {
	ctx   context.Context
	store *store.Store

	mu      sync.Mutex
	iface   netif.Adapter
	cancel  context.CancelFunc
	running bool
	// busy voorkomt dat een handmatige scan en de achtergrondronde
	// tegelijk het netwerk aflopen.
	busy bool
	// passief zegt of de meeluisteraar draait; passiefReden legt uit
	// waarom niet, in woorden die de gebruiker verder helpen.
	passief      bool
	passiefReden string
	// dnsProxy draait het DNS-doorgeefluik; nil als het uitstaat.
	dnsProxy *dnsproxy.Proxy
	dnsLog   *dnsproxy.Logboek
	dnsStop  context.CancelFunc
	// basis is de geleerde normaalsituatie van het netwerk.
	basis *baseline.Basislijn
	// taalCode is de gekozen taal. De backend gebruikt hem alleen voor
	// foutmeldingen die als gewone error naar buiten gaan; al het andere
	// draagt een sleutel en wordt in de frontend vertaald.
	taalCode string
}

// Status is wat de statusbalk toont.
type Status struct {
	Taal       string        `json:"lang"`
	Adapter    netif.Adapter `json:"adapter"`
	Monitoring bool          `json:"monitoring"`
	Scanning   bool          `json:"scanning"`
	// Passive meldt of we op dit moment meeluisteren. Dat gaat via een raw
	// socket — pure Go, geen Npcap, wel administratorrechten.
	Passive       bool   `json:"passive"`
	PassiveReason string `json:"passiveReason"`
	// Capture meldt of Npcap aanwezig is. Dat voegt alleen de laag ónder
	// IP toe: ARP-frames en LLDP. De rest werkt zonder.
	Capture       bool   `json:"capture"`
	CaptureReason string `json:"captureReason"`
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.store = store.New(func(event string, data any) {
		runtime.EventsEmit(ctx, event, data)
	})
	a.store.LoadAliases(config.LaadNamen())

	a.basis = baseline.Nieuw()
	// Ontbreekt het bestand, dan beginnen we met een lege basislijn; de
	// eerste ronde wordt dan vanzelf de norm.
	config.LaadJSON("basislijn.json", a.basis)
	// Een bewaarde keuze alleen overnemen als we die taal ook echt kennen.
	// Anders — bijvoorbeeld na het verwijderen van een taalbestand — zou de
	// keuzelijst op niets staan en de UI op sleutels terugvallen.
	if code := config.LaadTaal(); i18n.Bestaat(code) {
		a.taalCode = code
	}
	a.zetVenstertitel()

	// Kies meteen een adapter, zodat het scherm niet leeg opent.
	if i, err := netif.Primary(); err == nil {
		a.mu.Lock()
		a.iface = i
		a.mu.Unlock()
		a.store.SetSubnet(i.CIDR, i.Gateway)
	}
}

func (a *App) shutdown(ctx context.Context) {
	a.StopMonitor()
	config.BewaarNamen(a.store.Aliases())
}

// Interfaces geeft alle adapters, zodat de gebruiker er zelf een kan kiezen.
func (a *App) Interfaces() ([]netif.Adapter, error) {
	return netif.List()
}

// SelectInterface wisselt van adapter. Dat betekent een ander subnet, dus
// de monitor gaat uit en de kaart begint opnieuw.
func (a *App) SelectInterface(name string) (netif.Adapter, error) {
	i, err := netif.ByName(name)
	if err != nil {
		return netif.Adapter{}, err
	}
	a.StopMonitor()
	a.mu.Lock()
	a.iface = i
	a.mu.Unlock()
	a.store.SetSubnet(i.CIDR, i.Gateway)
	a.emitStatus()
	return i, nil
}

// taal geeft de gekozen taalcode, met terugval op de standaardtaal.
func (a *App) taal() string {
	if a.taalCode == "" {
		return i18n.Standaard
	}
	return a.taalCode
}

// Talen geeft de beschikbare talen voor de keuzelijst. Een taal
// toevoegen is een JSON-bestand in internal/i18n/locales zetten; deze
// lijst en de app volgen vanzelf.
func (a *App) Talen() []i18n.Taal {
	return i18n.Talen()
}

// Teksten geeft de volledige tekstcatalogus van één taal. De frontend
// haalt hem op bij het starten en bij elke taalwissel, zodat er maar één
// bron van waarheid is voor beide kanten van de app.
func (a *App) Teksten(code string) map[string]string {
	return i18n.Catalogus(code)
}

// SetTaal legt de keuze vast en bewaart hem voor de volgende keer.
func (a *App) SetTaal(code string) string {
	if !i18n.Bestaat(code) {
		code = i18n.Standaard
	}
	a.mu.Lock()
	a.taalCode = code
	a.mu.Unlock()
	config.BewaarTaal(code)
	a.zetVenstertitel()
	a.emitStatus()
	return code
}

// zetVenstertitel houdt de titelbalk van het venster in de gekozen taal.
// Die valt buiten de webview en verandert dus niet mee met de React-kant.
func (a *App) zetVenstertitel() {
	if a.ctx == nil {
		return
	}
	runtime.WindowSetTitle(a.ctx, i18n.T(a.taal(), "app.title"))
}

// Status vertelt de UI waar we staan.
func (a *App) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	ok, reason := capture.Available()
	return Status{
		Taal:          a.taal(),
		Adapter:       a.iface,
		Monitoring:    a.running,
		Scanning:      a.busy,
		Passive:       a.passief,
		PassiveReason: a.passiefReden,
		Capture:       ok,
		CaptureReason: reason,
	}
}

func (a *App) emitStatus() {
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "status", a.Status())
	}
}

// Ports leest wat er op déze machine naar het netwerk luistert.
//
// Anders dan de netwerkscan kijkt dit naar binnen: welke programma's hier
// een poort openhouden, en of die vanaf je hele netwerk bereikbaar is. De
// uitleg komt al vertaald terug, want dat is inhoud en geen schermtekst.
func (a *App) Ports() (*listen.Overzicht, error) {
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	c, annuleer := context.WithTimeout(ctx, 30*time.Second)
	defer annuleer()
	return listen.Scan(c, a.taal())
}

// --- wat is er veranderd ---------------------------------------------

// waarneming bouwt de huidige stand op uit de kaart en de DNS-gegevens.
func (a *App) waarneming() baseline.Waarneming {
	w := baseline.Waarneming{Hosts: a.store.Graph().Hosts, Domeinen: map[string][]string{}}

	a.mu.Lock()
	l := a.dnsLog
	a.mu.Unlock()
	if l != nil {
		for _, t := range l.Drukste(0, "") {
			w.Domeinen[t.Client] = append(w.Domeinen[t.Client], t.Name)
		}
	}
	return w
}

// Findings vergelijkt de huidige stand met de basislijn.
func (a *App) Findings() []baseline.Bevinding {
	a.mu.Lock()
	b := a.basis
	a.mu.Unlock()
	if b == nil {
		return nil
	}
	return baseline.Vergelijk(a.waarneming(), b)
}

// BaselineInfo vertelt hoe groot de basislijn is en wanneer hij voor het
// laatst is bijgewerkt.
type BaselineInfo struct {
	Devices int       `json:"devices"`
	Updated time.Time `json:"updated"`
	Empty   bool      `json:"empty"`
}

func (a *App) BaselineInfo() BaselineInfo {
	a.mu.Lock()
	b := a.basis
	a.mu.Unlock()
	if b == nil {
		return BaselineInfo{Empty: true}
	}
	return BaselineInfo{Devices: len(b.Apparaten), Updated: b.Bijgewerkt, Empty: b.Leeg()}
}

// LearnBaseline legt de huidige stand vast als het nieuwe normaal.
func (a *App) LearnBaseline() error {
	a.mu.Lock()
	b := a.basis
	a.mu.Unlock()
	if b == nil {
		return errors.New(i18n.T(a.taal(), "err.notStarted"))
	}
	b.Leer(a.waarneming())
	return config.BewaarJSON("basislijn.json", b)
}

// ForgetDevice haalt één apparaat uit de basislijn, bijvoorbeeld iets dat
// je hebt weggedaan.
func (a *App) ForgetDevice(key string) error {
	a.mu.Lock()
	b := a.basis
	a.mu.Unlock()
	if b == nil {
		return nil
	}
	b.Vergeet(key)
	return config.BewaarJSON("basislijn.json", b)
}

// --- DNS-doorgeefluik ---------------------------------------------------

// StartDNS zet het doorgeefluik aan op het LAN-adres van deze machine.
//
// Pas als de gebruiker de DNS-server in zijn router hierheen wijst, komt
// er verkeer langs. Tot die tijd draait dit zonder iets te zien, en dat
// zegt het scherm er ook bij.
func (a *App) StartDNS() error {
	a.mu.Lock()
	if a.dnsProxy != nil {
		a.mu.Unlock()
		return nil
	}
	iface := a.iface
	a.mu.Unlock()

	if iface.IP == "" {
		return errors.New(i18n.T(a.taal(), "err.noAdapter"))
	}

	logboek := dnsproxy.NieuwLogboek(5000)
	proxy := dnsproxy.Nieuw(dnsproxy.Opties{Luister: iface.IP + ":53"}, func(v dnsproxy.Vraag) {
		// Alleen een logregel bij een nieuw domein voor dit apparaat.
		// Elke vraag loggen zou het logboek in minuten vullen met ruis.
		if logboek.Noteer(v) && v.Name != "" {
			a.store.Log(model.TagDNS, "", "ev.dnsNew", "name", a.naamVoorIP(v.Client), "domain", v.Name)
		}
	})

	ctx, stop := context.WithCancel(a.ctx)
	a.mu.Lock()
	a.dnsProxy, a.dnsLog, a.dnsStop = proxy, logboek, stop
	a.mu.Unlock()

	fout := make(chan error, 1)
	go func() { fout <- proxy.Run(ctx) }()

	// Even wachten: een bezette poort merk je meteen, en dan is een fout
	// teruggeven nuttiger dan een knop die zogenaamd aan staat.
	select {
	case err := <-fout:
		a.StopDNS()
		if err != nil {
			return err
		}
	case <-time.After(400 * time.Millisecond):
	}
	a.emitStatus()
	return nil
}

// StopDNS zet het doorgeefluik uit. Het logboek blijft staan.
func (a *App) StopDNS() {
	a.mu.Lock()
	stop := a.dnsStop
	a.dnsProxy, a.dnsStop = nil, nil
	a.mu.Unlock()
	if stop != nil {
		stop()
	}
	a.emitStatus()
}

// DNSStatus vertelt of het doorgeefluik loopt en hoeveel het zag.
func (a *App) DNSStatus() dnsproxy.Status {
	a.mu.Lock()
	p := a.dnsProxy
	iface := a.iface
	a.mu.Unlock()
	if p == nil {
		return dnsproxy.Status{Adres: iface.IP + ":53"}
	}
	return p.Status()
}

// DNSDevices geeft per apparaat hoeveel het opvroeg, met de naam erbij
// zoals de netwerkkaart hem kent.
func (a *App) DNSDevices() []dnsproxy.Apparaat {
	a.mu.Lock()
	l := a.dnsLog
	a.mu.Unlock()
	if l == nil {
		return nil
	}
	app := l.Apparaten()
	for i := range app {
		app[i].Naam = a.naamVoorIP(app[i].Client)
	}
	return app
}

// DNSTop geeft de meest opgevraagde domeinen, eventueel van één apparaat.
func (a *App) DNSTop(n int, client string) []dnsproxy.Teller {
	a.mu.Lock()
	l := a.dnsLog
	a.mu.Unlock()
	if l == nil {
		return nil
	}
	return l.Drukste(n, client)
}

// DNSRecent geeft de laatste vragen, nieuwste eerst.
func (a *App) DNSRecent(n int) []dnsproxy.Vraag {
	a.mu.Lock()
	l := a.dnsLog
	a.mu.Unlock()
	if l == nil {
		return nil
	}
	return l.Recent(n)
}

// naamVoorIP zoekt de apparaatnaam op in de netwerkkaart. Valt terug op
// het IP-adres, want dat is altijd beter dan niets.
func (a *App) naamVoorIP(ip string) string {
	if a.store == nil {
		return ip
	}
	for _, h := range a.store.Graph().Hosts {
		if h.IP == ip {
			if h.Name != "" {
				return h.Name
			}
			if h.Model != "" {
				return h.Model
			}
			break
		}
	}
	return ip
}

// Graph geeft de hele kaart in één keer. De frontend haalt dit één keer
// op bij het openen; daarna komt alles via events binnen.
func (a *App) Graph() model.Graph {
	return a.store.Graph()
}

// Events geeft het logboek zoals het nu is.
func (a *App) Events() []model.Event {
	return a.store.Events()
}

// SetAlias legt een zelfgekozen naam vast en bewaart die op schijf, zodat
// hij een herstart van de app overleeft.
func (a *App) SetAlias(key, name string) {
	a.store.SetAlias(key, name)
	config.BewaarNamen(a.store.Aliases())
}

// ScanNow doet één volledige ronde: hosts zoeken, MAC's ophalen, namen
// opzoeken en poorten scannen.
func (a *App) ScanNow(portSpec string) error {
	ports, err := probe.Ports(portSpec)
	if err != nil {
		return err
	}
	return a.runScan(ports, false)
}

// ScanHost scant één enkele host grondig. Bedoeld voor de knop in het
// detailpaneel: interessant apparaat gevonden, even goed doorlichten.
func (a *App) ScanHost(ip, portSpec string) error {
	ports, err := probe.Ports(portSpec)
	if err != nil {
		return err
	}
	if !a.claim() {
		return errors.New(i18n.T(a.taal(), "err.scanRunning"))
	}
	defer a.release()

	targets := make([]probe.Target, 0, len(ports))
	for _, p := range ports {
		targets = append(targets, probe.Target{IP: ip, Port: p})
	}
	a.store.Log(model.TagScan, "", "ev.deepScan", "ip", ip, "n", strconv.Itoa(len(ports)))

	var found []model.Port
	probe.ScanPorts(a.ctx, targets, probe.PortScanOptions{}, func(ip string, p model.Port) {
		found = append(found, p)
		a.store.Observe(store.Fact{IP: ip, Ports: []model.Port{p}, Kind: probe.GuessKind(found)})
	})
	a.store.Log(model.TagScan, "", "ev.deepScanDone", "ip", ip, "n", strconv.Itoa(len(found)))
	return nil
}

// StartMonitor zet de doorlopende bewaking aan: eerst een volledige ronde,
// daarna elke 30 seconden een snelle controle wie er nog is. Zo zie je
// apparaten komen en gaan zonder het netwerk te belasten met poortscans.
func (a *App) StartMonitor(portSpec string) error {
	ports, err := probe.Ports(portSpec)
	if err != nil {
		return err
	}

	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return nil
	}
	if a.iface.IP == "" {
		a.mu.Unlock()
		return errors.New(i18n.T(a.taal(), "err.noAdapter"))
	}
	ctx, cancel := context.WithCancel(a.ctx)
	a.cancel, a.running = cancel, true
	a.mu.Unlock()
	a.emitStatus()

	go func() {
		defer func() {
			a.mu.Lock()
			a.running = false
			a.mu.Unlock()
			a.emitStatus()
		}()

		a.store.Log(model.TagScan, "", "ev.monitorStarted", "cidr", a.snapshotIface().CIDR)
		go a.luisterPassief(ctx)
		a.scanWithCtx(ctx, ports, false)

		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				a.store.Log(model.TagScan, "", "ev.monitorStopped")
				return
			case <-t.C:
				// Alleen kijken wie er nog is; poorten scannen we niet
				// elke ronde opnieuw.
				a.scanWithCtx(ctx, nil, true)
				a.store.ExpireOlderThan(95 * time.Second)
			}
		}
	}()
	return nil
}

// luisterPassief start de meeluisteraar naast de actieve rondes.
//
// Mislukt dat — meestal omdat de app niet als administrator draait — dan
// gaat de bewaking gewoon door zonder. Het actieve deel levert al een
// volledige kaart; passief luisteren voegt daar de namen aan toe die
// apparaten ongevraagd rondsturen, en apparaten die nergens op antwoorden.
func (a *App) luisterPassief(ctx context.Context) {
	sn := &capture.Sniffer{Iface: a.snapshotIface(), Store: a.store}

	a.mu.Lock()
	a.passief, a.passiefReden = true, ""
	a.mu.Unlock()
	a.emitStatus()

	err := sn.Run(ctx)

	a.mu.Lock()
	a.passief = false
	if err != nil && ctx.Err() == nil {
		a.passiefReden = err.Error()
	}
	a.mu.Unlock()
	a.emitStatus()

	if err != nil && ctx.Err() == nil {
		a.store.Log(model.TagScan, "", "ev.passiveOff", "err", err.Error())
	}
}

// StopMonitor zet de bewaking uit. De kaart blijft staan zoals hij is.
func (a *App) StopMonitor() {
	a.mu.Lock()
	cancel := a.cancel
	a.cancel = nil
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (a *App) runScan(ports []int, skipPorts bool) error {
	if a.ctx == nil {
		return errors.New(i18n.T(a.taal(), "err.notStarted"))
	}
	return a.scanWithCtx(a.ctx, ports, skipPorts)
}

func (a *App) scanWithCtx(ctx context.Context, ports []int, skipPorts bool) error {
	if !a.claim() {
		return errors.New(i18n.T(a.taal(), "err.scanRunning"))
	}
	defer a.release()

	iface := a.snapshotIface()
	if iface.IP == "" {
		return errors.New(i18n.T(a.taal(), "err.noAdapter"))
	}

	sc := &probe.Scanner{
		Iface:     iface,
		Store:     a.store,
		Ports:     ports,
		SkipPorts: skipPorts || len(ports) == 0,
	}
	return sc.Run(ctx, func(p probe.Progress) {
		runtime.EventsEmit(a.ctx, "scan:progress", p)
	})
}

// claim zorgt dat er nooit twee scans tegelijk lopen; de tweede krijgt
// netjes nul te doen in plaats van het netwerk dubbel te belasten.
func (a *App) claim() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.busy {
		return false
	}
	a.busy = true
	go a.emitStatus()
	return true
}

func (a *App) release() {
	a.mu.Lock()
	a.busy = false
	a.mu.Unlock()
	a.emitStatus()
}

func (a *App) snapshotIface() netif.Adapter {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.iface
}
