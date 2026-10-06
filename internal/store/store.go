// Package store houdt de enige waarheid over het netwerk bij.
//
// Elke bron — passieve capture, actieve probes, DNS-proxy — schrijft
// Facts. De store voegt ze samen, ziet zelf wat er veranderde en stuurt
// alleen die verandering naar de frontend. Bronnen weten dus niets van
// elkaar en niets van de UI.
package store

import (
	"sort"
	"sync"
	"time"

	"netwerksniffer/internal/model"
	"netwerksniffer/internal/oui"
)

// Fact is wat één bron op één moment over één host te weten kwam.
// Lege velden betekenen "geen informatie", niet "leegmaken".
type Fact struct {
	IP     string
	MAC    string
	Name   string
	Origin string
	Model  string

	Ports  []model.Port
	TTL    int
	Rx, Tx uint64

	Kind    model.Kind
	Gateway bool
	Self    bool
}

// originRank bepaalt welke naam wint als meerdere bronnen er een leveren.
// Hoger is sterker. De eigen alias staat bewust bovenaan: die is expliciet
// door een mens gekozen en verslaat elke automatische vondst.
var originRank = map[string]int{
	model.OriginAlias:    100,
	model.OriginDHCP:     60,
	model.OriginMDNS:     50,
	model.OriginMDNSHost: 45,
	model.OriginNetBIOS:  40,
	model.OriginSSDP:     30,
	model.OriginWSD:      25,
	model.OriginRDNS:     10,
	model.OriginARP:      0,
}

// Store is veilig voor gelijktijdig gebruik door alle bronnen.
type Store struct {
	mu    sync.RWMutex
	byKey map[string]*model.Host
	byIP  map[string]string // IP -> Key, om hosts zonder MAC terug te vinden
	alias map[string]string // MAC -> door de gebruiker gekozen naam

	// arpOwner onthoudt welk MAC een IP claimde, zodat een tweede claimant
	// als mogelijke ARP-spoofing opvalt.
	arpOwner map[string]string

	log     []model.Event
	maxLog  int
	emit    func(event string, data any)
	subnet  string
	gateway string
}

// New maakt een lege store. emit mag nil zijn (handig in tests); anders
// is het runtime.EventsEmit van Wails.
func New(emit func(event string, data any)) *Store {
	if emit == nil {
		emit = func(string, any) {}
	}
	return &Store{
		byKey:    map[string]*model.Host{},
		byIP:     map[string]string{},
		alias:    map[string]string{},
		arpOwner: map[string]string{},
		maxLog:   500,
		emit:     emit,
	}
}

// SetSubnet legt vast welk broadcast-domein de kaart toont.
func (s *Store) SetSubnet(cidr, gatewayIP string) {
	s.mu.Lock()
	s.subnet, s.gateway = cidr, gatewayIP
	s.mu.Unlock()
}

// Observe voegt één waarneming samen met wat we al wisten.
func (s *Store) Observe(f Fact) {
	if f.IP == "" && f.MAC == "" {
		return
	}
	f.MAC = oui.Normalize(f.MAC)

	s.mu.Lock()
	now := time.Now()

	var dropped string
	key := f.MAC
	if key == "" {
		if k, ok := s.byIP[f.IP]; ok {
			key = k
		} else {
			key = f.IP
		}
	} else if f.IP != "" {
		if old, ok := s.byIP[f.IP]; ok && old != key {
			prev, bestaat := s.byKey[old]
			switch {
			case bestaat && prev.MAC == "":
				// De host was alleen op z'n IP bekend — de ping-sweep vindt
				// hosts vóórdat de ARP-cache het MAC prijsgeeft. Nu we het
				// MAC kennen verhuist alles wat we wisten mee naar de
				// stabiele sleutel. Zonder dit staat elke host dubbel.
				dropped = s.rekeyLocked(old, key)
			case bestaat:
				// Twee verschillende MAC-adressen op hetzelfde IP. Dat is
				// géén samenvoeging maar een verhuizing: het adres is aan
				// een ander apparaat toegekend. Beide hosts houden hun
				// eigen identiteit; alleen de IP-verwijzing gaat over.
				// (Ze zonder meer samenvoegen liet eerder twee apparaten
				// in elkaar opgaan en één van beide z'n MAC verliezen.)
				delete(s.byIP, f.IP)
			}
		}
	}

	h, existed := s.byKey[key]
	if !existed {
		h = &model.Host{
			Key:       key,
			FirstSeen: now,
			Status:    model.StatusNew,
			Kind:      model.KindUnknown,
		}
		s.byKey[key] = h
	}

	var events []model.Event
	changed := !existed

	// Een host die van IP wisselt houdt z'n identiteit, want we sleutelen
	// op MAC. Dat is het vermelden waard in het logboek.
	if f.IP != "" && h.IP != f.IP {
		if h.IP != "" {
			events = append(events, model.Event{
				At: now, Tag: model.TagDHCP, Host: key, Key: "ev.newAddress",
				Args: map[string]string{"name": s.labelLocked(h), "ip": f.IP, "old": h.IP},
			})
			delete(s.byIP, h.IP)
		}
		h.IP = f.IP
		s.byIP[f.IP] = key
		changed = true
	}

	if f.MAC != "" && h.MAC != f.MAC {
		h.MAC = f.MAC
		h.RandomMAC = oui.IsRandom(f.MAC)
		// Geen tekst invullen als de fabrikant onbekend is: "onbekend" is
		// een label, geen gegeven, en de frontend kiest de woorden.
		h.Vendor = oui.Lookup(f.MAC)
		changed = true
	}

	// Twee MAC-adressen die hetzelfde IP claimen is óf een IP-conflict óf
	// ARP-spoofing. We kiezen geen kant; we melden het.
	if f.IP != "" && f.MAC != "" && f.Origin == model.OriginARP {
		if prev, ok := s.arpOwner[f.IP]; ok && prev != f.MAC {
			h.Status = model.StatusAlert
			h.NoteKey = "note.arpConflict"
			h.NoteArgs = map[string]string{"ip": f.IP, "prev": prev}
			events = append(events, model.Event{
				At: now, Tag: model.TagAlert, Host: key, Key: "ev.arpConflict",
				Args: map[string]string{"mac": f.MAC, "ip": f.IP, "prev": prev},
			})
			changed = true
		}
		s.arpOwner[f.IP] = f.MAC
	}

	if f.Name != "" && f.Origin != "" {
		if s.addNameLocked(h, f.Name, f.Origin) {
			changed = true
		}
	}
	if f.Model != "" && h.Model != f.Model {
		h.Model = f.Model
		changed = true
	}
	if len(f.Ports) > 0 && s.addPortsLocked(h, f.Ports) {
		changed = true
	}
	if f.TTL > 0 && h.TTL != f.TTL {
		h.TTL, h.OSHint = f.TTL, osFromTTL(f.TTL)
		changed = true
	}
	if f.Kind != "" && f.Kind != model.KindUnknown && h.Kind != f.Kind {
		h.Kind = f.Kind
		changed = true
	}
	if f.Gateway && !h.IsGateway {
		h.IsGateway, h.Kind = true, model.KindRouter
		changed = true
	}
	if f.Self && !h.IsSelf {
		h.IsSelf = true
		changed = true
	}
	h.RxBytes += f.Rx
	h.TxBytes += f.Tx

	// Terug van weggeweest telt als gebeurtenis.
	if h.Status == model.StatusOffline {
		h.Status = model.StatusOnline
		events = append(events, model.Event{
			At: now, Tag: model.TagNew, Host: key, Key: "ev.backOnline",
			Args: map[string]string{"name": s.labelLocked(h)},
		})
		changed = true
	}
	h.LastSeen = now

	if !existed {
		events = append(events, model.Event{
			At: now, Tag: model.TagNew, Host: key, Key: "ev.newDevice",
			Args: map[string]string{"name": s.labelLocked(h)},
		})
	}

	snap := s.snapshotLocked(h)
	s.appendLogLocked(events)
	s.mu.Unlock()

	if dropped != "" {
		s.emit("host:remove", dropped)
	}
	if changed {
		name := "host:update"
		if !existed {
			name = "host:new"
		}
		s.emit(name, snap)
	}
	for _, e := range events {
		s.emit("log", e)
	}
}

// rekeyLocked verhuist een host die op z'n IP bekend stond naar de
// MAC-sleutel. Bestond die sleutel al, dan smelten beide samen. Geeft de
// sleutel terug die daarmee verdween, zodat de UI die node kan opruimen.
func (s *Store) rekeyLocked(old, key string) string {
	prev, ok := s.byKey[old]
	if !ok {
		return ""
	}
	delete(s.byKey, old)

	if cur, exists := s.byKey[key]; exists {
		s.mergeLocked(cur, prev)
	} else {
		prev.Key = key
		s.byKey[key] = prev
	}
	if prev.IP != "" {
		s.byIP[prev.IP] = key
	}
	return old
}

// mergeLocked vult dst aan met wat src wist. dst wint bij elk conflict:
// die heeft een MAC-adres en is dus de betrouwbaardere identiteit.
func (s *Store) mergeLocked(dst, src *model.Host) {
	if dst.TTL == 0 && src.TTL != 0 {
		dst.TTL, dst.OSHint = src.TTL, src.OSHint
	}
	if dst.Kind == model.KindUnknown {
		dst.Kind = src.Kind
	}
	if src.IsGateway {
		dst.IsGateway, dst.Kind = true, model.KindRouter
	}
	if src.IsSelf {
		dst.IsSelf = true
	}
	if src.Status == model.StatusAlert {
		dst.Status = model.StatusAlert
	}
	if dst.NoteKey == "" {
		dst.NoteKey, dst.NoteArgs = src.NoteKey, src.NoteArgs
	}
	if dst.Model == "" {
		dst.Model = src.Model
	}
	if !src.FirstSeen.IsZero() && (dst.FirstSeen.IsZero() || src.FirstSeen.Before(dst.FirstSeen)) {
		dst.FirstSeen = src.FirstSeen
	}
	if src.LastSeen.After(dst.LastSeen) {
		dst.LastSeen = src.LastSeen
	}
	dst.RxBytes += src.RxBytes
	dst.TxBytes += src.TxBytes

	for _, n := range src.Names {
		s.addNameLocked(dst, n.Value, n.Origin)
	}
	s.addPortsLocked(dst, src.Ports)
}

// addNameLocked bewaart een naam met z'n herkomst en herberekent welke wint.
func (s *Store) addNameLocked(h *model.Host, name, origin string) bool {
	for i, n := range h.Names {
		if n.Origin == origin {
			if n.Value == name {
				return false
			}
			h.Names[i].Value = name
			s.recomputeNameLocked(h)
			return true
		}
	}
	h.Names = append(h.Names, model.NameSource{Value: name, Origin: origin})
	s.recomputeNameLocked(h)
	return true
}

// recomputeNameLocked sorteert de herkomstlijst sterkste bron eerst en zet
// de winnaar als weergavenaam.
func (s *Store) recomputeNameLocked(h *model.Host) {
	sort.SliceStable(h.Names, func(i, j int) bool {
		return originRank[h.Names[i].Origin] > originRank[h.Names[j].Origin]
	})
	if len(h.Names) > 0 {
		h.Name = h.Names[0].Value
	} else {
		h.Name = ""
	}
}

func (s *Store) addPortsLocked(h *model.Host, ports []model.Port) bool {
	seen := map[int]bool{}
	for _, p := range h.Ports {
		seen[p.Number] = true
	}
	changed := false
	for _, p := range ports {
		if !seen[p.Number] {
			h.Ports = append(h.Ports, p)
			changed = true
		}
	}
	if changed {
		sort.Slice(h.Ports, func(i, j int) bool { return h.Ports[i].Number < h.Ports[j].Number })
	}
	return changed
}

// labelLocked geeft de beste menselijke aanduiding die we nu hebben.
func (s *Store) labelLocked(h *model.Host) string {
	if h.Name != "" {
		return h.Name
	}
	if h.IP != "" {
		return h.IP
	}
	return h.MAC
}

// SetAlias legt een door de gebruiker gekozen naam vast. De sleutel is het
// MAC-adres, zodat de naam een nieuw IP overleeft.
func (s *Store) SetAlias(key, name string) {
	s.mu.Lock()
	h, ok := s.byKey[key]
	if !ok {
		s.mu.Unlock()
		return
	}
	if name == "" {
		delete(s.alias, key)
		for i, n := range h.Names {
			if n.Origin == model.OriginAlias {
				h.Names = append(h.Names[:i], h.Names[i+1:]...)
				break
			}
		}
		s.recomputeNameLocked(h)
	} else {
		s.alias[key] = name
		s.addNameLocked(h, name, model.OriginAlias)
	}
	snap := s.snapshotLocked(h)
	s.mu.Unlock()
	s.emit("host:update", snap)
}

// Aliases geeft de opgeslagen namen terug, om ze te bewaren tussen sessies.
func (s *Store) Aliases() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.alias))
	for k, v := range s.alias {
		out[k] = v
	}
	return out
}

// LoadAliases zet bewaarde namen terug bij het opstarten.
func (s *Store) LoadAliases(m map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range m {
		s.alias[k] = v
		if h, ok := s.byKey[k]; ok {
			s.addNameLocked(h, v, model.OriginAlias)
		}
	}
}

// ExpireOlderThan zet hosts die te lang stil zijn op offline. Wordt door
// de sweep-lus aangeroepen; hosts verdwijnen nooit uit de kaart, ze doven.
func (s *Store) ExpireOlderThan(d time.Duration) {
	s.mu.Lock()
	now := time.Now()
	var gone []model.Event
	var snaps []model.Host
	for _, h := range s.byKey {
		if h.Status == model.StatusOffline || h.IsSelf {
			continue
		}
		if now.Sub(h.LastSeen) > d {
			h.Status = model.StatusOffline
			gone = append(gone, model.Event{
				At: now, Tag: model.TagGone, Host: h.Key, Key: "ev.gone",
				Args: map[string]string{"name": s.labelLocked(h)},
			})
			snaps = append(snaps, s.snapshotLocked(h))
		}
	}
	s.appendLogLocked(gone)
	s.mu.Unlock()

	for _, h := range snaps {
		s.emit("host:update", h)
	}
	for _, e := range gone {
		s.emit("log", e)
	}
}

// Log schrijft een regel die niet uit een Fact volgt (scanvoortgang,
// DNS-waarnemingen, foutmeldingen).
//
// args komt in paren: naam, waarde. De zin wordt pas op het scherm
// gemaakt, in de taal die daar gekozen is.
func (s *Store) Log(tag, hostKey, key string, args ...string) {
	e := model.Event{At: time.Now(), Tag: tag, Host: hostKey, Key: key, Args: paar(args)}
	s.mu.Lock()
	s.appendLogLocked([]model.Event{e})
	s.mu.Unlock()
	s.emit("log", e)
}

// paar maakt van een vlakke lijst naam/waarde-paren een map. Een oneven
// laatste element valt weg: dat is een programmeerfout, geen data.
func paar(args []string) map[string]string {
	if len(args) < 2 {
		return nil
	}
	m := make(map[string]string, len(args)/2)
	for i := 0; i+1 < len(args); i += 2 {
		m[args[i]] = args[i+1]
	}
	return m
}

func (s *Store) appendLogLocked(evs []model.Event) {
	s.log = append(s.log, evs...)
	if len(s.log) > s.maxLog {
		s.log = s.log[len(s.log)-s.maxLog:]
	}
}

// snapshotLocked maakt een kopie zodat de frontend nooit naar geheugen
// kijkt dat een bron nog aan het wijzigen is.
func (s *Store) snapshotLocked(h *model.Host) model.Host {
	c := *h
	c.Names = append([]model.NameSource(nil), h.Names...)
	c.Ports = append([]model.Port(nil), h.Ports...)
	if a, ok := s.alias[h.Key]; ok {
		c.Name = a
	}
	return c
}

// Graph geeft de hele kaart: alle hosts plus de verbindingen die we
// kunnen onderbouwen. Domme switches staan er niet in — die zijn
// onzichtbaar en worden dus niet verzonnen.
func (s *Store) Graph() model.Graph {
	s.mu.RLock()
	defer s.mu.RUnlock()

	g := model.Graph{Subnet: s.subnet}
	var gwKey string
	for k, h := range s.byKey {
		if h.IsGateway {
			gwKey = k
		}
		g.Hosts = append(g.Hosts, s.snapshotLocked(h))
	}
	sort.Slice(g.Hosts, func(i, j int) bool { return g.Hosts[i].IP < g.Hosts[j].IP })

	if gwKey != "" {
		for _, h := range g.Hosts {
			if h.Key != gwKey {
				g.Links = append(g.Links, model.Link{From: gwKey, To: h.Key, Kind: "subnet"})
			}
		}
	}
	return g
}

// Events geeft het logboek, oudste eerst.
func (s *Store) Events() []model.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]model.Event(nil), s.log...)
}

// osFromTTL raadt het besturingssysteem uit de resterende TTL. Ruw maar
// verrassend betrouwbaar: de meeste stacks starten op 64, 128 of 255.
// Geeft een tekstsleutel terug, niet een naam.
func osFromTTL(ttl int) string {
	switch {
	case ttl > 128:
		return "os.network"
	case ttl > 64:
		return "os.windows"
	case ttl > 32:
		return "os.linux"
	default:
		return ""
	}
}
