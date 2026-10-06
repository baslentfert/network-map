// Package listen brengt in kaart wat er op deze machine naar het netwerk
// luistert, en zegt erover wat het is.
//
// De lijst zelf is geen nieuw idee — TCPView en netstat doen dat al. Het
// verschil zit in de duiding: welke dienst dit is, of hij vanaf het hele
// netwerk bereikbaar is, en of dat hier klopt. Dat laatste is het enige
// dat je als mens echt nodig hebt.
package listen

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// Bereik zegt wie bij deze socket kan. Dit is het bruikbaarste gegeven in
// de hele lijst: hetzelfde proces op 127.0.0.1 of op 0.0.0.0 is het
// verschil tussen privé en open voor iedereen op je netwerk.
type Bereik string

const (
	// BereikLokaal: alleen deze machine zelf (127.0.0.1 of ::1).
	BereikLokaal Bereik = "lokaal"
	// BereikNetwerk: alle interfaces (0.0.0.0 of ::), dus iedereen op je
	// netwerk kan erbij.
	BereikNetwerk Bereik = "netwerk"
	// BereikAdapter: één specifiek adres, bijvoorbeeld alleen de VPN.
	BereikAdapter Bereik = "adapter"
)

// Oordeel is de samenvatting in één woord.
type Oordeel string

const (
	// OordeelNormaal: dit hoort hier, geen actie nodig.
	OordeelNormaal Oordeel = "normaal"
	// OordeelLetOp: werkt zoals bedoeld, maar staat verder open dan de
	// meeste mensen verwachten.
	OordeelLetOp Oordeel = "let op"
	// OordeelOnbekend: we weten niet wat dit is. Geen beschuldiging — een
	// uitnodiging om te kijken.
	OordeelOnbekend Oordeel = "onbekend"
)

// Luisteraar is één open poort op deze machine.
type Luisteraar struct {
	Proto string `json:"proto"`
	IP    string `json:"ip"`
	Port  int    `json:"port"`
	// DualStack is waar als dezelfde dienst zowel op IPv4 als op IPv6
	// luistert. Windows meldt dat als twee regels; dat is technisch juist
	// maar leest als dubbelop, want het is één dienst.
	DualStack bool `json:"dualStack"`

	PID     int32  `json:"pid"`
	Process string `json:"process"`
	Path    string `json:"path"`
	User    string `json:"user"`
	// Sinds is wanneer het proces startte; leeg als we er niet bij konden.
	Sinds time.Time `json:"since"`

	Bereik  Bereik  `json:"scope"`
	Dienst  string  `json:"service"`
	Uitleg  string  `json:"explanation"`
	Oordeel Oordeel `json:"verdict"`
	Waarom  string  `json:"why"`

	// Verbindingen is het aantal actieve verbindingen op deze poort.
	Verbindingen int `json:"connections"`
}

// Adres is het volledige luisteradres. Luistert de dienst op beide
// IP-versies, dan tonen we één regel met een sterretje in plaats van
// 0.0.0.0 en :: apart.
func (l Luisteraar) Adres() string {
	if l.DualStack {
		return fmt.Sprintf("*:%d", l.Port)
	}
	return fmt.Sprintf("%s:%d", l.IP, l.Port)
}

// Verbinding is één actieve verbinding van of naar deze machine.
type Verbinding struct {
	Proto   string `json:"proto"`
	Lokaal  string `json:"local"`
	Extern  string `json:"remote"`
	Status  string `json:"status"`
	PID     int32  `json:"pid"`
	Process string `json:"process"`
}

// Overzicht is het resultaat van één ronde.
type Overzicht struct {
	Luisteraars  []Luisteraar `json:"listeners"`
	Verbindingen []Verbinding `json:"connections"`
	// ZonderNaam telt de processen waar Windows ons niet in liet kijken.
	// Zonder administratorrechten is dat een flink deel, en dat hoort de
	// gebruiker te weten in plaats van lege kolommen te zien.
	ZonderNaam int  `json:"withoutName"`
	Verhoogd   bool `json:"elevated"`
}

// procInfo onthoudt wat we per proces al opzochten. Zonder cache vragen we
// honderden keren hetzelfde op.
type procInfo struct {
	naam, pad, gebruiker string
	start                time.Time
}

// Scan leest de socket-tabel en duidt elke regel.
func Scan(ctx context.Context, taal string) (*Overzicht, error) {
	conns, err := gnet.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		return nil, fmt.Errorf("socket-tabel uitlezen: %w", err)
	}

	cache := map[int32]procInfo{}
	kijk := func(pid int32) procInfo {
		if v, ok := cache[pid]; ok {
			return v
		}
		var p procInfo
		if pr, err := process.NewProcessWithContext(ctx, pid); err == nil {
			if v, err := pr.NameWithContext(ctx); err == nil {
				p.naam = v
			}
			if v, err := pr.ExeWithContext(ctx); err == nil {
				p.pad = v
			}
			if v, err := pr.UsernameWithContext(ctx); err == nil {
				p.gebruiker = v
			}
			if ms, err := pr.CreateTimeWithContext(ctx); err == nil && ms > 0 {
				p.start = time.UnixMilli(ms)
			}
		}
		cache[pid] = p
		return p
	}

	ov := &Overzicht{}

	// Eerst tellen hoeveel verbindingen er per lokale poort lopen, zodat
	// we bij elke luisteraar kunnen tonen of hij daadwerkelijk gebruikt
	// wordt. Een open poort waar niets op binnenkomt is iets anders dan
	// een open poort met twintig sessies.
	drukte := map[string]int{}
	for _, c := range conns {
		if c.Status == "ESTABLISHED" {
			drukte[fmt.Sprintf("%s/%d", proto(c), c.Laddr.Port)]++
		}
	}

	gezien := map[string]int{}
	for _, c := range conns {
		p := proto(c)

		if c.Status == "ESTABLISHED" {
			pi := kijk(c.Pid)
			ov.Verbindingen = append(ov.Verbindingen, Verbinding{
				Proto:   p,
				Lokaal:  fmt.Sprintf("%s:%d", c.Laddr.IP, c.Laddr.Port),
				Extern:  fmt.Sprintf("%s:%d", c.Raddr.IP, c.Raddr.Port),
				Status:  c.Status,
				PID:     c.Pid,
				Process: pi.naam,
			})
			continue
		}

		// UDP kent geen LISTEN-status; een gebonden UDP-socket is net zo
		// goed een open poort als een luisterende TCP-socket.
		if c.Status != "LISTEN" && p != "udp" {
			continue
		}

		// Eén dienst per proto/poort/proces. Windows meldt dezelfde socket
		// los voor IPv4 en IPv6, en soms meermaals; dat samenvoegen halveert
		// de lijst zonder dat er informatie verloren gaat.
		sleutel := fmt.Sprintf("%s/%d/%d", p, c.Laddr.Port, c.Pid)
		if i, al := gezien[sleutel]; al {
			b := bereikVan(c.Laddr.IP)
			if strings.Contains(c.Laddr.IP, ":") != strings.Contains(ov.Luisteraars[i].IP, ":") {
				ov.Luisteraars[i].DualStack = true
			}
			// Het ruimste bereik telt: luistert iets op zowel 127.0.0.1 als
			// 0.0.0.0, dan is het bereikbaar vanaf het netwerk.
			if b == BereikNetwerk {
				ov.Luisteraars[i].Bereik = b
				duid(&ov.Luisteraars[i], taal)
			}
			continue
		}
		gezien[sleutel] = len(ov.Luisteraars)

		pi := kijk(c.Pid)
		if pi.naam == "" {
			ov.ZonderNaam++
		}

		l := Luisteraar{
			Proto:        p,
			IP:           c.Laddr.IP,
			Port:         int(c.Laddr.Port),
			PID:          c.Pid,
			Process:      pi.naam,
			Path:         pi.pad,
			User:         pi.gebruiker,
			Sinds:        pi.start,
			Bereik:       bereikVan(c.Laddr.IP),
			Verbindingen: drukte[fmt.Sprintf("%s/%d", p, c.Laddr.Port)],
		}
		duid(&l, taal)
		ov.Luisteraars = append(ov.Luisteraars, l)
	}

	// Lezen we van minstens één systeemproces het pad, dan draaien we
	// verhoogd. Dat is betrouwbaarder dan een rechtenvlag opvragen.
	ov.Verhoogd = ov.ZonderNaam == 0 && len(ov.Luisteraars) > 0

	sorteer(ov.Luisteraars)
	return ov, nil
}

// sorteer zet wat aandacht vraagt bovenaan: eerst het oordeel, dan het
// bereik, dan de poort. Zo hoef je niet te zoeken naar het interessante.
func sorteer(ls []Luisteraar) {
	rang := map[Oordeel]int{OordeelLetOp: 0, OordeelOnbekend: 1, OordeelNormaal: 2}
	bres := map[Bereik]int{BereikNetwerk: 0, BereikAdapter: 1, BereikLokaal: 2}
	sort.SliceStable(ls, func(a, b int) bool {
		if r := rang[ls[a].Oordeel] - rang[ls[b].Oordeel]; r != 0 {
			return r < 0
		}
		if r := bres[ls[a].Bereik] - bres[ls[b].Bereik]; r != 0 {
			return r < 0
		}
		return ls[a].Port < ls[b].Port
	})
}

func proto(c gnet.ConnectionStat) string {
	if c.Type == 2 {
		return "udp"
	}
	return "tcp"
}

func bereikVan(ip string) Bereik {
	switch {
	case ip == "0.0.0.0" || ip == "::" || ip == "":
		return BereikNetwerk
	case ip == "127.0.0.1" || ip == "::1" || strings.HasPrefix(ip, "127."):
		return BereikLokaal
	default:
		return BereikAdapter
	}
}
