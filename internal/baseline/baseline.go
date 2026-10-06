// Package baseline onthoudt hoe jouw netwerk er normaal uitziet, en meldt
// wat daarvan afwijkt.
//
// Geen model, geen drempelwaarden die je moet afstellen: tellen en
// vergelijken. Op twintig apparaten verslaat dat elk lerend systeem, en
// het heeft een eigenschap die geen enkel model heeft — je kunt altijd
// precies navertellen waaróm iets gemeld is.
//
// De eerste ronde meldt niets. Alles wat er dan staat ís de norm; pas wat
// daarna verschijnt is nieuws.
package baseline

import (
	"sort"
	"strings"
	"time"

	"netwerksniffer/internal/model"
)

// Apparaat is wat we als normaal beschouwen voor één apparaat.
type Apparaat struct {
	Key    string `json:"key"`
	MAC    string `json:"mac"`
	Naam   string `json:"name"`
	Vendor string `json:"vendor"`
	// Poorten die we eerder open zagen.
	Poorten []int `json:"ports"`
	// Domeinen die dit apparaat eerder opvroeg, met hoe vaak.
	Domeinen map[string]int `json:"domains,omitempty"`
	Eerst    time.Time      `json:"first"`
	Laatst   time.Time      `json:"last"`
}

// Basislijn is het geheel, zoals het op schijf staat.
type Basislijn struct {
	Gemaakt    time.Time            `json:"created"`
	Bijgewerkt time.Time            `json:"updated"`
	Apparaten  map[string]*Apparaat `json:"devices"`
}

func Nieuw() *Basislijn {
	return &Basislijn{Gemaakt: time.Now(), Apparaten: map[string]*Apparaat{}}
}

// Leeg zegt of er nog niets geleerd is. Dan is de eerste ronde de norm.
func (b *Basislijn) Leeg() bool { return b == nil || len(b.Apparaten) == 0 }

// Ernst bepaalt of iets opvalt of alleen vermeld wordt.
type Ernst string

const (
	ErnstLetOp Ernst = "let op"
	ErnstInfo  Ernst = "info"
)

// Bevinding is één afwijking van de basislijn.
//
// Net als bij de logregels staat er een tekstsleutel in en geen zin, zodat
// het meebeweegt met de taalkeuze.
type Bevinding struct {
	Soort string            `json:"kind"`
	Key   string            `json:"key"`
	Args  map[string]string `json:"args"`
	Host  string            `json:"host"`
	Ernst Ernst             `json:"severity"`
	At    time.Time         `json:"at"`
}

// Waarneming is de huidige stand van zaken, zoals de scanner en de
// DNS-doorgever hem zien.
type Waarneming struct {
	Hosts []model.Host
	// Domeinen per IP-adres van het apparaat.
	Domeinen map[string][]string
}

// VerdwenenNa is hoe lang een apparaat weg moet zijn voordat we het
// vermelden. Korter dan dit en je krijgt elke avond een melding over een
// telefoon die naar bed ging.
const VerdwenenNa = 7 * 24 * time.Hour

// Vergelijk zet de huidige waarneming naast de basislijn.
func Vergelijk(w Waarneming, b *Basislijn) []Bevinding {
	nu := time.Now()
	if b.Leeg() {
		// Niets te vergelijken: de eerste ronde is per definitie normaal.
		return nil
	}

	var uit []Bevinding
	gezien := map[string]bool{}

	for _, h := range w.Hosts {
		gezien[h.Key] = true
		naam := label(h)
		oud, bekend := b.Apparaten[h.Key]

		if !bekend {
			uit = append(uit, Bevinding{
				Soort: "nieuw-apparaat", Key: "bev.newDevice", Host: h.Key,
				Args:  map[string]string{"name": naam, "ip": h.IP, "mac": h.MAC, "vendor": h.Vendor},
				Ernst: ErnstLetOp, At: nu,
			})
			continue
		}

		// Een apparaat dat op hetzelfde MAC opeens anders heet is op zich
		// onschuldig (iemand hernoemde z'n laptop), maar het is ook hoe
		// een nagemaakt apparaat eruitziet. Daarom vermelden, niet alarmeren.
		if oud.Naam != "" && naam != "" && !strings.EqualFold(oud.Naam, naam) {
			uit = append(uit, Bevinding{
				Soort: "naam-gewijzigd", Key: "bev.nameChanged", Host: h.Key,
				Args:  map[string]string{"old": oud.Naam, "new": naam, "mac": h.MAC},
				Ernst: ErnstInfo, At: nu,
			})
		}

		for _, p := range h.Ports {
			if !bevatInt(oud.Poorten, p.Number) {
				uit = append(uit, Bevinding{
					Soort: "nieuwe-poort", Key: "bev.newPort", Host: h.Key,
					Args: map[string]string{
						"name": naam, "port": itoa(p.Number), "service": p.Service,
					},
					Ernst: ErnstLetOp, At: nu,
				})
			}
		}

		for _, d := range w.Domeinen[h.IP] {
			if oud.Domeinen == nil || oud.Domeinen[strings.ToLower(d)] == 0 {
				uit = append(uit, Bevinding{
					Soort: "nieuw-domein", Key: "bev.newDomain", Host: h.Key,
					Args:  map[string]string{"name": naam, "domain": d},
					Ernst: ErnstInfo, At: nu,
				})
			}
		}
	}

	// Apparaten die lang weg zijn. Niet alarmerend, wel goed om te weten:
	// meestal is het iets dat je hebt weggedaan en nog in de lijst staat.
	for key, a := range b.Apparaten {
		if gezien[key] || a.Laatst.IsZero() {
			continue
		}
		if nu.Sub(a.Laatst) > VerdwenenNa {
			uit = append(uit, Bevinding{
				Soort: "verdwenen", Key: "bev.gone", Host: key,
				Args: map[string]string{
					"name": vanNaam(a), "days": itoa(int(nu.Sub(a.Laatst).Hours() / 24)),
				},
				Ernst: ErnstInfo, At: nu,
			})
		}
	}

	sort.SliceStable(uit, func(i, j int) bool {
		if (uit[i].Ernst == ErnstLetOp) != (uit[j].Ernst == ErnstLetOp) {
			return uit[i].Ernst == ErnstLetOp
		}
		return uit[i].Soort < uit[j].Soort
	})
	return uit
}

// Leer neemt de huidige waarneming op in de basislijn. Daarna is dit het
// nieuwe normaal en meldt het niet opnieuw.
func (b *Basislijn) Leer(w Waarneming) {
	nu := time.Now()
	if b.Apparaten == nil {
		b.Apparaten = map[string]*Apparaat{}
	}

	for _, h := range w.Hosts {
		a := b.Apparaten[h.Key]
		if a == nil {
			a = &Apparaat{Key: h.Key, Eerst: nu, Domeinen: map[string]int{}}
			b.Apparaten[h.Key] = a
		}
		a.MAC = h.MAC
		if n := label(h); n != "" {
			a.Naam = n
		}
		if h.Vendor != "" {
			a.Vendor = h.Vendor
		}
		for _, p := range h.Ports {
			if !bevatInt(a.Poorten, p.Number) {
				a.Poorten = append(a.Poorten, p.Number)
			}
		}
		sort.Ints(a.Poorten)

		if a.Domeinen == nil {
			a.Domeinen = map[string]int{}
		}
		for _, d := range w.Domeinen[h.IP] {
			a.Domeinen[strings.ToLower(d)]++
		}
		a.Laatst = nu
	}
	b.Bijgewerkt = nu
	if b.Gemaakt.IsZero() {
		b.Gemaakt = nu
	}
}

// Vergeet haalt één apparaat uit de basislijn, bijvoorbeeld iets dat je
// hebt weggedaan.
func (b *Basislijn) Vergeet(key string) {
	delete(b.Apparaten, key)
	b.Bijgewerkt = time.Now()
}

func label(h model.Host) string {
	if h.Name != "" {
		return h.Name
	}
	if h.Model != "" {
		return h.Model
	}
	return h.IP
}

func vanNaam(a *Apparaat) string {
	if a.Naam != "" {
		return a.Naam
	}
	return a.MAC
}

func bevatInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
