// Package oui zet een MAC-adres om in een fabrikantnaam.
//
// De IEEE deelt adresruimte in drie maten uit: MA-L (24 bits, de klassieke
// OUI), MA-M (28 bits) en MA-S (36 bits). Grote blokken die verder zijn
// opgedeeld staan in de MA-L-lijst op naam van de IEEE zelf — daar heb je
// niets aan. We zoeken daarom van lang naar kort: eerst 36 bits, dan 28,
// dan 24. Zonder die volgorde krijgt bijvoorbeeld 98:fc:84:… "IEEE
// Registration Authority" als fabrikant in plaats van de echte eigenaar.
package oui

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"strings"
	"sync"
)

//go:embed oui.tsv.gz
var raw []byte

var (
	once           sync.Once
	tier9          map[string]string // MA-S, 36 bits
	tier7          map[string]string // MA-M, 28 bits
	tier6          map[string]string // MA-L, 24 bits
	hexDigits      = "0123456789ABCDEF"
	legalSuffixes  = []string{
		", INC.", ", INC", " INC.", " INC", " INCORPORATED",
		", LTD.", ", LTD", " LTD.", " LTD", " LIMITED",
		"CO.,LTD.", "CO., LTD.", "CO.,LTD", " CO., LTD", " CO. LTD", " CO.,",
		" CORPORATION", " CORPORATE", " CORP.", " CORP",
		" GMBH", " LLC", " L.L.C.", " B.V.", " BV", " S.A.", " S.A", " A/S",
		" PTY", " PLC", " AG", " SAS", " SRL", " OY", " AB",
		" TECHNOLOGY CO.", " COMPANY LIMITED", " CO", " COMPANY",
	}
)

// placeholder herkent registratienamen die geen echte fabrikant zijn.
func placeholder(v string) bool {
	u := strings.ToUpper(v)
	return strings.Contains(u, "IEEE REGISTRATION AUTHORITY") || u == "PRIVATE"
}

func load() {
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return
	}
	defer zr.Close()

	tier9 = make(map[string]string, 7200)
	tier7 = make(map[string]string, 6600)
	tier6 = make(map[string]string, 40100)

	cur := tier6
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		// Kopregels schakelen tussen de drie tiers.
		if line[0] == '#' {
			switch line {
			case "#9":
				cur = tier9
			case "#7":
				cur = tier7
			case "#6":
				cur = tier6
			}
			continue
		}
		tab := strings.IndexByte(line, '\t')
		if tab <= 0 {
			continue
		}
		cur[line[:tab]] = line[tab+1:]
	}
}

// hexOnly haalt de scheidingstekens weg en maakt er hoofdletters van.
func hexOnly(mac string) string {
	var b strings.Builder
	b.Grow(12)
	for i := 0; i < len(mac); i++ {
		c := mac[i]
		switch {
		case c >= '0' && c <= '9', c >= 'A' && c <= 'F':
			b.WriteByte(c)
		case c >= 'a' && c <= 'f':
			b.WriteByte(c - 32)
		}
	}
	return b.String()
}

// Lookup geeft de fabrikant, of een lege string als die niet te bepalen is.
// Een leeg antwoord is een geldig antwoord: bij een geroteerd MAC-adres
// bestaat er domweg geen fabrikant om te vinden.
func Lookup(mac string) string {
	h := hexOnly(mac)
	if len(h) < 6 {
		return ""
	}
	if IsRandom(mac) {
		return ""
	}
	once.Do(load)

	if len(h) >= 9 {
		if v, ok := tier9[h[:9]]; ok && !placeholder(v) {
			return tidy(v)
		}
	}
	if len(h) >= 7 {
		if v, ok := tier7[h[:7]]; ok && !placeholder(v) {
			return tidy(v)
		}
	}
	if v, ok := tier6[h[:6]]; ok && !placeholder(v) {
		return tidy(v)
	}
	return ""
}

// tidy haalt de juridische staart eraf: "Synology Incorporated" wordt
// "Synology". De schrijfwijze laten we verder met rust — die zelf
// mooier maken gaat vaker mis dan goed ("IEEE" wordt dan "Ieee").
func tidy(v string) string {
	v = strings.TrimSpace(v)
	// Herhalen tot er niets meer af gaat: "… Co., LTD" heeft twee
	// staarten, en na het strippen van de ene komt de andere pas vrij.
	for round := 0; round < 4; round++ {
		before := v
		upper := strings.ToUpper(v)
		for _, suf := range legalSuffixes {
			if strings.HasSuffix(upper, suf) && len(v) > len(suf) {
				v = strings.TrimRight(strings.TrimSpace(v[:len(v)-len(suf)]), " ,.")
				upper = strings.ToUpper(v)
			}
		}
		if v == before {
			break
		}
	}
	return v
}

// IsRandom zegt of het locally-administered bit gezet is. Telefoons
// roteren hun MAC per netwerk om je niet te laten volgen; het tweede bit
// van het eerste octet verraadt dat. Zulke adressen staan in geen enkele
// IEEE-lijst, en dat is opzet — niet een gat in onze database.
func IsRandom(mac string) bool {
	h := hexOnly(mac)
	if len(h) < 2 {
		return false
	}
	first := hexVal(h[0])<<4 | hexVal(h[1])
	return first&0x02 != 0
}

// IsMulticast herkent groepsadressen (broadcast, mDNS, SSDP). Die horen
// niet als apparaat op de kaart.
func IsMulticast(mac string) bool {
	h := hexOnly(mac)
	if len(h) < 2 {
		return false
	}
	first := hexVal(h[0])<<4 | hexVal(h[1])
	return first&0x01 != 0
}

func hexVal(c byte) int {
	return strings.IndexByte(hexDigits, c)
}

// Normalize brengt een MAC in de vorm aa:bb:cc:dd:ee:ff. Bronnen leveren
// het in alle smaken aan (Windows met streepjes, pcap met dubbele punten),
// en de store sleutelt erop — dus één vorm.
func Normalize(mac string) string {
	h := hexOnly(mac)
	if len(h) != 12 {
		return ""
	}
	var b strings.Builder
	b.Grow(17)
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteByte(lower(h[i]))
		b.WriteByte(lower(h[i+1]))
	}
	return b.String()
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'F' {
		return c + 32
	}
	return c
}
