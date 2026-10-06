package discover

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SSDPResult is wat een apparaat over zichzelf vertelt via UPnP.
type SSDPResult struct {
	IP           string
	Name         string
	Manufacturer string
	Model        string
	Server       string
}

var ssdpAddr = &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}

// mx is het aantal seconden dat apparaten hun antwoord mogen spreiden.
// Laag houden: hoger betekent alleen langer wachten op de laatste reactie.
const ssdpMX = 2

func msearch(st string) []byte {
	return []byte(strings.Join([]string{
		"M-SEARCH * HTTP/1.1",
		"HOST: 239.255.255.250:1900",
		`MAN: "ssdp:discover"`,
		fmt.Sprintf("MX: %d", ssdpMX),
		"ST: " + st,
		"", "",
	}, "\r\n"))
}

// kopregels leest de HTTP-achtige kopregels uit een SSDP-antwoord.
func kopregels(s string) map[string]string {
	out := map[string]string{}
	for _, regel := range strings.Split(s, "\n") {
		regel = strings.TrimRight(regel, "\r")
		i := strings.IndexByte(regel, ':')
		if i <= 0 {
			continue
		}
		sleutel := strings.ToUpper(strings.TrimSpace(regel[:i]))
		out[sleutel] = strings.TrimSpace(regel[i+1:])
	}
	return out
}

var (
	reFriendly = regexp.MustCompile(`(?is)<friendlyName>\s*(.*?)\s*</friendlyName>`)
	reManu     = regexp.MustCompile(`(?is)<manufacturer>\s*(.*?)\s*</manufacturer>`)
	reModel    = regexp.MustCompile(`(?is)<modelName>\s*(.*?)\s*</modelName>`)
)

// haalBeschrijving haalt de device description op waar LOCATION naar
// wijst. Daar staat de naam die de eigenaar het apparaat gaf, plus
// fabrikant en model — veel rijker dan wat het SSDP-antwoord zelf geeft.
func haalBeschrijving(ctx context.Context, loc string) (naam, fabrikant, model string) {
	u, err := url.Parse(loc)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return
	}
	c, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(c, http.MethodGet, loc, nil)
	if err != nil {
		return
	}
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Een device description is een paar kilobyte; meer lezen we niet, om
	// niet aan een apparaat vast te zitten dat eindeloos blijft sturen.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return
	}
	pak := func(re *regexp.Regexp) string {
		if m := re.FindSubmatch(body); len(m) == 2 {
			return strings.TrimSpace(string(m[1]))
		}
		return ""
	}
	return pak(reFriendly), pak(reManu), pak(reModel)
}

// SSDP zoekt UPnP-apparaten met een M-SEARCH en haalt van elk gevonden
// apparaat de beschrijving op.
//
// Dit vindt vooral tv's, mediaspelers, NAS-apparaten en routers. Ze
// antwoorden meerdere keren (één per dienst die ze aanbieden), dus we
// houden per adres alleen het eerste bruikbare antwoord.
func SSDP(ctx context.Context, ips []string, wacht time.Duration, onResult func(SSDPResult)) error {
	if wacht <= 0 {
		wacht = 4 * time.Second
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return fmt.Errorf("kon geen UDP-socket openen voor SSDP: %w", err)
	}
	defer conn.Close()

	klaar := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.SetReadDeadline(time.Now())
		case <-klaar:
		}
	}()
	defer close(klaar)

	// De multicastvraag als bonus. Op Windows sneuvelt het antwoord
	// meestal in de firewall: wij sturen naar 239.255.255.250, het
	// apparaat antwoordt vanaf z'n eigen adres, en dat telt niet als
	// antwoord op onze vraag.
	for _, st := range []string{"ssdp:all", "upnp:rootdevice"} {
		conn.WriteToUDP(msearch(st), ssdpAddr)
		time.Sleep(80 * time.Millisecond)
	}

	// Daarom ook unicast naar poort 1900 van elke bekende host. UPnP-
	// apparaten horen een gerichte M-SEARCH gewoon te beantwoorden, en
	// dat antwoord komt van het adres waar we naartoe schreven.
	pakket := msearch("ssdp:all")
	for _, ip := range ips {
		doel := &net.UDPAddr{IP: net.ParseIP(ip), Port: 1900}
		if doel.IP == nil {
			continue
		}
		conn.WriteToUDP(pakket, doel)
		time.Sleep(time.Millisecond)
	}

	type vondst struct{ loc, server string }
	gevonden := map[string]vondst{}

	conn.SetReadDeadline(time.Now().Add(wacht))
	buf := make([]byte, 4096)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		ip := from.IP.String()
		if _, al := gevonden[ip]; al {
			continue
		}
		h := kopregels(string(buf[:n]))
		loc := h["LOCATION"]
		if loc == "" {
			continue
		}
		gevonden[ip] = vondst{loc: loc, server: h["SERVER"]}
	}

	// De beschrijvingen parallel ophalen; één traag apparaat mag de rest
	// niet ophouden.
	var wg sync.WaitGroup
	var mu sync.Mutex
	for ip, v := range gevonden {
		wg.Add(1)
		go func(ip string, v vondst) {
			defer wg.Done()
			naam, fabrikant, model := haalBeschrijving(ctx, v.loc)
			if naam == "" && model == "" && fabrikant == "" {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if onResult != nil {
				onResult(SSDPResult{
					IP: ip, Name: naam, Manufacturer: fabrikant,
					Model: model, Server: v.server,
				})
			}
		}(ip, v)
	}
	wg.Wait()
	return nil
}
