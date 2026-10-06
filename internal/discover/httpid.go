package discover

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// HTTPResult is wat een apparaat over zichzelf vertelt via z'n webinterface.
type HTTPResult struct {
	IP   string
	Name string
	// Model is de productaanduiding. Voor veel IoT-apparaten is dat het
	// enige dat er is: een P1-meter heet gewoon "P1 Meter", er is geen
	// individuele naam om te vinden.
	Model string
}

// eindpunt is één bekend adres waarop een apparaatsoort zichzelf bekendmaakt.
type eindpunt struct {
	pad string
	// lees haalt naam en model uit het antwoord. Geeft lege strings terug
	// als dit niet het verwachte apparaat is.
	lees func(body []byte) (naam, model string)
}

// Bekende lokale API's. Klein gehouden en alleen gevuld met dingen die we
// echt hebben gezien of die goed gedocumenteerd zijn — een gokkende
// fingerprint die het verkeerde apparaat aanwijst is erger dan geen naam.
var httpEindpunten = []eindpunt{
	// HomeWizard energiemeters en stekkers.
	{"/api", func(b []byte) (string, string) {
		var v struct {
			ProductName string `json:"product_name"`
			ProductType string `json:"product_type"`
		}
		if json.Unmarshal(b, &v) != nil || v.ProductName == "" {
			return "", ""
		}
		return "", strings.TrimSpace(v.ProductName)
	}},
	// Shelly-schakelaars: /shelly is bewust onbeveiligd en geeft type en naam.
	{"/shelly", func(b []byte) (string, string) {
		var v struct {
			Type  string `json:"type"`
			Model string `json:"model"`
			Name  string `json:"name"`
			App   string `json:"app"`
		}
		if json.Unmarshal(b, &v) != nil {
			return "", ""
		}
		model := firstNonEmpty(v.Model, v.Type, v.App)
		if model == "" {
			return "", ""
		}
		return strings.TrimSpace(v.Name), "Shelly " + strings.TrimSpace(model)
	}},
	// Philips Hue-bridge.
	{"/api/config", func(b []byte) (string, string) {
		var v struct {
			Name      string `json:"name"`
			ModelID   string `json:"modelid"`
			BridgeID  string `json:"bridgeid"`
			SWVersion string `json:"swversion"`
		}
		if json.Unmarshal(b, &v) != nil || v.BridgeID == "" {
			return "", ""
		}
		return strings.TrimSpace(v.Name), "Philips Hue " + strings.TrimSpace(v.ModelID)
	}},
	// Plex-mediaserver.
	{"/identity", func(b []byte) (string, string) {
		if !strings.Contains(string(b), "MediaContainer") {
			return "", ""
		}
		return "", "Plex Media Server"
	}},
	// Tasmota-firmware op ESP-apparaten.
	{"/cm?cmnd=Status", func(b []byte) (string, string) {
		var v struct {
			Status struct {
				DeviceName  string `json:"DeviceName"`
				FriendlyName any    `json:"FriendlyName"`
			} `json:"Status"`
		}
		if json.Unmarshal(b, &v) != nil || v.Status.DeviceName == "" {
			return "", ""
		}
		return strings.TrimSpace(v.Status.DeviceName), "Tasmota"
	}},
}

var reTitel = regexp.MustCompile(`(?is)<title>\s*(.*?)\s*</title>`)

// nietszeggendeTitel filtert paginatitels die niets over het apparaat
// zeggen. Zonder deze lijst zou elk kastje "Login" gaan heten.
var nietszeggendeTitel = map[string]bool{
	"login": true, "log in": true, "index": true, "home": true,
	"welcome": true, "router": true, "administration": true,
	"401 unauthorized": true, "403 forbidden": true, "404 not found": true,
	"document": true, "untitled": true, "": true,
}

// HTTPIdentificatie probeert per host een handvol bekende eindpunten en
// valt terug op de paginatitel.
//
// Bedoeld voor apparaten die op geen enkel naamprotocol antwoorden maar
// wel een webinterface hebben — dat is een grote groep in elk huishouden.
func HTTPIdentificatie(ctx context.Context, ips []string, onResult func(HTTPResult)) {
	client := &http.Client{
		Timeout: 3 * time.Second,
		// Niet doorverwijzen: de eerste reactie zegt genoeg, en een
		// omleiding naar een inlogpagina levert alleen ruis op.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 16)

	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			for _, e := range httpEindpunten {
				if ctx.Err() != nil {
					return
				}
				body := haal(ctx, client, "http://"+ip+e.pad)
				if len(body) == 0 {
					continue
				}
				naam, model := e.lees(body)
				if naam == "" && model == "" {
					continue
				}
				mu.Lock()
				if onResult != nil {
					onResult(HTTPResult{IP: ip, Name: naam, Model: model})
				}
				mu.Unlock()
				return
			}

			// Niets herkend: dan maar de paginatitel.
			if titel := paginaTitel(ctx, client, ip); titel != "" {
				mu.Lock()
				if onResult != nil {
					onResult(HTTPResult{IP: ip, Model: titel})
				}
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()
}

func paginaTitel(ctx context.Context, client *http.Client, ip string) string {
	for _, url := range []string{"http://" + ip + "/", "https://" + ip + "/"} {
		body := haal(ctx, client, url)
		m := reTitel.FindSubmatch(body)
		if len(m) != 2 {
			continue
		}
		t := strings.Join(strings.Fields(string(m[1])), " ")
		if len(t) > 48 {
			t = t[:48]
		}
		if nietszeggendeTitel[strings.ToLower(t)] || len(t) < 3 {
			continue
		}
		return t
	}
	return ""
}

func haal(ctx context.Context, client *http.Client, url string) []byte {
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(c, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil
	}
	// Ruim genoeg voor een API-antwoord of een <title>, en klein genoeg om
	// niet vast te zitten aan een apparaat dat blijft sturen.
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if err != nil {
		return nil
	}
	return b
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
