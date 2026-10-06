package discover

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"time"
)

// CertResult is wat het TLS-certificaat van een apparaat prijsgeeft.
type CertResult struct {
	IP string
	// Model is een modelaanduiding, geen apparaatnaam. Drie Deco's dragen
	// alle drie CN=tplinkdeco.net: dat zegt wát het is, niet wélke het is.
	// De store houdt het daarom apart van de naam.
	Model string
}

// certPoorten zijn de plekken waar een apparaat een beheerinterface met
// TLS aanbiedt.
var certPoorten = []int{443, 8443}

// bekendeCN vertaalt certificaatnamen die op zichzelf niets zeggen naar
// iets leesbaars. De lijst is klein en groeit alleen met dingen die we
// echt hebben gezien.
var bekendeCN = map[string]string{
	"tplinkdeco.net":    "TP-Link Deco",
	"tplinkwifi.net":    "TP-Link router",
	"tplinkrepeater.net": "TP-Link versterker",
	"tplinkmodem.net":   "TP-Link modem",
	"routerlogin.net":   "Netgear router",
	"asusrouter.com":    "ASUS router",
	"fritz.box":         "AVM FRITZ!Box",
	"synologynas":       "Synology NAS",
}

// modelUitCN maakt van een certificaatnaam een bruikbare aanduiding, of
// een lege string als er niets zinnigs in staat.
func modelUitCN(cn string) string {
	cn = strings.TrimSpace(strings.ToLower(cn))
	if cn == "" {
		return ""
	}
	if m, ok := bekendeCN[cn]; ok {
		return m
	}
	// Zelfondertekende certificaten van apparaten dragen vaak het IP of
	// een tijdelijke naam; daar heeft niemand iets aan.
	if net.ParseIP(cn) != nil || strings.HasPrefix(cn, "*") || cn == "localhost" {
		return ""
	}
	if len(cn) < 3 || !strings.ContainsAny(cn, ".-") {
		return ""
	}
	return cn
}

// Certificaten haalt van elke host het TLS-certificaat op en leidt daar
// een modelaanduiding uit af.
//
// Dit vult het gat dat overblijft bij apparaten die niets adverteren: een
// Deco-satelliet zwijgt op mDNS, NetBIOS én SSDP, maar presenteert wel
// een certificaat zodra je z'n beheerpagina opvraagt.
func Certificaten(ctx context.Context, ips []string, onResult func(CertResult)) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 24)

	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			for _, poort := range certPoorten {
				if ctx.Err() != nil {
					return
				}
				model := haalCert(ctx, ip, poort)
				if model == "" {
					continue
				}
				mu.Lock()
				if onResult != nil {
					onResult(CertResult{IP: ip, Model: model})
				}
				mu.Unlock()
				return
			}
		}(ip)
	}
	wg.Wait()
}

func haalCert(ctx context.Context, ip string, poort int) string {
	c, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	d := &net.Dialer{Timeout: 2 * time.Second}
	// Certificaten van netwerkapparaten zijn vrijwel altijd
	// zelfondertekend; we controleren ze niet, we lezen ze alleen.
	conn, err := tls.DialWithDialer(d, "tcp",
		net.JoinHostPort(ip, itoa(poort)),
		&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return ""
	}
	defer conn.Close()

	if deadline, ok := c.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return ""
	}
	if m := modelUitCN(certs[0].Subject.CommonName); m != "" {
		return m
	}
	for _, naam := range certs[0].DNSNames {
		if m := modelUitCN(naam); m != "" {
			return m
		}
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [6]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
