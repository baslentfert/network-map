// Package netif leest de netwerkadapters van deze machine uit.
//
// Go's net.Interfaces() geeft geen gateway en geen prefixlengte, en juist
// die twee bepalen wat we moeten scannen. Daarom rechtstreeks
// GetAdaptersAddresses uit iphlpapi.
package netif

import (
	"fmt"
	"net/netip"
	"sort"
	"unsafe"

	"golang.org/x/sys/windows"

	"netwerksniffer/internal/oui"
)

// Adapter is één bruikbare netwerkadapter.
type Adapter struct {
	Index       uint32 `json:"index"`
	Name        string `json:"name"`        // "Wi-Fi"
	Description string `json:"description"` // "Intel(R) Wi-Fi 6 AX201"
	// DeviceName is de naam waarmee pcap deze adapter opent. Npcap kent
	// hem alleen onder \Device\NPF_{GUID}, niet onder "Wi-Fi".
	DeviceName string   `json:"deviceName"`
	MAC        string   `json:"mac"`
	IP         string   `json:"ip"`
	Prefix     int      `json:"prefix"`
	CIDR       string   `json:"cidr"`
	Gateway    string   `json:"gateway"`
	DNS        []string `json:"dns"`
	Up         bool     `json:"up"`
	Metric     uint32   `json:"metric"`
}

// HostCount is het aantal adressen dat een scan zou moeten aflopen,
// netwerk- en broadcastadres niet meegeteld.
func (i Adapter) HostCount() int {
	if i.Prefix <= 0 || i.Prefix > 32 {
		return 0
	}
	n := 1 << (32 - i.Prefix)
	if n <= 2 {
		return n
	}
	return n - 2
}

const ifTypeSoftwareLoopback = 24

// List geeft alle IPv4-adapters die aanstaan en een adres hebben.
func List() ([]Adapter, error) {
	const flags = windows.GAA_FLAG_INCLUDE_PREFIX | windows.GAA_FLAG_INCLUDE_GATEWAYS

	size := uint32(16384)
	var buf []byte
	for try := 0; ; try++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_INET, flags, 0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		// Windows vertelt via size hoeveel het écht nodig heeft.
		if err == windows.ERROR_BUFFER_OVERFLOW && try < 3 {
			continue
		}
		return nil, fmt.Errorf("adapters uitlezen: %w", err)
	}

	var out []Adapter
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		if aa.IfType == ifTypeSoftwareLoopback {
			continue
		}

		it := Adapter{
			Index:       aa.IfIndex,
			Name:        windows.UTF16PtrToString(aa.FriendlyName),
			Description: windows.UTF16PtrToString(aa.Description),
			DeviceName:  `\Device\NPF_` + windows.BytePtrToString(aa.AdapterName),
			Up:          aa.OperStatus == windows.IfOperStatusUp,
			Metric:      aa.Ipv4Metric,
		}
		if n := aa.PhysicalAddressLength; n == 6 {
			it.MAC = oui.Normalize(fmt.Sprintf("%02x%02x%02x%02x%02x%02x",
				aa.PhysicalAddress[0], aa.PhysicalAddress[1], aa.PhysicalAddress[2],
				aa.PhysicalAddress[3], aa.PhysicalAddress[4], aa.PhysicalAddress[5]))
		}

		for ua := aa.FirstUnicastAddress; ua != nil; ua = ua.Next {
			ip := ua.Address.IP()
			if ip == nil || ip.To4() == nil {
				continue
			}
			it.IP = ip.String()
			it.Prefix = int(ua.OnLinkPrefixLength)
			break
		}
		if it.IP == "" {
			continue
		}
		it.CIDR = cidrOf(it.IP, it.Prefix)

		if ga := aa.FirstGatewayAddress; ga != nil {
			if ip := ga.Address.IP(); ip != nil && ip.To4() != nil {
				it.Gateway = ip.String()
			}
		}
		// Windows noemt dezelfde DNS-server vaak twee keer (IPv4- en
		// IPv6-transport naar hetzelfde adres); één keer is genoeg.
		seenDNS := map[string]bool{}
		for ds := aa.FirstDnsServerAddress; ds != nil; ds = ds.Next {
			ip := ds.Address.IP()
			if ip == nil || ip.To4() == nil {
				continue
			}
			if s := ip.String(); !seenDNS[s] {
				seenDNS[s] = true
				it.DNS = append(it.DNS, s)
			}
		}
		out = append(out, it)
	}
	return out, nil
}

// Primary kiest de adapter waar het echte netwerk aan hangt.
//
// Op een ontwikkelmachine staan er al snel vier: Tailscale levert een /32
// zonder gateway, VirtualBox en WSL leveren eigen subnetten zonder
// gateway. Alleen de adapter met een default gateway praat met de buiten-
// wereld, en bij meerdere wint de laagste metric — dezelfde regel die
// Windows zelf gebruikt om verkeer te routeren.
func Primary() (Adapter, error) {
	all, err := List()
	if err != nil {
		return Adapter{}, err
	}
	var cand []Adapter
	for _, i := range all {
		if i.Up && i.Gateway != "" && i.Prefix > 0 && i.Prefix < 32 {
			cand = append(cand, i)
		}
	}
	if len(cand) == 0 {
		return Adapter{}, fmt.Errorf("geen adapter met een default gateway gevonden — zit deze machine wel op een netwerk?")
	}
	sort.Slice(cand, func(a, b int) bool { return cand[a].Metric < cand[b].Metric })
	return cand[0], nil
}

// ByName zoekt een adapter op z'n naam of op de pcap-devicenaam.
func ByName(name string) (Adapter, error) {
	all, err := List()
	if err != nil {
		return Adapter{}, err
	}
	for _, i := range all {
		if i.Name == name || i.DeviceName == name || i.IP == name {
			return i, nil
		}
	}
	return Adapter{}, fmt.Errorf("adapter %q niet gevonden", name)
}

// Hosts geeft alle adressen in het subnet, zonder netwerk- en
// broadcastadres en zonder ons eigen adres.
func (i Adapter) Hosts() []netip.Addr {
	pfx, err := netip.ParsePrefix(i.CIDR)
	if err != nil {
		return nil
	}
	self, _ := netip.ParseAddr(i.IP)

	var out []netip.Addr
	network := pfx.Masked().Addr()
	last := broadcast(pfx)
	for a := network.Next(); a.IsValid() && a.Less(last); a = a.Next() {
		if a == self {
			continue
		}
		out = append(out, a)
	}
	return out
}

func broadcast(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := uint32(1<<(32-p.Bits())) - 1
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func cidrOf(ip string, prefix int) string {
	a, err := netip.ParseAddr(ip)
	if err != nil || prefix <= 0 {
		return ""
	}
	return netip.PrefixFrom(a, prefix).Masked().String()
}
