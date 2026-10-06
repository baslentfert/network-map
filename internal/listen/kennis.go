package listen

import (
	"strings"
)

// Dit bestand is de kern van het nut. De lijst met open poorten haal je
// ook uit netstat; wat die niet geeft is of iets hoort waar het staat.
//
// Twee uitgangspunten. Een poort krijgt alleen een oordeel als we weten
// waarover we praten — "onbekend" is een eerlijker antwoord dan een
// verzonnen risicoscore. En het oordeel gaat over blootstelling, niet over
// gevaar: dat je bestandsdeling aanstaat is normaal op een thuisnetwerk en
// rampzalig op een hotel-wifi, en dat verschil kan deze app niet zien.

type soort int

const (
	soortWindows    soort = iota // hoort bij het besturingssysteem
	soortOntdekking              // apparaten die elkaar vinden
	soortBeheer                  // toegang op afstand
	soortDeling                  // bestanden en printers
	soortOntwikkel               // ontwikkelgereedschap
	soortDatabase
	soortApp   // gewone programma's
	soortMedia // streaming
	soortDynamisch
)

type kennis struct {
	dienst string
	soort  soort
	nl, en string
}

// Poorten die we herkennen. Bewust eindig: liever veertig die kloppen dan
// driehonderd waarvan de helft gokwerk is.
var perPoort = map[int]kennis{
	// --- Netwerkdiensten die je zelf draait ---
	53: {"DNS-server", soortApp,
		"Deze machine beantwoordt DNS-vragen. Vaak van Docker, WSL, een VPN of een adblocker.",
		"This machine answers DNS queries. Often from Docker, WSL, a VPN or an ad blocker."},
	67: {"DHCP-server", soortApp,
		"Deze machine deelt IP-adressen uit. Normaal doet je router dat; meestal komt dit van Hyper-V, VirtualBox of internetverbinding delen.",
		"This machine hands out IP addresses. Normally your router does that; this usually comes from Hyper-V, VirtualBox or connection sharing."},
	500: {"IPsec (IKE)", soortApp,
		"Opzetten van een VPN-verbinding.",
		"Setting up a VPN connection."},
	4500: {"IPsec (NAT-T)", soortApp,
		"VPN-verkeer door een NAT-router heen.",
		"VPN traffic through a NAT router."},
	41641: {"Tailscale", soortApp,
		"Privénetwerk tussen je eigen apparaten. Luistert op alle interfaces omdat het juist verbindingen van buiten moet aannemen.",
		"Private network between your own devices. Listens on all interfaces because it needs to accept connections from outside."},
	9000: {"MinIO / Portainer", soortOntwikkel,
		"Poort 9000 is meestal MinIO (S3-opslag) of Portainer (Docker-beheer).",
		"Port 9000 is usually MinIO (S3 storage) or Portainer (Docker management)."},
	9001: {"MinIO-console", soortOntwikkel,
		"Beheerscherm van MinIO.",
		"MinIO's admin console."},
	1337: {"vrije poort", soortOntwikkel,
		"Poort 1337 heeft geen vaste betekenis; hij wordt vaak door ontwikkelgereedschap gekozen.",
		"Port 1337 has no fixed meaning; development tools often pick it."},
	4444: {"vrije poort", soortOntwikkel,
		"Poort 4444 heeft geen vaste betekenis. Vaak eigen software of een testserver — maar ook een klassieke keuze van aanvalsgereedschap, dus controleer welk programma dit is.",
		"Port 4444 has no fixed meaning. Often in-house software or a test server — but also a classic choice for attack tooling, so check which program this is."},
	5050: {"vrije poort", soortApp,
		"Geen vaste dienst. Wordt onder meer door synchronisatie- en beheerprogramma's gebruikt.",
		"No fixed service. Used among others by sync and management tools."},
	8443: {"webserver (TLS, alt)", soortOntwikkel,
		"Versleutelde webpoort naast 443, vaak een beheerpagina.",
		"Encrypted web port alongside 443, often an admin page."},
	8000: {"ontwikkelserver", soortOntwikkel,
		"Veelgebruikte alternatieve webpoort, vaak Python of PHP.",
		"Common alternative web port, often Python or PHP."},

	// --- Windows zelf ---
	135: {"RPC-endpointmapper", soortWindows,
		"Wijst programma's de weg naar Windows-diensten. Hoort op elke Windows-machine te staan.",
		"Directs programs to Windows services. Present on every Windows machine."},
	139: {"NetBIOS-sessie", soortDeling,
		"Oude bestandsdeling. Tegenwoordig vervangen door poort 445, maar Windows houdt hem aan.",
		"Legacy file sharing. Superseded by port 445, but Windows keeps it around."},
	445: {"SMB-bestandsdeling", soortDeling,
		"Gedeelde mappen en printers. Normaal thuis; dit is wel de poort waar ransomware zich graag langs verspreidt.",
		"Shared folders and printers. Normal at home; also the port ransomware likes to spread through."},
	3389: {"Remote Desktop", soortBeheer,
		"Vanaf een ander apparaat deze machine overnemen. Handig als je het zelf aanzette, zorgwekkend als dat niet zo is.",
		"Taking over this machine from elsewhere. Handy if you enabled it, concerning if you did not."},
	5040: {"Connected Devices Platform", soortWindows,
		"Windows-dienst voor het koppelen van je apparaten onderling.",
		"Windows service that links your devices to each other."},
	7680: {"Delivery Optimization", soortWindows,
		"Windows haalt updates deels bij andere pc's in je netwerk op in plaats van bij Microsoft.",
		"Windows fetches part of its updates from other PCs on your network instead of from Microsoft."},
	5357: {"WSD-webdienst", soortOntdekking,
		"Hoort bij netwerkdetectie: zo vinden printers en pc's elkaar.",
		"Part of network discovery: how printers and PCs find each other."},
	2179: {"Hyper-V VMConnect", soortBeheer,
		"Verbinding met het scherm van een virtuele machine.",
		"Connection to a virtual machine's console."},
	2869: {"UPnP-gebeurtenissen", soortOntdekking,
		"Apparaten melden elkaar veranderingen, bijvoorbeeld een mediaserver aan je tv.",
		"Devices notify each other of changes, for instance a media server telling your TV."},

	// --- Ontdekkingsprotocollen ---
	137:  {"NetBIOS-naamservice", soortOntdekking, "Oude Windows-naamopzoeking.", "Legacy Windows name lookup."},
	138:  {"NetBIOS-datagram", soortOntdekking, "Oude Windows-mededelingen op het netwerk.", "Legacy Windows network announcements."},
	1900: {"SSDP / UPnP", soortOntdekking, "Zoekt en adverteert apparaten: tv's, routers, mediaservers.", "Finds and advertises devices: TVs, routers, media servers."},
	3702: {"WS-Discovery", soortOntdekking, "Zoekt netwerkprinters, scanners en Windows-machines.", "Finds network printers, scanners and Windows machines."},
	5353: {"mDNS / Bonjour", soortOntdekking, "Namen zonder DNS-server. Apple, printers, Chromecast, slimme apparaten.", "Names without a DNS server. Apple, printers, Chromecast, smart devices."},
	5355: {"LLMNR", soortOntdekking, "Naamopzoeking binnen je eigen netwerk; de opvolger van NetBIOS.", "Name lookup within your own network; NetBIOS's successor."},

	// --- Toegang op afstand ---
	22:   {"SSH", soortBeheer, "Beveiligde opdrachtregel op afstand. Krachtig; wil je zelden open naar het hele netwerk.", "Secure remote command line. Powerful; rarely something you want open to the whole network."},
	23:   {"Telnet", soortBeheer, "Opdrachtregel op afstand, volledig onversleuteld. Hoort nergens meer aan te staan.", "Remote command line, entirely unencrypted. Should not be running anywhere any more."},
	5900: {"VNC", soortBeheer, "Schermovername. Vaak zwak of niet beveiligd.", "Screen sharing. Often weakly protected or not at all."},
	5938: {"TeamViewer", soortBeheer, "Hulp op afstand.", "Remote assistance."},

	// --- Ontwikkelgereedschap ---
	3000: {"ontwikkelserver", soortOntwikkel, "Standaardpoort van Node, Next.js en Rails tijdens het ontwikkelen.", "Default port for Node, Next.js and Rails during development."},
	3001: {"ontwikkelserver", soortOntwikkel, "Tweede ontwikkelserver naast 3000.", "Second dev server alongside 3000."},
	4200: {"Angular-ontwikkelserver", soortOntwikkel, "Angular tijdens het ontwikkelen.", "Angular during development."},
	5173: {"Vite-ontwikkelserver", soortOntwikkel, "Vite tijdens het ontwikkelen; ook wat Wails in dev-modus gebruikt.", "Vite during development; also what Wails uses in dev mode."},
	8080: {"webserver (alt)", soortOntwikkel, "Tweede webpoort. Proxy's, testservers, beheerpagina's van apparaten.", "Secondary web port. Proxies, test servers, device admin pages."},
	9229: {"Node-debugger", soortOntwikkel, "Debugger van Node.js. Wie hierbij kan, kan code uitvoeren.", "Node.js debugger. Anyone who reaches it can execute code."},
	2375: {"Docker (onversleuteld)", soortOntwikkel, "Docker-besturing zonder beveiliging. Toegang hiertoe is volledige controle over de machine.", "Unsecured Docker control. Access to this is full control of the machine."},
	2376: {"Docker (TLS)", soortOntwikkel, "Docker-besturing met certificaat.", "Docker control with a certificate."},

	// --- Databases ---
	1433:  {"SQL Server", soortDatabase, "Microsoft-database.", "Microsoft database."},
	3306:  {"MySQL / MariaDB", soortDatabase, "Database. Hoort normaal alleen vanaf deze machine bereikbaar te zijn.", "Database. Normally should only be reachable from this machine."},
	5432:  {"PostgreSQL", soortDatabase, "Database. Hoort normaal alleen vanaf deze machine bereikbaar te zijn.", "Database. Normally should only be reachable from this machine."},
	6379:  {"Redis", soortDatabase, "Sleutel-waardeopslag, standaard zonder wachtwoord. Nooit open naar het netwerk.", "Key-value store, passwordless by default. Never expose to the network."},
	27017: {"MongoDB", soortDatabase, "Database.", "Database."},
	9200:  {"Elasticsearch", soortDatabase, "Zoekmachine, standaard zonder wachtwoord.", "Search engine, passwordless by default."},
	11211: {"Memcached", soortDatabase, "Cache zonder beveiliging. Wordt misbruikt voor aanvallen als hij open staat.", "Unsecured cache. Abused for attacks when left open."},

	// --- Gewone programma's ---
	17500: {"Dropbox LAN-sync", soortApp, "Dropbox haalt bestanden bij andere pc's in je netwerk in plaats van uit de cloud.", "Dropbox fetches files from other PCs on your network instead of from the cloud."},
	27036: {"Steam", soortApp, "Steam-spellenbibliotheek delen en uitzenden binnen je netwerk.", "Steam library sharing and broadcasting within your network."},
	4070:  {"Spotify Connect", soortApp, "Spotify aansturen vanaf een ander apparaat.", "Controlling Spotify from another device."},
	1716:  {"KDE Connect", soortApp, "Koppeling tussen telefoon en computer.", "Link between phone and computer."},

	// --- Media en printen ---
	32400: {"Plex", soortMedia, "Mediaserver.", "Media server."},
	8096:  {"Jellyfin", soortMedia, "Mediaserver.", "Media server."},
	8008:  {"Chromecast", soortMedia, "Casten naar een scherm.", "Casting to a screen."},
	631:   {"IPP-printen", soortDeling, "Netwerkprinten.", "Network printing."},
	9100:  {"JetDirect", soortDeling, "Rechtstreeks naar een printer sturen.", "Sending straight to a printer."},
	5000:  {"webdienst", soortApp, "Veelgebruikt: Synology DSM, Flask, UPnP. Welke het is hangt van het proces af.", "Commonly Synology DSM, Flask or UPnP. Which one depends on the process."},
	5001:  {"webdienst (TLS)", soortApp, "Versleutelde variant van 5000.", "Encrypted variant of 5000."},
}

// Processen die hun eigen verhaal vertellen, ongeacht de poort. Dit vangt
// de ontwikkelservers op willekeurige poorten en de bekende programma's.
var perProces = []struct {
	match  string
	dienst string
	soort  soort
	nl, en string
}{
	{"node", "Node.js", soortOntwikkel, "Een Node-programma, meestal een ontwikkelserver.", "A Node program, usually a dev server."},
	{"bun", "Bun", soortOntwikkel, "Een Bun-programma, meestal een ontwikkelserver.", "A Bun program, usually a dev server."},
	{"deno", "Deno", soortOntwikkel, "Een Deno-programma.", "A Deno program."},
	{"python", "Python", soortOntwikkel, "Een Python-programma dat op het netwerk luistert.", "A Python program listening on the network."},
	{"java", "Java", soortApp, "Een Java-programma dat op het netwerk luistert.", "A Java program listening on the network."},
	{"docker", "Docker", soortOntwikkel, "Docker, of een container die een poort doorgeeft.", "Docker, or a container forwarding a port."},
	{"wsl", "WSL", soortOntwikkel, "Linux onder Windows geeft een poort door.", "Linux on Windows forwarding a port."},
	{"vmware", "VMware", soortApp, "Virtualisatie.", "Virtualisation."},
	{"virtualbox", "VirtualBox", soortApp, "Virtualisatie.", "Virtualisation."},
	{"dropbox", "Dropbox", soortApp, "Bestandssynchronisatie.", "File synchronisation."},
	{"onedrive", "OneDrive", soortApp, "Bestandssynchronisatie.", "File synchronisation."},
	{"steam", "Steam", soortApp, "Spellenplatform.", "Games platform."},
	{"spotify", "Spotify", soortApp, "Muziek.", "Music."},
	{"teams", "Microsoft Teams", soortApp, "Vergaderen en chatten.", "Meetings and chat."},
	{"zoom", "Zoom", soortApp, "Vergaderen.", "Meetings."},
	{"chrome", "Chrome", soortApp, "Browser.", "Browser."},
	{"firefox", "Firefox", soortApp, "Browser.", "Browser."},
	{"code", "Visual Studio Code", soortOntwikkel, "Editor; luistert voor uitbreidingen en foutopsporing.", "Editor; listens for extensions and debugging."},
	{"ollama", "Ollama", soortOntwikkel, "Draait taalmodellen lokaal.", "Runs language models locally."},
	{"tailscale", "Tailscale", soortApp, "Privénetwerk tussen je eigen apparaten.", "Private network between your own devices."},
	{"svchost", "Windows-systeemdienst", soortWindows, "Een gedeelde Windows-dienst. Welke precies is zonder meer rechten niet te zien.", "A shared Windows service. Which one exactly is not visible without more privileges."},
	{"system", "Windows-kern", soortWindows, "Het besturingssysteem zelf.", "The operating system itself."},
}

// duid vult dienst, uitleg en oordeel in.
func duid(l *Luisteraar, taal string) {
	k, bekend := perPoort[l.Port]
	if !bekend {
		k, bekend = uitProces(l.Process)
	}
	// Een bekende poort wint, maar het proces kan hem preciezer maken:
	// poort 5000 met node.exe is een ontwikkelserver, niet Synology DSM.
	if bekend && k.soort != soortOntwikkel {
		if pk, ok := uitProces(l.Process); ok && pk.soort == soortOntwikkel {
			k = pk
		}
	}

	switch {
	case bekend:
		l.Dienst = k.dienst
		l.Uitleg = kies(taal, k.nl, k.en)
	case l.Port >= 49152:
		l.Dienst = kies(taal, "tijdelijke poort", "ephemeral port")
		l.Uitleg = kies(taal,
			"Windows deelt poorten boven 49151 tijdelijk uit. Die horen bij een lopend gesprek, niet bij een vaste dienst.",
			"Windows hands out ports above 49151 temporarily. These belong to an ongoing conversation, not a fixed service.")
		// Wel degelijk thuisgebracht: niet als onbekend wegzetten, want dan
		// vult de aandachtslijst zich met ruis die niemand kan opvolgen.
		k.soort, bekend = soortDynamisch, true
	default:
		l.Dienst = kies(taal, "onbekend", "unknown")
		l.Uitleg = kies(taal,
			"Deze poort staat niet in onze lijst. Dat zegt niets over of het goed of fout is — alleen dat wij hem niet herkennen.",
			"This port is not in our list. That says nothing about right or wrong — only that we do not recognise it.")
	}

	oordeel(l, k.soort, bekend, taal)
}

func uitProces(naam string) (kennis, bool) {
	n := strings.ToLower(strings.TrimSuffix(naam, ".exe"))
	if n == "" {
		return kennis{}, false
	}
	for _, p := range perProces {
		if strings.Contains(n, p.match) {
			return kennis{dienst: p.dienst, soort: p.soort, nl: p.nl, en: p.en}, true
		}
	}
	return kennis{}, false
}

// oordeel kijkt uitsluitend naar blootstelling. Of iets gevaarlijk is
// hangt af van het netwerk waar je op zit, en dat weet deze app niet.
func oordeel(l *Luisteraar, s soort, bekend bool, taal string) {
	if l.Bereik == BereikLokaal {
		l.Oordeel = OordeelNormaal
		l.Waarom = kies(taal,
			"Alleen bereikbaar vanaf deze machine zelf.",
			"Only reachable from this machine itself.")
		return
	}

	if !bekend {
		l.Oordeel = OordeelOnbekend
		l.Waarom = kies(taal,
			"Open naar je hele netwerk en wij weten niet wat het is. Kijk welk programma dit is.",
			"Open to your whole network and we do not know what it is. Check which program this is.")
		return
	}

	switch s {
	case soortOntwikkel:
		l.Oordeel = OordeelLetOp
		l.Waarom = kies(taal,
			"Een ontwikkelserver die op je hele netwerk luistert. Meestal onbedoeld: die hoort op 127.0.0.1.",
			"A dev server listening on your whole network. Usually unintended: it belongs on 127.0.0.1.")
	case soortDatabase:
		l.Oordeel = OordeelLetOp
		l.Waarom = kies(taal,
			"Een database die vanaf je hele netwerk bereikbaar is. Die hoort normaal alleen lokaal te luisteren.",
			"A database reachable from your whole network. It normally should listen locally only.")
	case soortBeheer:
		l.Oordeel = OordeelLetOp
		l.Waarom = kies(taal,
			"Toegang op afstand, open naar je hele netwerk. Prima als je dat zelf aanzette; controleer het anders.",
			"Remote access, open to your whole network. Fine if you enabled it yourself; otherwise worth checking.")
	case soortWindows, soortOntdekking, soortDeling, soortApp, soortMedia:
		l.Oordeel = OordeelNormaal
		l.Waarom = kies(taal,
			"Hoort op een thuisnetwerk te kunnen. Op een openbaar netwerk zou je dit uit willen zetten.",
			"Expected on a home network. On a public network you would want this switched off.")
	default:
		l.Oordeel = OordeelNormaal
		l.Waarom = kies(taal,
			"Hoort bij een lopende verbinding, niet bij een vaste dienst.",
			"Belongs to an ongoing connection, not to a fixed service.")
	}
}

func kies(taal, nl, en string) string {
	if taal == "nl" {
		return nl
	}
	return en
}
