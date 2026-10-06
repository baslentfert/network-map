import { useEffect, useMemo, useState } from "react";
import NetworkMap from "./NetworkMap";
import PortsView from "./PortsView";
import TrafficView from "./TrafficView";
import WatchView from "./WatchView";
import { useNetwork, ipSort, toonNaam } from "./net";
import type { Adapter, Host, LogEvent } from "./net";
import { useT, geleden } from "./i18n";
import type { I18n, MsgKey } from "./i18n";

type Tab = "map" | "devices" | "ports" | "traffic" | "watch" | "log";

const STATUS_CLASS: Record<string, string> = {
  online: "s-online", new: "s-new", alert: "s-alert", offline: "s-offline",
};
const ERNST: Record<string, string> = { alert: "loud", nieuw: "mark", weg: "gone" };

// De tags zoals de backend ze stuurt, met hun tekstsleutel ernaast.
const FILTERS: Array<[string, MsgKey]> = [
  ["alles", "filter.all"],
  ["alert", "tag.alert"],
  ["nieuw", "tag.new"],
  ["weg", "tag.gone"],
  ["dhcp", "tag.dhcp"],
  ["arp", "tag.arp"],
  ["scan", "tag.scan"],
  ["mdns", "tag.mdns"],
  ["dns", "tag.dns"],
];

const PROFIELEN: Array<[string, MsgKey]> = [
  ["snel", "profile.quick"],
  ["normaal", "profile.normal"],
  ["grondig", "profile.thorough"],
];

const TABS: Array<[Tab, MsgKey]> = [
  ["map", "tab.map"],
  ["devices", "tab.devices"],
  ["ports", "tab.ports"],
  ["traffic", "tab.traffic"],
  ["watch", "tab.watch"],
  ["log", "tab.log"],
];

function klok(iso: string): string {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? "--:--:--" : d.toLocaleTimeString(undefined, { hour12: false });
}

/** regel maakt van een gebeurtenis een zin in de huidige taal. */
function regel(t: I18n["t"], e: LogEvent): string {
  const args: Record<string, string> = { ...(e.args ?? {}) };
  // Sommige parameters zijn zelf een sleutel — het DHCP-berichttype
  // bijvoorbeeld. Die vertalen we mee in plaats van "dhcp.request" te tonen.
  if (args.what) args.what = t(args.what as MsgKey);
  return t(e.key as MsgKey, args);
}

const POTLOOD = (
  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M11.5 2.5l2 2L6 12l-2.5.5L4 10z" />
  </svg>
);

export default function App() {
  const net = useNetwork();
  const { t, taal, talen, zetTaal, klaar } = useT();
  const [tab, setTab] = useState<Tab>("map");
  const [sel, setSel] = useState<string | null>(null);
  const [filter, setFilter] = useState("alles");
  const [profiel, setProfiel] = useState("snel");
  const [adapters, setAdapters] = useState<Adapter[]>([]);

  useEffect(() => { net.adapters().then(setAdapters).catch(() => {}); }, [net.status.adapter.name]);

  const hosts = useMemo(
    () => Object.values(net.hosts).sort((a, b) => ipSort(a.ip, b.ip)),
    [net.hosts]
  );
  const gekozen = sel ? net.hosts[sel] ?? null : null;
  const nieuw = hosts.filter((h) => h.status === "new").length;
  const online = hosts.filter((h) => h.status !== "offline").length;

  const zichtbaar = useMemo(
    () => (filter === "alles" ? net.events : net.events.filter((e) => e.tag === filter)),
    [net.events, filter]
  );

  const bezig = net.status.scanning;
  const pct = net.progress.total > 0 ? (net.progress.done / net.progress.total) * 100 : 0;
  const fase = net.progress.phase ? t(`phase.${net.progress.phase}` as MsgKey) : "";

  if (!klaar) return null;

  return (
    <div className="app">
      <header className="bar">
        <div className="brand">
          <h1>{t("app.title")}</h1>
          <span className="sub">
            {net.status.adapter.cidr ? (
              <>
                <b>{net.status.adapter.name}</b> · {net.status.adapter.cidr} ·{" "}
                {t("app.gateway")} {net.status.adapter.gateway}
              </>
            ) : (
              t("app.noAdapter")
            )}
          </span>
        </div>

        <div className="stat"><b>{hosts.length}</b><span>{t("stat.devices")}</span></div>
        <div className="stat"><b>{online}</b><span>{t("stat.online")}</span></div>
        <div className="stat"><b>{nieuw}</b><span>{t("stat.new")}</span></div>

        <select
          value={net.status.adapter.name}
          onChange={(e) => net.selectAdapter(e.target.value)}
          disabled={bezig || net.status.monitoring}
          title={t("profile.pick")}
        >
          {adapters.map((a) => (
            <option key={a.deviceName} value={a.name}>
              {a.name} — {a.cidr || t("profile.noAddress")}
            </option>
          ))}
        </select>

        <select value={profiel} onChange={(e) => setProfiel(e.target.value)} disabled={bezig}>
          {PROFIELEN.map(([v, k]) => <option key={v} value={v}>{t(k)}</option>)}
        </select>

        <button className="btn" onClick={() => net.scan(profiel)} disabled={bezig || !net.status.adapter.cidr}>
          {bezig ? t("btn.scanning") : t("btn.scanNow")}
        </button>

        <button
          className="btn primary"
          onClick={() => (net.status.monitoring ? net.stop() : net.start(profiel))}
          disabled={!net.status.adapter.cidr}
        >
          {net.status.monitoring ? t("btn.stopMonitor") : t("btn.startMonitor")}
        </button>

        <span
          className={"chip " + (net.status.passive ? "on" : "off")}
          title={net.status.passive ? t("tip.listening") : net.status.passiveReason || t("tip.passiveOff")}
        >
          {net.status.passive ? t("chip.listening") : t("chip.passiveOff")}
        </span>
        <span
          className={"chip " + (net.status.capture ? "on" : "off")}
          title={net.status.capture ? t("tip.npcap") : t("tip.noL2")}
        >
          {net.status.capture ? t("chip.npcap") : t("chip.noL2")}
        </span>

        <select value={taal} onChange={(e) => zetTaal(e.target.value)} style={{ maxWidth: 130 }}>
          {talen.map((l) => <option key={l.code} value={l.code}>{l.name}</option>)}
        </select>
      </header>

      <div className={"progress" + (bezig ? "" : " idle")} title={fase}>
        <i style={{ width: `${pct}%` }} />
      </div>

      {net.error && (
        <div className="bar" style={{ borderColor: "var(--alert)", color: "var(--alert)" }}>
          {net.error}
          <button className="btn" style={{ marginLeft: "auto" }} onClick={() => net.setError("")}>
            {t("btn.close")}
          </button>
        </div>
      )}

      <nav className="tabs" role="tablist">
        {TABS.map(([v, k]) => (
          <button key={v} className="tab" role="tab" aria-selected={tab === v} onClick={() => setTab(v)}>
            {t(k)}
          </button>
        ))}
      </nav>

      <div className="stage">
        {tab === "map" && (
          <section className="view">
            {hosts.length === 0 ? (
              <div className="empty">
                <h2>{t("empty.title")}</h2>
                <p>{t("empty.body")}</p>
              </div>
            ) : (
              <>
                <NetworkMap
                  hosts={hosts}
                  subnet={net.status.adapter.cidr}
                  selected={sel}
                  onSelect={setSel}
                  naamVan={toonNaam}
                />
                <div className="overlay legend">
                  <div className="row"><i style={{ background: "var(--online)" }} /> {t("legend.online")}</div>
                  <div className="row"><i style={{ background: "var(--amber)" }} /> {t("legend.new")}</div>
                  <div className="row"><i style={{ background: "var(--alert)" }} /> {t("legend.alert")}</div>
                  <div className="row"><i style={{ background: "var(--offline)" }} /> {t("legend.gone")}</div>
                </div>
                <p className="overlay caveat">{t("map.caveat")}</p>
              </>
            )}
          </section>
        )}

        {tab === "devices" && (
          <section className="view">
            <div className="scroll">
              <table>
                <thead>
                  <tr>
                    <th>{t("col.status")}</th><th>{t("col.ip")}</th><th>{t("col.mac")}</th>
                    <th>{t("col.vendor")}</th><th>{t("col.name")}</th>
                    <th className="num">{t("col.ports")}</th><th>{t("col.kind")}</th>
                  </tr>
                </thead>
                <tbody>
                  {hosts.map((h) => (
                    <tr key={h.key} aria-selected={sel === h.key} onClick={() => setSel(h.key)}>
                      <td>
                        <span className={"pill " + STATUS_CLASS[h.status]}>
                          <i />{t(`status.${h.status}` as MsgKey)}
                        </span>
                      </td>
                      <td className="mono">{h.ip}</td>
                      <td className="mono dim">{h.mac || "—"}</td>
                      <td className={h.randomMac || !h.vendor ? "dim" : ""}>
                        {h.randomMac ? t("vendor.private") : h.vendor || t("vendor.unknown")}
                      </td>
                      <td className={h.name ? "" : "dim ital"}>{toonNaam(h) || t("name.assign")}</td>
                      <td className="num">{h.ports?.length || "—"}</td>
                      <td className="dim">
                        {h.kind === "unknown" ? "—" : t(`kind.${h.kind}` as MsgKey)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {tab === "log" && (
          <section className="view">
            <div className="scroll">
              <table>
                <thead>
                  <tr><th>{t("col.time")}</th><th>{t("col.type")}</th><th>{t("col.event")}</th></tr>
                </thead>
                <tbody>
                  {[...net.events].reverse().map((e, i) => (
                    <tr key={i} onClick={() => e.host && setSel(e.host)}>
                      <td className="mono dim">{klok(e.at)}</td>
                      <td className={"mono t-" + e.tag}>{e.tag}</td>
                      <td>{regel(t, e)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {tab === "ports" && <PortsView />}

        {tab === "traffic" && <TrafficView />}

        {tab === "watch" && <WatchView />}

        {tab !== "ports" && tab !== "traffic" && tab !== "watch" && <Detail
          host={gekozen}
          bezig={bezig}
          onAlias={(naam) => gekozen && net.setAlias(gekozen.key, naam)}
          onScan={() => gekozen && net.scanHost(gekozen.ip, "grondig")}
        />}
      </div>

      <section className="ticker">
        <header>
          <h3>{t("log.title")}</h3>
          <span className="count">
            {filter === "alles"
              ? t("log.count", { n: net.events.length })
              : t("log.filtered", { shown: zichtbaar.length, total: net.events.length, filter })}
          </span>
          <div className="filters">
            {FILTERS.map(([v, k]) => (
              <button key={v} className="filt" aria-pressed={filter === v} onClick={() => setFilter(v)}>
                {t(k)}
              </button>
            ))}
          </div>
        </header>
        <div className="feed">
          {zichtbaar.slice(-60).reverse().map((e, i) => (
            <div key={`${e.at}-${i}`} className={"ev " + (ERNST[e.tag] || "")}>
              <time>{klok(e.at)}</time>
              <span className={"tag t-" + e.tag}>{e.tag}</span>
              <span className="txt">{regel(t, e)}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

function Detail({
  host, bezig, onAlias, onScan,
}: {
  host: Host | null;
  bezig: boolean;
  onAlias: (naam: string) => void;
  onScan: () => void;
}) {
  const { t } = useT();
  const [bewerk, setBewerk] = useState(false);
  const [concept, setConcept] = useState("");

  useEffect(() => { setBewerk(false); }, [host?.key]);

  if (!host) return <aside className="panel leeg">{t("panel.empty")}</aside>;

  const bewaar = () => { onAlias(concept.trim()); setBewerk(false); };
  const bronnen = host.names ?? [];

  return (
    <aside className="panel">
      <span className={"pill " + STATUS_CLASS[host.status]}>
        <i />{t(`status.${host.status}` as MsgKey)}
      </span>

      {bewerk ? (
        <input
          className="naam-in"
          autoFocus
          maxLength={40}
          value={concept}
          placeholder={t("name.placeholder")}
          onChange={(e) => setConcept(e.target.value)}
          onBlur={bewaar}
          onKeyDown={(e) => {
            if (e.key === "Enter") bewaar();
            if (e.key === "Escape") setBewerk(false);
          }}
        />
      ) : (
        <div className={"naam" + (host.name ? "" : " zonder")}>
          <h2>{host.name || host.model || t("panel.unnamed")}</h2>
          <button
            title={t("btn.rename")}
            aria-label={t("btn.rename")}
            onClick={() => { setConcept(host.name); setBewerk(true); }}
          >
            {POTLOOD}
          </button>
        </div>
      )}

      <p className="sub">
        {host.randomMac ? t("vendor.privateLong") : host.vendor || t("vendor.unknown")}
        {host.isGateway && ` · ${t("app.gateway")}`}
        {host.isSelf && ` · ${t("vendor.self")}`}
      </p>

      {!host.name && (
        <p className="hint">
          {host.model ? t("panel.hintModel", { model: host.model }) : t("panel.hintNoName")}{" "}
          {t("panel.hintTail")}
        </p>
      )}

      <dl className="kv">
        <dt>{t("kv.ip")}</dt><dd>{host.ip || "—"}</dd>
        <dt>{t("kv.mac")}</dt><dd>{host.mac || "—"}</dd>
        {host.ttl > 0 && (
          <>
            <dt>{t("kv.ttl")}</dt>
            <dd>
              {host.ttl}{" "}
              <span className="dim">
                ({host.osHint ? t(host.osHint as MsgKey) : t("os.unknown")})
              </span>
            </dd>
          </>
        )}
        <dt>{t("kv.kind")}</dt>
        <dd>{t(`kind.${host.kind}` as MsgKey)}</dd>
        {host.model && (<><dt>{t("kv.model")}</dt><dd>{host.model}</dd></>)}
        <dt>{t("kv.seen")}</dt><dd>{geleden(t, host.lastSeen)}</dd>
      </dl>

      <div className="sec">
        <span>{t("sec.ports")}</span>
        <button className="btn" onClick={onScan} disabled={bezig}>
          {bezig ? t("btn.busy") : t("btn.deepScan")}
        </button>
      </div>
      {host.ports && host.ports.length > 0 ? (
        <div className="ports">
          {host.ports.map((p) => (
            <span key={p.number} className="port"><b>{p.number}</b> {p.service}</span>
          ))}
        </div>
      ) : (
        <p className="note">{t("panel.noPorts")}</p>
      )}

      <div className="sec"><span>{t("sec.names")}</span></div>
      {bronnen.length > 0 ? (
        bronnen.map((n, i) => (
          <div key={i} className="src">
            <span>{n.value}</span>
            <span>{n.origin === "alias" ? t("origin.alias") : n.origin}</span>
          </div>
        ))
      ) : (
        <p className="note">{t("panel.noNames")}</p>
      )}

      {host.noteKey && (
        <p className="note">{t(host.noteKey as MsgKey, host.noteArgs)}</p>
      )}
    </aside>
  );
}
