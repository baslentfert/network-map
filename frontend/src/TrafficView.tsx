import { useCallback, useEffect, useState } from "react";
import * as App from "../wailsjs/go/main/App";
import { useT } from "./i18n";

interface Status {
  active: boolean;
  address: string;
  upstream: string[] | null;
  queries: number;
  failed: number;
}

interface Apparaat {
  client: string;
  name: string;
  queries: number;
  domains: number;
}

interface Teller {
  client: string;
  name: string;
  count: number;
  addresses?: string[] | null;
}

interface Vraag {
  at: string;
  client: string;
  name: string;
  type: string;
  rcode: string;
  ms: number;
  answers?: string[] | null;
}

function klok(iso: string): string {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? "--:--:--" : d.toLocaleTimeString(undefined, { hour12: false });
}

export default function TrafficView() {
  const { t } = useT();
  const [st, setSt] = useState<Status | null>(null);
  const [apparaten, setApparaten] = useState<Apparaat[]>([]);
  const [top, setTop] = useState<Teller[]>([]);
  const [recent, setRecent] = useState<Vraag[]>([]);
  const [fout, setFout] = useState("");
  const [bezig, setBezig] = useState(false);
  const [gekozen, setGekozen] = useState<string>("");

  const ververs = useCallback(async () => {
    try {
      const [s, a, d, r] = await Promise.all([
        App.DNSStatus(), App.DNSDevices(), App.DNSTop(25, gekozen), App.DNSRecent(60),
      ]);
      setSt(s as unknown as Status);
      setApparaten(((a ?? []) as unknown) as Apparaat[]);
      setTop(((d ?? []) as unknown) as Teller[]);
      setRecent(((r ?? []) as unknown) as Vraag[]);
    } catch (e) {
      setFout(String(e));
    }
  }, [gekozen]);

  // Een seconde is snel genoeg om levend aan te voelen en traag genoeg om
  // niets te kosten; de gegevens staan toch al in het geheugen.
  useEffect(() => {
    ververs();
    const id = setInterval(ververs, 1000);
    return () => clearInterval(id);
  }, [ververs]);

  const schakel = async () => {
    setBezig(true);
    setFout("");
    try {
      if (st?.active) await App.StopDNS();
      else await App.StartDNS();
      await ververs();
    } catch (e) {
      setFout(String(e));
    } finally {
      setBezig(false);
    }
  };

  const adres = st?.address ?? "";

  return (
    <>
      <section className="view">
        <div className="scroll">
          <div className="ports-kop">
            <div>
              <h2>{t("dns.title")}</h2>
              <p className="sub">
                {st?.active
                  ? t("dns.running", { addr: adres }) + " · " +
                    t("dns.stats", { n: st.queries, failed: st.failed })
                  : t("dns.stopped")}
              </p>
            </div>
            <div className="ports-knoppen">
              <button className="btn primary" onClick={schakel} disabled={bezig}>
                {bezig ? t("btn.busy") : st?.active ? t("dns.stop") : t("dns.start")}
              </button>
            </div>
          </div>

          <p className="note" style={{ padding: "10px 12px 0" }}>
            {t("dns.intro", { addr: adres })}
          </p>
          {st?.upstream && st.upstream.length > 0 && (
            <p className="note mono" style={{ padding: "2px 12px 10px" }}>
              {t("dns.upstream")}: {st.upstream.join(", ")}
            </p>
          )}

          {fout && (
            <p className="note" style={{ color: "var(--alert)", padding: "0 12px 8px" }}>{fout}</p>
          )}

          {st?.active && apparaten.length === 0 && (
            <p className="note" style={{ padding: "0 12px 12px", color: "var(--amber)" }}>
              {t("dns.waiting")}
            </p>
          )}

          {apparaten.length > 0 && (
            <>
              <div className="sec" style={{ margin: "4px 12px 6px" }}><span>{t("dns.devices")}</span></div>
              <table>
                <thead>
                  <tr>
                    <th>{t("col.device")}</th><th>{t("col.ip")}</th>
                    <th className="num">{t("col.queries")}</th>
                    <th className="num">{t("col.domains")}</th>
                  </tr>
                </thead>
                <tbody>
                  {apparaten.map((a) => (
                    <tr
                      key={a.client}
                      aria-selected={gekozen === a.client}
                      onClick={() => setGekozen(gekozen === a.client ? "" : a.client)}
                    >
                      <td>{a.name !== a.client ? a.name : <span className="dim ital">{t("panel.unnamed")}</span>}</td>
                      <td className="mono dim">{a.client}</td>
                      <td className="num">{a.queries}</td>
                      <td className="num dim">{a.domains}</td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <div className="sec" style={{ margin: "14px 12px 6px" }}>
                <span>{t("dns.busiest")}{gekozen ? ` · ${gekozen}` : ""}</span>
              </div>
              <table>
                <thead>
                  <tr>
                    <th>{t("col.domain")}</th><th>{t("col.device")}</th>
                    <th className="num">{t("col.count")}</th>
                  </tr>
                </thead>
                <tbody>
                  {top.map((d, i) => (
                    <tr key={`${d.client}-${d.name}-${i}`}>
                      <td className="mono">{d.name}</td>
                      <td className="dim">{d.client}</td>
                      <td className="num" style={{ color: d.count > 100 ? "var(--alert)" : undefined }}>
                        {d.count}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </div>
      </section>

      <aside className="panel">
        <div className="sec" style={{ marginTop: 0, borderTop: 0, paddingTop: 0 }}>
          <span>{t("dns.live")}</span>
        </div>
        {recent.length === 0 ? (
          <p className="dim" style={{ fontSize: 12.5 }}>{t("dns.waiting")}</p>
        ) : (
          <div className="mono" style={{ fontSize: 11.5, lineHeight: 1.7 }}>
            {recent.map((v, i) => (
              <div key={i} style={{ borderBottom: "1px dotted var(--line-soft)", padding: "2px 0" }}>
                <span className="dim">{klok(v.at)}</span>{" "}
                <span style={{ color: "var(--ink)" }}>{v.name}</span>
                <br />
                <span className="dim">{v.client} · {v.type} · {v.rcode}</span>
              </div>
            ))}
          </div>
        )}
      </aside>
    </>
  );
}
