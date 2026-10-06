import { useCallback, useEffect, useState } from "react";
import * as App from "../wailsjs/go/main/App";
import { useT } from "./i18n";
import type { MsgKey } from "./i18n";

type Bereik = "lokaal" | "netwerk" | "adapter";
type Oordeel = "normaal" | "let op" | "onbekend";

interface Luisteraar {
  proto: string;
  ip: string;
  port: number;
  dualStack: boolean;
  pid: number;
  process: string;
  path: string;
  user: string;
  since: string;
  scope: Bereik;
  service: string;
  explanation: string;
  verdict: Oordeel;
  why: string;
  connections: number;
}

interface Overzicht {
  listeners: Luisteraar[] | null;
  connections: unknown[] | null;
  withoutName: number;
}

// De kleur volgt het oordeel, niet het bereik: amber is "hier moet je
// kijken", en dat is de enige reden om deze lijst te openen.
const OORDEEL_CLASS: Record<Oordeel, string> = {
  "normaal": "s-online",
  "let op": "s-new",
  "onbekend": "s-offline",
};

function adres(l: Luisteraar): string {
  return l.dualStack ? `*:${l.port}` : `${l.ip}:${l.port}`;
}

export default function PortsView() {
  const { t, taal } = useT();
  const [data, setData] = useState<Overzicht | null>(null);
  const [bezig, setBezig] = useState(false);
  const [alleen, setAlleen] = useState(true);
  const [sel, setSel] = useState<Luisteraar | null>(null);
  const [fout, setFout] = useState("");

  const lees = useCallback(async () => {
    setBezig(true);
    try {
      setFout("");
      setData((await App.Ports()) as unknown as Overzicht);
    } catch (e) {
      setFout(String(e));
    } finally {
      setBezig(false);
    }
  }, []);

  // Opnieuw ophalen bij een taalwissel: de uitleg komt vertaald uit de
  // backend, dus die moet mee veranderen.
  useEffect(() => { lees(); }, [lees, taal]);

  const alles = data?.listeners ?? [];
  const netwerk = alles.filter((l) => l.scope === "netwerk").length;
  const lokaal = alles.filter((l) => l.scope === "lokaal").length;
  const letop = alles.filter((l) => l.verdict === "let op").length;
  const onbekend = alles.filter((l) => l.verdict === "onbekend").length;

  const rijen = alleen ? alles.filter((l) => l.verdict !== "normaal") : alles;

  return (
    <>
      <section className="view">
        <div className="scroll">
          <div className="ports-kop">
            <div>
              <h2>{t("ports.title")}</h2>
              <p className="sub">
                {t("ports.summary", { n: alles.length, net: netwerk, local: lokaal })}
                {" · "}
                <b style={{ color: "var(--amber)" }}>{t("ports.attention", { n: letop })}</b>
                {" · "}
                {t("ports.unknownCount", { n: onbekend })}
              </p>
            </div>
            <div className="ports-knoppen">
              <button className="filt" aria-pressed={alleen} onClick={() => setAlleen(!alleen)}>
                {t("ports.onlyNotable")}
              </button>
              <button className="btn" onClick={lees} disabled={bezig}>
                {bezig ? t("btn.busy") : t("ports.refresh")}
              </button>
            </div>
          </div>

          {fout && <p className="note" style={{ color: "var(--alert)", padding: "0 12px" }}>{fout}</p>}

          {!!data?.withoutName && (
            <p className="note" style={{ padding: "0 12px 8px" }}>
              {t("ports.noName", { n: data.withoutName })}
            </p>
          )}

          <table>
            <thead>
              <tr>
                <th>{t("col.verdict")}</th>
                <th>{t("col.ip")}</th>
                <th>{t("col.process")}</th>
                <th>{t("col.service")}</th>
                <th>{t("col.scope")}</th>
                <th className="num">{t("ports.connections", { n: "" }).trim()}</th>
              </tr>
            </thead>
            <tbody>
              {rijen.map((l, i) => (
                <tr
                  key={`${l.proto}-${l.port}-${l.pid}-${i}`}
                  aria-selected={sel?.port === l.port && sel?.proto === l.proto && sel?.pid === l.pid}
                  onClick={() => setSel(l)}
                >
                  <td>
                    <span className={"pill " + OORDEEL_CLASS[l.verdict]}>
                      <i />{t(`verdict.${l.verdict}` as MsgKey)}
                    </span>
                  </td>
                  <td className="mono">{l.proto} {adres(l)}</td>
                  <td className={l.process ? "" : "dim ital"}>
                    {l.process || `? (pid ${l.pid})`}
                  </td>
                  <td>{l.service}</td>
                  <td className={l.scope === "netwerk" ? "" : "dim"}>
                    {t(`scope.${l.scope}` as MsgKey)}
                  </td>
                  <td className="num dim">{l.connections || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {rijen.length === 0 && !bezig && (
            <p className="note" style={{ padding: "16px 12px" }}>{t("ports.empty")}</p>
          )}
        </div>
      </section>

      <aside className="panel">
        {!sel ? (
          <p className="dim" style={{ fontSize: 12.5 }}>{t("panel.empty")}</p>
        ) : (
          <>
            <span className={"pill " + OORDEEL_CLASS[sel.verdict]}>
              <i />{t(`verdict.${sel.verdict}` as MsgKey)}
            </span>
            <h2 style={{ margin: "8px 0 2px", fontSize: 19 }}>{sel.service}</h2>
            <p className="sub">{sel.proto} {adres(sel)} · {t(`scope.${sel.scope}` as MsgKey)}</p>

            <p className="note" style={{ marginTop: 0 }}>{sel.explanation}</p>
            {sel.why && (
              <p className="note" style={{ color: sel.verdict === "normaal" ? undefined : "var(--ink-2)" }}>
                → {sel.why}
              </p>
            )}

            <div className="sec"><span>{t("col.process")}</span></div>
            <dl className="kv">
              <dt>{t("col.process")}</dt>
              <dd>{sel.process || "—"}</dd>
              <dt>{t("panel.pid")}</dt>
              <dd>{sel.pid}</dd>
              {sel.user && (<><dt>{t("kv.kind")}</dt><dd>{sel.user}</dd></>)}
            </dl>
            {sel.path && (
              <>
                <div className="sec"><span>{t("panel.path")}</span></div>
                <p className="note mono" style={{ wordBreak: "break-all" }}>{sel.path}</p>
              </>
            )}
          </>
        )}
      </aside>
    </>
  );
}
