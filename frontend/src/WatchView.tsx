import { useCallback, useEffect, useState } from "react";
import * as App from "../wailsjs/go/main/App";
import { useT, geleden } from "./i18n";
import type { MsgKey } from "./i18n";

type Ernst = "let op" | "info";

interface Bevinding {
  kind: string;
  key: string;
  args: Record<string, string> | null;
  host: string;
  severity: Ernst;
  at: string;
}

interface Info {
  devices: number;
  updated: string;
  empty: boolean;
}

const ERNST_CLASS: Record<Ernst, string> = { "let op": "s-new", info: "s-offline" };

export default function WatchView() {
  const { t, taal } = useT();
  const [bevindingen, setBevindingen] = useState<Bevinding[]>([]);
  const [info, setInfo] = useState<Info | null>(null);
  const [bezig, setBezig] = useState(false);
  const [fout, setFout] = useState("");

  const ververs = useCallback(async () => {
    try {
      const [b, i] = await Promise.all([App.Findings(), App.BaselineInfo()]);
      setBevindingen(((b ?? []) as unknown) as Bevinding[]);
      setInfo(i as unknown as Info);
    } catch (e) {
      setFout(String(e));
    }
  }, []);

  useEffect(() => {
    ververs();
    const id = setInterval(ververs, 4000);
    return () => clearInterval(id);
  }, [ververs, taal]);

  const leer = async () => {
    setBezig(true);
    setFout("");
    try {
      await App.LearnBaseline();
      await ververs();
    } catch (e) {
      setFout(String(e));
    } finally {
      setBezig(false);
    }
  };

  const vergeet = async (key: string) => {
    try {
      await App.ForgetDevice(key);
      await ververs();
    } catch (e) {
      setFout(String(e));
    }
  };

  const letop = bevindingen.filter((b) => b.severity === "let op").length;

  return (
    <>
      <section className="view">
        <div className="scroll">
          <div className="ports-kop">
            <div>
              <h2>{t("watch.title")}</h2>
              <p className="sub">
                {info?.empty
                  ? t("watch.empty")
                  : t("watch.learned", {
                      n: info?.devices ?? 0,
                      when: info ? geleden(t, info.updated) : "",
                    })}
              </p>
            </div>
            <div className="ports-knoppen">
              <button className="btn primary" onClick={leer} disabled={bezig}>
                {bezig ? t("btn.busy") : t("watch.learn")}
              </button>
            </div>
          </div>

          <p className="note" style={{ padding: "10px 12px 0" }}>{t("watch.intro")}</p>
          {fout && <p className="note" style={{ color: "var(--alert)", padding: "0 12px" }}>{fout}</p>}

          {bevindingen.length === 0 ? (
            <p className="note" style={{ padding: "16px 12px", color: "var(--online)" }}>
              {info?.empty ? t("watch.empty") : t("watch.none")}
            </p>
          ) : (
            <>
              <div className="sec" style={{ margin: "12px 12px 6px" }}>
                <span>
                  {t("watch.findings", { n: bevindingen.length })}
                  {letop > 0 && ` · ${t("severity.let op")}: ${letop}`}
                </span>
              </div>
              <table>
                <thead>
                  <tr>
                    <th>{t("col.verdict")}</th>
                    <th>{t("col.event")}</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {bevindingen.map((b, i) => (
                    <tr key={`${b.kind}-${b.host}-${i}`}>
                      <td>
                        <span className={"pill " + ERNST_CLASS[b.severity]}>
                          <i />{t(`severity.${b.severity}` as MsgKey)}
                        </span>
                      </td>
                      <td>{t(b.key as MsgKey, b.args ?? undefined)}</td>
                      <td className="num">
                        {b.kind === "verdwenen" && (
                          <button
                            className="filt"
                            onClick={(e) => { e.stopPropagation(); vergeet(b.host); }}
                          >
                            {t("btn.close")}
                          </button>
                        )}
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
          <span>{t("watch.title")}</span>
        </div>
        <p className="note">{t("watch.hint")}</p>
        <div className="sec"><span>{t("watch.learn")}</span></div>
        <p className="note">{t("watch.intro")}</p>
      </aside>
    </>
  );
}
