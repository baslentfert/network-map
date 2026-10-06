import {
  createContext, useCallback, useContext, useEffect, useMemo, useState,
} from "react";
import type { ReactNode } from "react";
import * as App from "../../wailsjs/go/main/App";
import type { MsgKey } from "./keys";

export type { MsgKey };

export interface Taal {
  code: string;
  name: string;
}

/** Argumenten voor een tekst met plaatshouders, zoals {name} of {n}. */
export type Args = Record<string, string | number>;

export interface I18n {
  /** t vertaalt een sleutel. Onbekende sleutels vangt TypeScript al af. */
  t: (key: MsgKey, args?: Args) => string;
  taal: string;
  talen: Taal[];
  zetTaal: (code: string) => void;
  /** klaar is false zolang de catalogus nog niet binnen is. */
  klaar: boolean;
}

const Context = createContext<I18n | null>(null);

/**
 * vul vervangt {naam}-plaatshouders. Dezelfde regels als de Go-kant, zodat
 * een tekst in beide werelden identiek uitpakt.
 */
function vul(tekst: string, args?: Args): string {
  if (!args) return tekst;
  let uit = tekst;
  for (const [k, v] of Object.entries(args)) {
    uit = uit.split(`{${k}}`).join(String(v));
  }
  return uit;
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [taal, setTaal] = useState<string>("nl");
  const [talen, setTalen] = useState<Taal[]>([]);
  const [teksten, setTeksten] = useState<Record<string, string>>({});
  const [klaar, setKlaar] = useState(false);

  // De catalogus komt van de backend, niet uit een eigen kopie hier. Zo is
  // er één bron van waarheid voor de UI én voor de logregels die de store
  // aanmaakt.
  const laad = useCallback(async (code: string) => {
    const m = (await App.Teksten(code)) as unknown as Record<string, string>;
    setTeksten(m ?? {});
    setTaal(code);
    setKlaar(true);
  }, []);

  useEffect(() => {
    let levend = true;
    (async () => {
      try {
        const [lijst, status] = await Promise.all([App.Talen(), App.Status()]);
        if (!levend) return;
        setTalen((lijst ?? []) as unknown as Taal[]);
        await laad((status as any)?.lang || "nl");
      } catch {
        if (levend) setKlaar(true); // liever sleutels tonen dan een leeg scherm
      }
    })();
    return () => { levend = false; };
  }, [laad]);

  const zetTaal = useCallback((code: string) => {
    App.SetTaal(code).then((bevestigd: string) => laad(bevestigd || code));
  }, [laad]);

  const waarde = useMemo<I18n>(() => ({
    // Valt een sleutel weg, dan tonen we de sleutel zelf. Dat is lelijk en
    // dus zichtbaar, in plaats van een stille lege knop.
    t: (key: MsgKey, args?: Args) => vul(teksten[key] ?? key, args),
    taal, talen, zetTaal, klaar,
  }), [teksten, taal, talen, zetTaal, klaar]);

  return <Context.Provider value={waarde}>{children}</Context.Provider>;
}

export function useT(): I18n {
  const c = useContext(Context);
  if (!c) throw new Error("useT buiten I18nProvider gebruikt");
  return c;
}

/** Relatieve tijd, in de taal van het moment. */
export function geleden(t: I18n["t"], iso: string): string {
  const d = new Date(iso).getTime();
  if (isNaN(d)) return t("time.unknown");
  const s = Math.max(0, Math.round((Date.now() - d) / 1000));
  if (s < 5) return t("time.now");
  if (s < 60) return t("time.seconds", { n: s });
  if (s < 3600) return t("time.minutes", { n: Math.round(s / 60) });
  if (s < 86400) return t("time.hours", { n: Math.round(s / 3600) });
  return t("time.days", { n: Math.round(s / 86400) });
}
