import { useCallback, useEffect, useRef, useState } from "react";
import * as App from "../wailsjs/go/main/App";
import { EventsOn, EventsOff } from "../wailsjs/runtime/runtime";

export type HostStatus = "online" | "new" | "alert" | "offline";
export type Kind = "router" | "ap" | "pc" | "phone" | "tv" | "nas" | "iot" | "unknown";

export interface NameSource {
  value: string;
  origin: string;
}

export interface Port {
  number: number;
  service: string;
}

export interface Host {
  key: string;
  ip: string;
  mac: string;
  vendor: string;
  name: string;
  kind: Kind;
  status: HostStatus;
  names: NameSource[] | null;
  model: string;
  ports: Port[] | null;
  ttl: number;
  osHint: string;
  randomMac: boolean;
  isGateway: boolean;
  isSelf: boolean;
  firstSeen: string;
  lastSeen: string;
  rxBytes: number;
  txBytes: number;
  /** Tekstsleutel plus parameters; de zin ontstaat pas bij het tonen. */
  noteKey: string;
  noteArgs?: Record<string, string>;
}

export interface LogEvent {
  at: string;
  tag: string;
  /** Verwijst naar de tekstcatalogus, bijv. "ev.newDevice". */
  key: string;
  args?: Record<string, string>;
  host: string;
}

export interface Adapter {
  index: number;
  name: string;
  description: string;
  deviceName: string;
  mac: string;
  ip: string;
  prefix: number;
  cidr: string;
  gateway: string;
  dns: string[] | null;
  up: boolean;
  metric: number;
}

/**
 * toonNaam geeft wat er onder een knooppunt hoort te staan.
 *
 * Een modelaanduiding is geen naam — drie Deco's heten alle drie
 * "TP-Link Deco" — dus die komt tussen haakjes. Zo blijft zichtbaar dat
 * het apparaat zelf geen naam prijsgaf en dat je er nog een kunt geven.
 */
export function toonNaam(h: Host): string {
  if (h.name) return h.name;
  if (h.model) return `(${h.model})`;
  return "";
}

export interface AppStatus {
  lang: string;
  adapter: Adapter;
  monitoring: boolean;
  scanning: boolean;
  passive: boolean;
  passiveReason: string;
  capture: boolean;
  captureReason: string;
}

export interface Progress {
  phase: string;
  done: number;
  total: number;
}

/** ipSort zet .9 vóór .10 in plaats van erna. */
export function ipSort(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 4; i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  }
  return a.localeCompare(b);
}

const LEEG_ADAPTER: Adapter = {
  index: 0, name: "", description: "", deviceName: "", mac: "",
  ip: "", prefix: 0, cidr: "", gateway: "", dns: null, up: false, metric: 0,
};

/**
 * useNetwork houdt de kaart bij zoals de backend hem ziet.
 *
 * De volledige toestand komt één keer binnen via Graph(); daarna stuurt de
 * store alleen nog de verandering. Zo blijft het scherm meelopen met de
 * scan zonder dat we periodiek de hele boel opnieuw ophalen.
 */
export function useNetwork() {
  const [hosts, setHosts] = useState<Record<string, Host>>({});
  const [events, setEvents] = useState<LogEvent[]>([]);
  const [status, setStatus] = useState<AppStatus>({
    lang: "nl", adapter: LEEG_ADAPTER, monitoring: false, scanning: false,
    passive: false, passiveReason: "", capture: false, captureReason: "",
  });
  const [progress, setProgress] = useState<Progress>({ phase: "", done: 0, total: 0 });
  const [error, setError] = useState("");

  // De laatste 400 regels zijn genoeg voor het scherm; de backend bewaart
  // er meer voor wie terugbladert.
  const logCap = useRef(400);

  const upsert = useCallback((h: Host) => {
    setHosts((prev) => ({ ...prev, [h.key]: h }));
  }, []);

  useEffect(() => {
    let levend = true;

    Promise.all([App.Graph(), App.Events(), App.Status()])
      .then(([g, evs, st]: any[]) => {
        if (!levend) return;
        const map: Record<string, Host> = {};
        for (const h of (g?.hosts ?? []) as Host[]) map[h.key] = h;
        setHosts(map);
        setEvents((evs ?? []) as LogEvent[]);
        setStatus(st as AppStatus);
      })
      .catch((e) => levend && setError(String(e)));

    EventsOn("host:new", (h: Host) => upsert(h));
    EventsOn("host:update", (h: Host) => upsert(h));
    EventsOn("host:remove", (key: string) => {
      setHosts((prev) => {
        if (!(key in prev)) return prev;
        const next = { ...prev };
        delete next[key];
        return next;
      });
    });
    EventsOn("log", (e: LogEvent) => {
      setEvents((prev) => {
        const next = prev.length >= logCap.current ? prev.slice(1) : prev.slice();
        next.push(e);
        return next;
      });
    });
    EventsOn("scan:progress", (p: Progress) => setProgress(p));
    EventsOn("status", (s: AppStatus) => setStatus(s));

    return () => {
      levend = false;
      for (const naam of ["host:new", "host:update", "host:remove", "log", "scan:progress", "status"]) {
        EventsOff(naam);
      }
    };
  }, [upsert]);

  const run = useCallback(async (fn: () => Promise<unknown>) => {
    try {
      setError("");
      await fn();
    } catch (e) {
      setError(String(e));
    }
  }, []);

  const acties = {
    scan: (spec: string) => run(() => App.ScanNow(spec)),
    scanHost: (ip: string, spec: string) => run(() => App.ScanHost(ip, spec)),
    start: (spec: string) => run(() => App.StartMonitor(spec)),
    stop: () => run(() => App.StopMonitor()),
    setAlias: (key: string, naam: string) => run(() => App.SetAlias(key, naam)),
    selectAdapter: (naam: string) => run(() => App.SelectInterface(naam)),
    adapters: () => App.Interfaces() as unknown as Promise<Adapter[]>,
  };

  return { hosts, events, status, progress, error, setError, ...acties };
}
