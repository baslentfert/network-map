import { useEffect, useRef } from "react";
import type { Host, Kind } from "./net";

interface Props {
  hosts: Host[];
  subnet: string;
  selected: string | null;
  onSelect: (key: string) => void;
  naamVan: (h: Host) => string;
}

interface Node {
  key: string;
  host: Host;
  x: number; y: number;
  vx: number; vy: number;
  r: number;
  puls: number;
}

/** Kleuren komen uit de stylesheet, zodat canvas en DOM niet uit elkaar lopen. */
function tokens() {
  const s = getComputedStyle(document.documentElement);
  const g = (n: string) => s.getPropertyValue("--" + n).trim();
  return {
    ink: g("ink"), ink2: g("ink-2"), muted: g("muted"),
    raised: g("raised"), line: g("line"), edge: g("edge"),
    online: g("online"), amber: g("amber"), alert: g("alert"), offline: g("offline"),
  };
}

function statusKleur(t: ReturnType<typeof tokens>, s: string) {
  return s === "online" ? t.online : s === "new" ? t.amber : s === "alert" ? t.alert : t.offline;
}

/** Straal groeit met het verkeersvolume, zodat drukke apparaten opvallen. */
function straal(h: Host): number {
  if (h.isGateway) return 21;
  if (h.kind === "ap") return 15;
  const kb = (h.rxBytes + h.txBytes) / 1024;
  return 12 + Math.min(7, Math.sqrt(kb) / 2.6);
}

/** Vormglyphs, zodat het soort apparaat ook zonder kleur leesbaar is. */
function glyph(ctx: CanvasRenderingContext2D, k: Kind, x: number, y: number, s: number, col: string) {
  ctx.strokeStyle = col;
  ctx.fillStyle = col;
  ctx.lineWidth = 1.4;
  ctx.lineCap = "round";
  ctx.beginPath();

  if (k === "router" || k === "ap") {
    const ringen = k === "router" ? 3 : 2;
    for (let i = 1; i <= ringen; i++) {
      ctx.moveTo(x + i * s * 0.34, y + s * 0.2);
      ctx.arc(x, y + s * 0.2, i * s * 0.34, -Math.PI * 0.78, -Math.PI * 0.22);
    }
    ctx.stroke();
    ctx.beginPath();
    ctx.arc(x, y + s * 0.2, s * 0.13, 0, 7);
    ctx.fill();
    return;
  }
  if (k === "pc") {
    ctx.rect(x - s * 0.6, y - s * 0.5, s * 1.2, s * 0.8);
    ctx.moveTo(x - s * 0.3, y + s * 0.55);
    ctx.lineTo(x + s * 0.3, y + s * 0.55);
    ctx.stroke();
    return;
  }
  if (k === "phone") {
    ctx.rect(x - s * 0.34, y - s * 0.62, s * 0.68, s * 1.24);
    ctx.stroke();
    ctx.beginPath();
    ctx.arc(x, y + s * 0.42, s * 0.08, 0, 7);
    ctx.fill();
    return;
  }
  if (k === "tv") {
    ctx.rect(x - s * 0.68, y - s * 0.5, s * 1.36, s * 0.9);
    ctx.moveTo(x - s * 0.26, y + s * 0.62);
    ctx.lineTo(x + s * 0.26, y + s * 0.62);
    ctx.stroke();
    return;
  }
  if (k === "nas") {
    for (let j = -1; j <= 1; j++) ctx.rect(x - s * 0.55, y + j * s * 0.4 - s * 0.16, s * 1.1, s * 0.3);
    ctx.stroke();
    return;
  }
  if (k === "iot") {
    ctx.arc(x, y, s * 0.5, 0, 7);
    ctx.stroke();
    ctx.beginPath();
    ctx.arc(x, y, s * 0.16, 0, 7);
    ctx.fill();
    return;
  }
  ctx.font = `600 ${s * 1.25}px "Saira Condensed", sans-serif`;
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText("?", x, y + 1);
}

export default function NetworkMap({ hosts, subnet, selected, onSelect, naamVan }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const nodesRef = useRef<Map<string, Node>>(new Map());
  const hoverRef = useRef<string | null>(null);
  const selRef = useRef(selected);
  const naamRef = useRef(naamVan);
  const subnetRef = useRef(subnet);

  selRef.current = selected;
  naamRef.current = naamVan;
  subnetRef.current = subnet;

  // Nieuwe hosts krijgen een plek op een ring; bestaande houden hun positie,
  // zodat de kaart niet opnieuw opschudt bij elke update.
  useEffect(() => {
    const map = nodesRef.current;
    const gezien = new Set<string>();
    hosts.forEach((h, i) => {
      gezien.add(h.key);
      const bestaand = map.get(h.key);
      if (bestaand) {
        bestaand.host = h;
        bestaand.r = straal(h);
        return;
      }
      const hoek = (i / Math.max(1, hosts.length)) * Math.PI * 2;
      map.set(h.key, {
        key: h.key, host: h,
        x: h.isGateway ? 0 : Math.cos(hoek) * 170,
        y: h.isGateway ? 0 : Math.sin(hoek) * 140,
        vx: 0, vy: 0, r: straal(h), puls: Math.random() * 6,
      });
    });
    for (const k of Array.from(map.keys())) if (!gezien.has(k)) map.delete(k);
  }, [hosts]);

  useEffect(() => {
    const cv = canvasRef.current;
    if (!cv) return;
    const ctx = cv.getContext("2d");
    if (!ctx) return;

    let W = 0, H = 0, frame = 0, t = 0;
    let T = tokens();

    const meet = () => {
      const ouder = cv.parentElement;
      if (!ouder) return;
      const r = ouder.getBoundingClientRect();
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      W = r.width; H = r.height;
      cv.width = Math.max(1, W * dpr);
      cv.height = Math.max(1, H * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    const ro = new ResizeObserver(meet);
    if (cv.parentElement) ro.observe(cv.parentElement);
    meet();

    const stap = () => {
      const ns = Array.from(nodesRef.current.values());
      for (let a = 0; a < ns.length; a++) {
        for (let b = a + 1; b < ns.length; b++) {
          const A = ns[a], B = ns[b];
          const dx = B.x - A.x, dy = B.y - A.y;
          const d2 = dx * dx + dy * dy || 0.01;
          const d = Math.sqrt(d2);
          let f = 2600 / d2;
          if (d < A.r + B.r + 22) f += 2.4;
          const ux = dx / d, uy = dy / d;
          A.vx -= ux * f; A.vy -= uy * f;
          B.vx += ux * f; B.vy += uy * f;
        }
      }
      // Elke host hangt aan de gateway. Dat is de enige verbinding die we
      // kunnen onderbouwen: wat er tussen zit — switches, mesh-satellieten
      // als bridge — is op deze laag onzichtbaar.
      const gw = ns.find((n) => n.host.isGateway);
      if (gw) {
        for (const n of ns) {
          if (n === gw) continue;
          const dx = n.x - gw.x, dy = n.y - gw.y;
          const d = Math.hypot(dx, dy) || 0.01;
          const rust = n.host.kind === "ap" ? 108 : 172;
          const f = (d - rust) * 0.011;
          const ux = dx / d, uy = dy / d;
          gw.vx += ux * f; gw.vy += uy * f;
          n.vx -= ux * f; n.vy -= uy * f;
        }
      }
      for (const n of ns) {
        n.vx += -n.x * 0.0016;
        n.vy += -n.y * 0.0016;
        n.vx *= 0.86; n.vy *= 0.86;
        n.x += n.vx; n.y += n.vy;
        n.puls += 0.026;
      }
      if (gw) { gw.x *= 0.6; gw.y *= 0.6; }
    };

    const teken = () => {
      t++;
      if (t % 240 === 1) T = tokens();
      stap();
      ctx.clearRect(0, 0, W, H);

      const cx = W / 2, cy = H / 2 - 6;
      const ns = Array.from(nodesRef.current.values());

      ctx.setLineDash([3, 7]);
      ctx.strokeStyle = T.line;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(cx, cy, Math.min(W, H) * 0.43, 0, 7);
      ctx.stroke();
      ctx.setLineDash([]);

      ctx.fillStyle = T.muted;
      ctx.font = '500 10px "IBM Plex Mono", monospace';
      ctx.textAlign = "left";
      ctx.textBaseline = "alphabetic";
      ctx.fillText(subnetRef.current || "", 14, 20);

      const gw = ns.find((n) => n.host.isGateway);
      if (gw) {
        for (const n of ns) {
          if (n === gw) continue;
          const uit = n.host.status === "offline";
          ctx.strokeStyle = uit ? T.line : T.edge;
          ctx.lineWidth = n.host.kind === "ap" ? 2 : 1;
          if (uit) ctx.setLineDash([2, 5]);
          ctx.beginPath();
          ctx.moveTo(cx + gw.x, cy + gw.y);
          ctx.lineTo(cx + n.x, cy + n.y);
          ctx.stroke();
          ctx.setLineDash([]);
        }
      }

      for (const n of ns) {
        const x = cx + n.x, y = cy + n.y;
        const col = statusKleur(T, n.host.status);
        const actief = n.host.status === "new" || n.host.status === "alert";

        if (actief) {
          ctx.strokeStyle = col;
          ctx.globalAlpha = 0.32;
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.arc(x, y, n.r + 6 + Math.sin(n.puls) * 4, 0, 7);
          ctx.stroke();
          ctx.globalAlpha = 1;
        }

        ctx.fillStyle = T.raised;
        ctx.beginPath();
        ctx.arc(x, y, n.r, 0, 7);
        ctx.fill();

        const uitgelicht = selRef.current === n.key || hoverRef.current === n.key;
        ctx.strokeStyle = col;
        ctx.lineWidth = uitgelicht ? 2.4 : 1.6;
        ctx.beginPath();
        ctx.arc(x, y, n.r, 0, 7);
        ctx.stroke();

        if (n.host.isSelf) {
          ctx.setLineDash([2, 3]);
          ctx.strokeStyle = T.muted;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.arc(x, y, n.r + 4, 0, 7);
          ctx.stroke();
          ctx.setLineDash([]);
        }

        glyph(ctx, n.host.kind, x, y, n.r * 0.62, n.host.status === "offline" ? T.offline : T.ink2);

        ctx.textAlign = "center";
        ctx.textBaseline = "top";
        const naam = naamRef.current(n.host);
        ctx.fillStyle = naam ? (uitgelicht ? T.ink : T.ink2) : T.muted;
        ctx.font = '600 11px "Saira Condensed", sans-serif';
        ctx.fillText(naam || "." + n.host.ip.split(".").pop(), x, y + n.r + 5);

        ctx.fillStyle = T.muted;
        ctx.font = '400 9.5px "IBM Plex Mono", monospace';
        ctx.fillText(n.host.ip, x, y + n.r + 18);
      }

      frame = requestAnimationFrame(teken);
    };
    frame = requestAnimationFrame(teken);

    const raak = (e: MouseEvent): string | null => {
      const r = cv.getBoundingClientRect();
      const mx = e.clientX - r.left - W / 2;
      const my = e.clientY - r.top - (H / 2 - 6);
      let hit: string | null = null;
      for (const n of nodesRef.current.values()) {
        if (Math.hypot(mx - n.x, my - n.y) <= n.r + 6) hit = n.key;
      }
      return hit;
    };
    const onMove = (e: MouseEvent) => {
      hoverRef.current = raak(e);
      cv.style.cursor = hoverRef.current ? "pointer" : "grab";
    };
    const onClick = (e: MouseEvent) => {
      const k = raak(e);
      if (k) onSelect(k);
    };
    cv.addEventListener("mousemove", onMove);
    cv.addEventListener("click", onClick);

    return () => {
      cancelAnimationFrame(frame);
      ro.disconnect();
      cv.removeEventListener("mousemove", onMove);
      cv.removeEventListener("click", onClick);
    };
  }, [onSelect]);

  return <canvas id="map" ref={canvasRef} />;
}
