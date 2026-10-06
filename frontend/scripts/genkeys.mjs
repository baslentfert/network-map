// Genereert een uniontype van alle tekstsleutels uit de catalogus.
//
// De JSON in internal/i18n/locales is de enige bron van waarheid: Go
// embedt hem, de frontend haalt hem op via de backend. Dit script maakt
// daar een TypeScript-type van, zodat een verkeerd gespelde sleutel een
// buildfout is in plaats van een lege knop in de UI.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const hier = dirname(fileURLToPath(import.meta.url));
const bron = resolve(hier, "../../internal/i18n/locales/en.json");
const doel = resolve(hier, "../src/i18n/keys.ts");

const sleutels = Object.keys(JSON.parse(readFileSync(bron, "utf8"))).sort();

const uit = `// GEGENEREERD BESTAND — niet met de hand aanpassen.
// Bron: internal/i18n/locales/en.json
// Opnieuw maken: npm run genkeys (gebeurt automatisch bij dev en build).

export type MsgKey =
${sleutels.map((k) => `  | ${JSON.stringify(k)}`).join("\n")};

export const ALLE_SLEUTELS: readonly MsgKey[] = [
${sleutels.map((k) => `  ${JSON.stringify(k)},`).join("\n")}
] as const;
`;

mkdirSync(dirname(doel), { recursive: true });
writeFileSync(doel, uit, "utf8");
console.log(`keys.ts: ${sleutels.length} sleutels`);
