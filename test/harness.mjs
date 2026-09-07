// Headless-Chromium harness — serves this viewer with the *real* security
// headers (incl. CSP) from `_headers` and drives index.html, per the dev
// standards (§15). Exit 1 on any failure.
import { chromium } from "playwright";
import http from "node:http";
import { readFileSync, existsSync, statSync, mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { crc32 } from "node:zlib";

const ROOT = process.cwd();
const PORT = Number(process.env.PORT) || 8099;

const H = {};
for (const line of readFileSync(join(ROOT, "_headers"), "utf8").split("\n")) {
  const m = line.match(/^[ \t]+([A-Za-z0-9-]+):[ \t]*(.+?)\s*$/);
  if (m && !line.trim().startsWith("#")) H[m[1]] = m[2];
}
if (!H["Content-Security-Policy"]) {
  console.error("FAIL: no Content-Security-Policy found in _headers");
  process.exit(1);
}

const MIME = {
  ".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript",
  ".json": "application/json", ".webmanifest": "application/manifest+json",
  ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon",
  ".woff2": "font/woff2", ".xml": "application/xml", ".txt": "text/plain",
};
const mime = (p) => MIME[p.slice(p.lastIndexOf("."))] || "application/octet-stream";

const server = http.createServer((req, res) => {
  let p = decodeURIComponent((req.url || "/").split("?")[0]);
  if (p.endsWith("/")) p += "index.html";
  let fp = join(ROOT, p);
  if (!fp.startsWith(ROOT) || !existsSync(fp)) fp = join(ROOT, "index.html");
  try {
    res.writeHead(200, { ...H, "Content-Type": mime(fp) });
    res.end(readFileSync(fp));
  } catch (e) { res.writeHead(500); res.end(String(e)); }
});
await new Promise((r) => server.listen(PORT, r));

const browser = await chromium.launch(
  process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}
);
const results = [];
const check = (name, ok, detail) => results.push([name, !!ok, detail]);
const errs = [];
const hook = (page) => {
  page.on("console", (m) => { if (m.type() === "error") errs.push(m.text()); });
  page.on("pageerror", (e) => errs.push(String(e)));
};

// openEpub(buf, name) calls syncQueryName(name) before it ever tries
// JSZip.loadAsync(), so a fixture that fails to unzip (caught inside the
// promise chain, which shows an honest toast) still exercises the ?name=
// write path -- this does NOT need to be a real, valid EPUB.
const FIX = mkdtempSync(join(tmpdir(), "epub-harness-"));
const FIXTURE_EPUB = join(FIX, "sample.epub");
writeFileSync(FIXTURE_EPUB, "not a real epub");

// -- Hostile EPUB fixture for the DOMPurify pass in renderChapter().
// Built here rather than committed as a binary so the payloads stay readable
// in review: a security fixture nobody can inspect is a poor security fixture.
// Store-only ZIP (method 0) — no compression, so the writer is ~30 lines and
// JSZip reads it fine.
const zipStore = (entries) => {
  const locals = [], central = [];
  let off = 0;
  for (const [name, body] of entries) {
    const nb = Buffer.from(name, "utf8");
    const db = Buffer.isBuffer(body) ? body : Buffer.from(body, "utf8");
    const crc = crc32(db);
    const lf = Buffer.alloc(30);
    lf.writeUInt32LE(0x04034b50, 0); lf.writeUInt16LE(20, 4); lf.writeUInt16LE(0, 6);
    lf.writeUInt16LE(0, 8); lf.writeUInt16LE(0, 10); lf.writeUInt16LE(0, 12);
    lf.writeUInt32LE(crc, 14); lf.writeUInt32LE(db.length, 18); lf.writeUInt32LE(db.length, 22);
    lf.writeUInt16LE(nb.length, 26); lf.writeUInt16LE(0, 28);
    locals.push(lf, nb, db);
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(20, 4); cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(0, 8); cd.writeUInt16LE(0, 10); cd.writeUInt16LE(0, 12); cd.writeUInt16LE(0, 14);
    cd.writeUInt32LE(crc, 16); cd.writeUInt32LE(db.length, 20); cd.writeUInt32LE(db.length, 24);
    cd.writeUInt16LE(nb.length, 28); cd.writeUInt16LE(0, 30); cd.writeUInt16LE(0, 32);
    cd.writeUInt16LE(0, 34); cd.writeUInt16LE(0, 36); cd.writeUInt32LE(0, 38);
    cd.writeUInt32LE(off, 42);
    central.push(cd, nb);
    off += lf.length + nb.length + db.length;
  }
  const cdBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8); eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12); eocd.writeUInt32LE(off, 16);
  return Buffer.concat([Buffer.concat(locals), cdBuf, eocd]);
};

const HOSTILE_CHAPTER = `<?xml version="1.0" encoding="utf-8"?>
<html xmlns="http://www.w3.org/1999/xhtml"><head><title>Ch1</title></head><body>
<h1 id="ok-heading">Chapter One</h1>
<script>window.__xssScript = true;<\/script>
<img id="x-onerror" src="missing.png" onerror="window.__xssImg = true"/>
<a id="x-js" href="javascript:void(window.__xssHref = true)">js link</a>
<iframe id="x-frame" src="about:blank"></iframe>
<p id="x-click" onclick="window.__xssClick = true">handler</p>
<style id="x-style">body{color:red}</style>
<form id="x-form"><input id="x-input"/><button id="x-button">go</button></form>
<p id="x-styled" style="color:red">styled</p>
<img id="x-remote" src="https://example.com/beacon.png"/>
<img id="x-srcset" src="data:image/gif;base64,R0lGODlhAQABAAAAACw=" srcset="https://example.com/b.png 1x"/>
<img id="x-data" src="data:image/gif;base64,R0lGODlhAQABAAAAACw="/>
</body></html>`;

const HOSTILE_EPUB = join(FIX, "hostile.epub");
writeFileSync(HOSTILE_EPUB, zipStore([
  ["mimetype", "application/epub+zip"],
  ["META-INF/container.xml",
   `<?xml version="1.0"?><container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
    <rootfiles><rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/></rootfiles></container>`],
  ["OEBPS/content.opf",
   `<?xml version="1.0"?><package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="id">
    <metadata xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>Hostile Fixture</dc:title>
    <dc:creator>Harness</dc:creator><dc:identifier id="id">urn:uuid:test</dc:identifier></metadata>
    <manifest><item id="c1" href="ch1.xhtml" media-type="application/xhtml+xml"/></manifest>
    <spine><itemref idref="c1"/></spine></package>`],
  ["OEBPS/ch1.xhtml", HOSTILE_CHAPTER],
]));

// -- main context: light system scheme, full toggle round-trip
const ctx = await browser.newContext({ colorScheme: "light", viewport: { width: 1240, height: 800 } });
const page = await ctx.newPage();
hook(page);
await page.goto(`http://localhost:${PORT}/`, { waitUntil: "load", timeout: 30000 });
await page.evaluate(() => document.fonts.ready);
check("font loads under CSP", await page.evaluate(() => [...document.fonts].some((f) => f.family.includes("JetBrains"))));
check("heading uses JetBrains Mono", await page.evaluate(() => {
  const el = document.querySelector(".doc-title") || document.querySelector(".empty-title");
  return el && getComputedStyle(el).fontFamily.includes("JetBrains Mono");
}));
check("light default with light system scheme", await page.evaluate(() => document.getElementById("bgPicker").value) === "#ffffff");
check("toggle present in toolbar", await page.evaluate(() => {
  const t = document.getElementById("themeToggle");
  return !!t && t.hasAttribute("aria-pressed") && !!t.closest("nav.actions");
}));
check("icons in light mode (sun shown, moon hidden)", await page.evaluate(() => {
  const s = document.getElementById("themeIconSun"), m = document.getElementById("themeIconMoon");
  return !s.hasAttribute("hidden") && m.hasAttribute("hidden");
}));
await page.click("#themeToggle");
check("toggle to dark sets picker #0d1117", await page.evaluate(() => document.getElementById("bgPicker").value) === "#0d1117");
check("aria-pressed true in dark", await page.getAttribute("#themeToggle", "aria-pressed") === "true");
check("icons in dark mode (moon shown, sun hidden)", await page.evaluate(() => {
  const s = document.getElementById("themeIconSun"), m = document.getElementById("themeIconMoon");
  const moonVisible = !m.hasAttribute("hidden") && getComputedStyle(m).display !== "none";
  const sunHidden = s.hasAttribute("hidden") || getComputedStyle(s).display === "none";
  return moonVisible && sunHidden;
}));
check("choice persists (mykk-bg)", await page.evaluate(() => { try { return localStorage.getItem("mykk-bg") === "#0d1117"; } catch (e) { return false; } }));
await page.click("#themeToggle");
check("toggle back to light", await page.evaluate(() => document.getElementById("bgPicker").value) === "#ffffff");

// -- ?name=: loading a file reflects its name into the URL, Clear removes it
await page.setInputFiles("#fileInput", FIXTURE_EPUB);
await page.waitForFunction(() =>
  new URLSearchParams(location.search).get("name") === "sample.epub", null, { timeout: 10000 });
check("load: URL reflects ?name=sample.epub", await page.evaluate(() =>
  new URLSearchParams(location.search).get("name")) === "sample.epub");
await page.click("#btnClear");
check("clear: ?name= removed from the URL", await page.evaluate(() =>
  new URLSearchParams(location.search).get("name")) === null);
await ctx.close();

// -- direct visit with ?name=: empty-state names the last-viewed file
const p3 = await browser.newContext().then((c) => c.newPage());
hook(p3);
await p3.goto(`http://localhost:${PORT}/?name=${encodeURIComponent("sample.epub")}`, { waitUntil: "load", timeout: 30000 });
check("?name=: 'shared for' sub-line names the file", await p3.evaluate(() =>
  /shared for/.test(document.querySelector(".empty-sub").textContent) &&
  /sample\.epub/.test(document.querySelector(".empty-sub").textContent)));
await p3.context().close();

// -- ?name= carrying markup renders as TEXT, never parsed as HTML
const p4 = await browser.newContext().then((c) => c.newPage());
hook(p4);
const HOSTILE_NAME = "<img src=x onerror=alert(1)>.epub";
await p4.goto(`http://localhost:${PORT}/?name=${encodeURIComponent(HOSTILE_NAME)}`, { waitUntil: "load", timeout: 30000 });
check("?name=: hostile markup shows as literal text, never parsed", await p4.evaluate((name) => {
  const sub = document.querySelector(".empty-sub");
  return sub.textContent.includes(name) && sub.querySelector("img") === null;
}, HOSTILE_NAME));
await p4.context().close();

// -- fresh context with dark system scheme: must default dark
const ctx2 = await browser.newContext({ colorScheme: "dark" });
const p2 = await ctx2.newPage();
hook(p2);
await p2.goto(`http://localhost:${PORT}/`, { waitUntil: "load", timeout: 30000 });
check("system-dark default (#0d1117)", await p2.evaluate(() => document.getElementById("bgPicker").value) === "#0d1117");
await ctx2.close();

// -- the document sink: DOMParser -> DOMPurify -> #content, in renderChapter().
// Distinct from the ?name= sink above, which lands in .empty-sub and is NOT
// sanitized. Every assertion here is written to fail when DOMPurify is removed
// -- but this repo fails in the OPPOSITE direction from markdown-viewer.us:
// its sanitize() call is a ternary whose else-branch is "", so a missing
// DOMPurify renders NOTHING rather than rendering unsanitized. That makes every
// "hostile element is absent" assertion pass vacuously, and the two POSITIVE
// assertions -- the heading guard and the data: image -- are the only things
// that catch it. They are the load-bearing checks here.
const ctxX = await browser.newContext();
const px = await ctxX.newPage();
hook(px);
await px.goto(`http://localhost:${PORT}/`, { waitUntil: "load", timeout: 30000 });
await px.setInputFiles("#fileInput", HOSTILE_EPUB);
await px.waitForFunction(() => {
  const c = document.getElementById("content");
  return c && c.querySelector("#ok-heading");
}, null, { timeout: 15000 }).catch(() => {});

check("hostile book actually rendered (chapter heading present)", await px.evaluate(() =>
  !!document.getElementById("content").querySelector("#ok-heading")));

check("sanitizer: <script> element does not survive", await px.evaluate(() =>
  document.getElementById("content").querySelector("script") === null));
check("sanitizer: no onerror/onclick handler attribute survives", await px.evaluate(() => {
  const c = document.getElementById("content");
  return c.querySelector("[onerror]") === null && c.querySelector("[onclick]") === null;
}));
check("sanitizer: javascript: href does not survive", await px.evaluate(() => {
  const a = document.getElementById("content").querySelector("#x-js");
  return !a || !/^javascript:/i.test(a.getAttribute("href") || "");
}));
check("sanitizer: <iframe> does not survive", await px.evaluate(() =>
  document.getElementById("content").querySelector("iframe") === null));

// FORBID_TAGS / FORBID_ATTR are this repo's own config and differ from
// markdown-viewer.us's, so they get assertions of their own.
check("config: FORBID_TAGS strips style/form/input/button", await px.evaluate(() => {
  const c = document.getElementById("content");
  return ["style", "form", "input", "button"].every((t) => c.querySelector(t) === null);
}));
check("config: FORBID_ATTR strips style attributes", await px.evaluate(() =>
  document.getElementById("content").querySelector("[style]") === null));

// The uponSanitizeAttribute hook added in #1: remote resources must be stripped
// before they reach the DOM, so a book cannot phone home just by being opened.
check("hook: remote img src is stripped", await px.evaluate(() => {
  const i = document.getElementById("content").querySelector("#x-remote");
  return !i || !/^https?:/i.test(i.getAttribute("src") || "");
}));
check("hook: srcset is stripped entirely", await px.evaluate(() =>
  document.getElementById("content").querySelector("[srcset]") === null));
// POSITIVE: a data: image is allowed through -- the second assertion a
// render-nothing failure cannot satisfy.
check("hook: data: img src is preserved (not over-stripped)", await px.evaluate(() => {
  const i = document.getElementById("content").querySelector("#x-data");
  return !!i && /^data:image\/gif/.test(i.getAttribute("src") || "");
}));

await px.waitForTimeout(300);
check("sanitizer: img onerror did not fire", await px.evaluate(() => window.__xssImg !== true));
await ctxX.close();

// -- static assertions
const sz = (p) => (existsSync(join(ROOT, p)) ? statSync(join(ROOT, p)).size : 0);
check("fonts present", sz("fonts/JetBrainsMono-Bold.subset.woff2") > 10000 && sz("fonts/JetBrainsMono-ExtraBold.subset.woff2") > 10000 && sz("fonts/OFL.txt") > 0);
check("favicon.ico present", sz("favicon.ico") > 2000);
check("site.webmanifest valid", (() => { try { return !!JSON.parse(readFileSync(join(ROOT, "site.webmanifest"), "utf8")).name; } catch (e) { return false; } })());
check("llms/ads/security.txt present", sz("llms.txt") > 0 && sz("ads.txt") > 0 && sz(".well-known/security.txt") > 0);
const csp = H["Content-Security-Policy"];
check("CSP allows self fonts + manifest", /font-src[^;]*'self'/.test(csp) && /manifest-src 'self'/.test(csp));
const idx = readFileSync(join(ROOT, "index.html"), "utf8");
check("head links (manifest + favicon.ico)", idx.includes('rel="manifest"') && idx.includes("/favicon.ico"));

// External-resource network noise (analytics offline) is allowed; CSP
// violations are worded "Refused to ..." and still fail.
const ALLOW = [/plausible/i, /thompsonblack/i, /net::ERR/i, /Failed to load resource/i];
const real = errs.filter((e) => !ALLOW.some((re) => re.test(e)));
check("no unexpected console/CSP errors", real.length === 0, real[0]);

await browser.close();
server.close();

let failed = 0;
for (const [name, ok, detail] of results) {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${!ok && detail ? "  — " + String(detail).slice(0, 160) : ""}`);
  if (!ok) failed++;
}
console.log(`\n${results.length - failed}/${results.length} checks passed`);
process.exit(failed ? 1 : 0);
