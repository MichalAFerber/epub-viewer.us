(function(){
  "use strict";
  var doc = document, root = doc.documentElement, body = doc.body;
  var content     = doc.getElementById("content");
  var empty       = doc.getElementById("empty");
  var fileInput   = doc.getElementById("fileInput");
  var overlay     = doc.getElementById("dropOverlay");
  var toastEl     = doc.getElementById("toast");
  var docTitle    = doc.getElementById("docTitle");
    var brandIcon   = doc.getElementById("brandIcon");
    (function(){ var fl = doc.querySelector('link[rel="icon"]'); if (brandIcon && fl) brandIcon.src = fl.href; })();
  var hoverZone   = doc.getElementById("hoverZone");
  var bgPicker    = doc.getElementById("bgPicker");
  var themeColor  = doc.getElementById("themeColor");
  var tocPanel    = doc.getElementById("tocPanel");
  var tocList     = doc.getElementById("tocList");
  var scrim       = doc.getElementById("scrim");
  var chapNav     = doc.getElementById("chapNav");
  var btnPrev     = doc.getElementById("btnPrev");
  var btnNext     = doc.getElementById("btnNext");
  var chapPos     = doc.getElementById("chapPos");
  var btnToc      = doc.getElementById("btnToc");
  var toastTimer  = null;
  var BASE_TITLE  = "EPUB Viewer";
  var ACCEPT_EXT  = [".epub"];   // this viewer only opens EPUB books
  var XLINK_NS    = "http://www.w3.org/1999/xlink";

  var book = null;        // { zf, title, author, spine, spineIdx, manifest, byPath, toc }
  var current = -1;       // index into book.spine
  var blobUrls = {};      // zip path -> object URL (revoked on clear)
  var chapterSeq = 0;     // guards against stale async chapter loads
  var bookSeq = 0;        // bumped on clear/new-open; guards stale TOC loads
  var currentName = "";   // the raw uploaded filename -- this viewer otherwise
                          // displays book.title/author, never the filename itself

  // Reflect the loaded file's name into the URL (?name=), so a bookmarked or
  // shared link says what was being viewed. history.replaceState only, and
  // URLSearchParams does its own percent-encoding — this never touches the
  // DOM, so it carries no XSS risk on its own. The value becomes untrusted
  // input again the moment it is read back (see the on-load block near the
  // bottom of this script), and that path must stay textContent-only.
  function syncQueryName(name){
    var url = new URL(location.href);
    if (name) url.searchParams.set("name", name);
    else url.searchParams.delete("name");
    history.replaceState(null, "", url.pathname + url.search + url.hash);
  }

  // Strip remote/srcset resource references before they ever hit the DOM — a malicious
  // book must not be able to phone home just by being opened. Local paths pass through
  // and are swapped to in-memory blob: URLs after insertion; data: URIs are self-contained.
  if (window.DOMPurify && DOMPurify.addHook){
    DOMPurify.addHook("uponSanitizeAttribute", function(node, data){
      var an = (data.attrName || "").toLowerCase();
      if (an === "srcset"){ data.keepAttr = false; return; }
      var tag = (node.tagName || "").toLowerCase();
      if (tag !== "img" && tag !== "audio" && tag !== "video" && tag !== "source" &&
          tag !== "track" && tag !== "image" && tag !== "use") return;
      if (an === "src" || an === "poster" || an === "href" || an === "xlink:href"){
        // normalize the way URL parsers do: drop tabs/newlines anywhere and leading controls/space
        var v = (data.attrValue || "").replace(/[\t\n\r]/g, "").replace(/^[\u0000-\u0020]+/, "") /* eslint-disable-line no-control-regex -- strip C0 before URL parse */;
        if (isExternal(v) && !/^data:/i.test(v)) data.keepAttr = false;
      }
    });
  }

  function toast(msg){
    toastEl.textContent = msg;
    toastEl.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function(){ toastEl.classList.remove("show"); }, 1900);
  }

  /* ---------- Path helpers (zip paths are /-separated, relative to zip root) ---------- */
  function dirOf(p){
    var i = p.lastIndexOf("/");
    return i === -1 ? "" : p.slice(0, i);
  }
  function normalize(p){
    var parts = p.split("/"), out = [];
    for (var i = 0; i < parts.length; i++){
      var s = parts[i];
      if (!s || s === ".") continue;
      if (s === "..") out.pop(); else out.push(s);
    }
    return out.join("/");
  }
  function stripFrag(href){
    return href.split("#")[0].split("?")[0];
  }
  function fragOf(href){
    var i = href.indexOf("#");
    return i === -1 ? "" : href.slice(i + 1);
  }
  function resolveHref(baseDir, href){
    var h = stripFrag(href);
    try { h = decodeURIComponent(h); } catch (e) {}
    if (!h) return "";
    if (h.charAt(0) === "/") h = h.slice(1);           // treat as zip-root-relative
    else if (baseDir) h = baseDir + "/" + h;
    return normalize(h);
  }
  // scheme:, protocol-relative, data:, or fragment-only URLs are not zip paths
  function isExternal(href){
    return /^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(href);
  }

  /* ---------- XML helpers (namespace-agnostic, EPUBs vary wildly) ---------- */
  function parseXml(text){
    var d = new DOMParser().parseFromString(text, "application/xml");
    return d.getElementsByTagName("parsererror").length ? null : d;
  }
  function firstLocal(node, name){
    var all = node.getElementsByTagName("*");
    for (var i = 0; i < all.length; i++) if (all[i].localName === name) return all[i];
    return null;
  }
  function allLocal(node, name){
    var out = [], all = node.getElementsByTagName("*");
    for (var i = 0; i < all.length; i++) if (all[i].localName === name) out.push(all[i]);
    return out;
  }

  // True only if encryption.xml encrypts something beyond IDPF/Adobe font obfuscation
  function hasRealEncryption(xml){
    var d = parseXml(xml);
    if (!d) return true;                       // unreadable: assume the worst
    var data = allLocal(d, "EncryptedData");
    if (!data.length) return false;
    for (var i = 0; i < data.length; i++){
      var m = firstLocal(data[i], "EncryptionMethod");
      var alg = (m && m.getAttribute("Algorithm")) || "";
      if (alg !== "http://www.idpf.org/2008/embedding" &&
          alg !== "http://ns.adobe.com/pdf/enc#RC") return true;
    }
    return false;
  }

  /* ---------- Resource extraction ---------- */
  var EXT_MIME = {
    jpg:"image/jpeg", jpeg:"image/jpeg", png:"image/png", gif:"image/gif",
    svg:"image/svg+xml", webp:"image/webp", bmp:"image/bmp", avif:"image/avif",
    mp3:"audio/mpeg", m4a:"audio/mp4", oga:"audio/ogg", ogg:"audio/ogg", wav:"audio/wav",
    mp4:"video/mp4", m4v:"video/mp4", webm:"video/webm"
  };
  function mimeFor(path){
    var it = book && book.byPath[path];
    if (it && it.type) return it.type;
    var m = /\.([a-z0-9]+)$/i.exec(path);
    return (m && EXT_MIME[m[1].toLowerCase()]) || "application/octet-stream";
  }
  function blobUrlFor(path){
    if (blobUrls[path]) return Promise.resolve(blobUrls[path]);
    var f = book && book.zf(path);
    if (!f) return Promise.resolve(null);
    var seq = bookSeq;   // a load resolving after clear/new-open must not touch the new book's cache
    return f.async("arraybuffer").then(function(buf){
      if (seq !== bookSeq) return null;
      if (!blobUrls[path]) blobUrls[path] = URL.createObjectURL(new Blob([buf], { type: mimeFor(path) }));
      return blobUrls[path];
    }, function(){ return null; });
  }
  function revokeAll(){
    for (var k in blobUrls){
      try { URL.revokeObjectURL(blobUrls[k]); } catch (e) {}
    }
    blobUrls = {};
  }

  /* ---------- Opening an EPUB ---------- */
  function fileExt(name){
    var m = /\.[A-Za-z0-9]+$/.exec(name || "");
    return m ? m[0].toLowerCase() : "";
  }
  function isAcceptedFile(name){
    return ACCEPT_EXT.indexOf(fileExt(name)) !== -1;
  }

  function readFile(file){
    if (!file) return;
    // validate the file type before we try to display anything
    if (file.name && !isAcceptedFile(file.name)){
      if (!familyRoute(file)) toast("Please choose an EPUB (.epub) file");   // §6.10: offer a sibling viewer first
      return;
    }
    var reader = new FileReader();
    reader.onload  = function(e){ openEpub(e.target.result, file.name || ""); };
    reader.onerror = function(){ toast("Could not read that file"); };
    reader.readAsArrayBuffer(file);
  }

  function openEpub(buf, name){
    currentName = name || "";
    syncQueryName(currentName);
    if (!window.JSZip){ toast("Viewer failed to load its unzip library"); return; }
    JSZip.loadAsync(buf).then(function(zip){
      // tolerant lookup: exact path first, then case-insensitive
      var lower = {};
      zip.forEach(function(rel){ lower[rel.toLowerCase()] = rel; });
      function zf(p){
        var f = zip.file(p);
        if (f) return f;
        var real = lower[p.toLowerCase()];
        return real ? zip.file(real) : null;
      }
      var container = zf("META-INF/container.xml");
      if (!container){ toast("That doesn't look like an EPUB (no META-INF/container.xml)"); return; }
      // encryption.xml that only obfuscates embedded fonts (InDesign's default) isn't DRM
      var encFile = zf("META-INF/encryption.xml");
      var drmCheck = encFile
        ? encFile.async("text").then(hasRealEncryption, function(){ return true; })
        : Promise.resolve(false);
      return container.async("text").then(function(xml){
        var cdoc = parseXml(xml);
        if (!cdoc){ toast("Couldn't read this EPUB's container.xml"); return; }
        var opfPath = "", rfs = allLocal(cdoc, "rootfile");
        for (var i = 0; i < rfs.length; i++){
          if (rfs[i].getAttribute("media-type") === "application/oebps-package+xml"){
            opfPath = rfs[i].getAttribute("full-path") || ""; break;
          }
        }
        if (!opfPath && rfs.length) opfPath = rfs[0].getAttribute("full-path") || "";
        opfPath = normalize(opfPath);
        var opfFile = opfPath && zf(opfPath);
        if (!opfFile){ toast("Couldn't find this EPUB's package file"); return; }
        return opfFile.async("text").then(function(opfXml){
          loadPackage(zf, opfXml, opfPath, name, drmCheck);
        });
      });
    }, function(){
      toast("That doesn't look like an EPUB file");
    }).catch(function(){
      toast("Couldn't open that book");
    });
  }

  function loadPackage(zf, opfXml, opfPath, name, drmCheck){
    var opf = parseXml(opfXml);
    if (!opf){ toast("Couldn't read this EPUB's package file"); return; }
    var opfDir = dirOf(opfPath);

    var title = "", author = "";
    var md = firstLocal(opf, "metadata");
    if (md){
      var t = allLocal(md, "title");   if (t.length) title  = (t[0].textContent || "").trim();
      var c = allLocal(md, "creator"); if (c.length) author = (c[0].textContent || "").trim();
    }

    var manifest = {}, byPath = {};
    var mEl = firstLocal(opf, "manifest");
    var items = mEl ? allLocal(mEl, "item") : [];
    for (var i = 0; i < items.length; i++){
      var id = items[i].getAttribute("id"), href = items[i].getAttribute("href");
      if (!id || !href || isExternal(href)) continue;
      var rec = {
        id: id,
        path: resolveHref(opfDir, href),
        type: items[i].getAttribute("media-type") || "",
        props: items[i].getAttribute("properties") || ""
      };
      manifest[id] = rec;
      byPath[rec.path] = rec;
    }

    var spine = [], spineIdx = {}, spineIdxLower = {};
    var sEl = firstLocal(opf, "spine");
    var refs = sEl ? allLocal(sEl, "itemref") : [];
    for (i = 0; i < refs.length; i++){
      var idref = refs[i].getAttribute("idref");
      var rec2 = idref && manifest[idref];
      if (rec2 && zf(rec2.path) && spineIdx[rec2.path] == null){
        spineIdx[rec2.path] = spine.length;
        if (spineIdxLower[rec2.path.toLowerCase()] == null) spineIdxLower[rec2.path.toLowerCase()] = spine.length;
        spine.push(rec2);
      }
    }
    if (!spine.length){
      drmCheck.then(function(isDrm){
        toast(isDrm ? "This book appears to be DRM-protected" : "This EPUB has no readable chapters");
      });
      return;
    }

    clearAll();
    book = {
      zf: zf,
      title: title || (name ? name.replace(/\.epub$/i, "") : "Untitled book"),
      author: author,
      manifest: manifest, byPath: byPath,
      spine: spine, spineIdx: spineIdx, spineIdxLower: spineIdxLower,
      toc: []
    };
    var drmSeq = bookSeq;
    drmCheck.then(function(isDrm){
      if (isDrm && drmSeq === bookSeq && book) toast("Heads up: this book has encrypted resources — some content may not display");
    });

    // TOC: EPUB 3 nav doc, falling back to EPUB 2 NCX, falling back to the spine
    var navItem = null, ncxItem = null;
    for (var mid in manifest){
      if (!navItem && /(?:^|\s)nav(?:\s|$)/.test(manifest[mid].props)) navItem = manifest[mid];
      if (!ncxItem && manifest[mid].type === "application/x-dtbncx+xml") ncxItem = manifest[mid];
    }
    var ncxId = sEl && sEl.getAttribute("toc");
    if (ncxId && manifest[ncxId]) ncxItem = manifest[ncxId];

    var seq = bookSeq;
    tocFrom(navItem, parseNavToc)
      .then(function(toc){ return (toc && toc.length) ? toc : tocFrom(ncxItem, parseNcxToc); })
      .then(function(toc){
        if (seq !== bookSeq || !book) return;      // a clear/new open happened meanwhile
        if (!toc || !toc.length){
          toc = [];
          for (var i = 0; i < book.spine.length; i++){
            toc.push({ label: "Section " + (i + 1), path: book.spine[i].path, frag: "", children: [] });
          }
        }
        book.toc = toc;
        buildTocPanel(toc);
      });

    startBook();
  }

  function tocFrom(item, parser){
    if (!item || !book) return Promise.resolve([]);
    var f = book.zf(item.path);
    if (!f) return Promise.resolve([]);
    return f.async("text").then(function(src){
      try { return parser(src, dirOf(item.path)); } catch (e) { return []; }
    }, function(){ return []; });
  }

  /* ---------- TOC parsing ---------- */
  function parseNavToc(src, baseDir){
    var d = new DOMParser().parseFromString(src, "text/html");
    var navs = d.getElementsByTagName("nav"), navEl = null;
    for (var i = 0; i < navs.length; i++){
      var type = navs[i].getAttribute("epub:type") ||
                 navs[i].getAttributeNS("http://www.idpf.org/2007/ops", "type") || "";
      if (/(?:^|\s)toc(?:\s|$)/.test(type)){ navEl = navs[i]; break; }
    }
    if (!navEl && navs.length) navEl = navs[0];
    if (!navEl) return [];
    var list = navEl.querySelector("ol, ul");
    return list ? walkNavList(list, baseDir) : [];
  }
  function walkNavList(list, baseDir){
    var out = [];
    for (var li = list.firstElementChild; li; li = li.nextElementSibling){
      if (li.tagName.toLowerCase() !== "li") continue;
      var a = null, sub = null;
      for (var ch = li.firstElementChild; ch; ch = ch.nextElementSibling){
        var tag = ch.tagName.toLowerCase();
        if (!a && (tag === "a" || tag === "span")) a = ch;
        else if (!sub && (tag === "ol" || tag === "ul")) sub = ch;
      }
      var entry = {
        label: ((a ? a.textContent : li.textContent) || "").replace(/\s+/g, " ").trim(),
        path: "", frag: "",
        children: sub ? walkNavList(sub, baseDir) : []
      };
      var href = a && a.getAttribute("href");
      if (href && !isExternal(href)){
        entry.path = resolveHref(baseDir, href);
        entry.frag = fragOf(href);
      }
      if (entry.label || entry.children.length) out.push(entry);
    }
    return out;
  }
  function parseNcxToc(src, baseDir){
    var d = parseXml(src);
    if (!d) return [];
    var map = firstLocal(d, "navMap");
    return map ? walkNavPoints(map, baseDir) : [];
  }
  function walkNavPoints(parent, baseDir){
    var out = [];
    for (var ch = parent.firstElementChild; ch; ch = ch.nextElementSibling){
      if (ch.localName !== "navPoint") continue;
      var entry = { label: "", path: "", frag: "", children: [] };
      for (var c = ch.firstElementChild; c; c = c.nextElementSibling){
        if (c.localName === "navLabel"){
          var t = firstLocal(c, "text");
          entry.label = ((t && t.textContent) || "").replace(/\s+/g, " ").trim();
        } else if (c.localName === "content"){
          var src2 = c.getAttribute("src") || "";
          if (src2 && !isExternal(src2)){
            entry.path = resolveHref(baseDir, src2);
            entry.frag = fragOf(src2);
          }
        }
      }
      entry.children = walkNavPoints(ch, baseDir);
      if (entry.label || entry.path || entry.children.length) out.push(entry);
    }
    return out;
  }

  // spine lookup with the same case tolerance zf() gives zip entries
  function spineIndexOf(path){
    if (!book || !path) return null;
    var i = book.spineIdx[path];
    if (i == null) i = book.spineIdxLower[path.toLowerCase()];
    return i == null ? null : i;
  }

  /* ---------- TOC panel ---------- */
  function buildTocPanel(toc){
    tocList.textContent = "";
    tocList.appendChild(buildTocLevel(toc));
    highlightToc();
  }
  function buildTocLevel(entries){
    var ul = doc.createElement("ul");
    for (var i = 0; i < entries.length; i++){
      var e = entries[i];
      var li = doc.createElement("li");
      var a = doc.createElement("a");
      a.textContent = e.label || "Untitled";
      var si = book ? spineIndexOf(e.path) : null;
      if (si != null){
        a.href = "#";
        a.setAttribute("data-path", book.spine[si].path);
        a.setAttribute("data-frag", e.frag || "");
      }
      li.appendChild(a);
      if (e.children && e.children.length) li.appendChild(buildTocLevel(e.children));
      ul.appendChild(li);
    }
    return ul;
  }
  tocList.addEventListener("click", function(ev){
    var a = ev.target && ev.target.closest ? ev.target.closest("a") : null;
    if (!a) return;
    ev.preventDefault();
    var path = a.getAttribute("data-path");
    if (!path || !book) return;
    var idx = spineIndexOf(path);
    if (idx == null) return;
    closeToc();
    showChapter(idx, a.getAttribute("data-frag") || "");
  });
  function highlightToc(){
    if (!book) return;
    var path = current >= 0 && book.spine[current] ? book.spine[current].path : "";
    var links = tocList.querySelectorAll("a[data-path]");
    var marked = false;
    for (var i = 0; i < links.length; i++){
      var on = !marked && links[i].getAttribute("data-path") === path;
      links[i].classList.toggle("active", on);
      if (on) marked = true;
    }
  }
  var btnTocClose = doc.getElementById("btnTocClose");
  function openTocPanel(){
    if (!book){ toast("Open a book first"); return; }
    tocPanel.classList.add("open");
    scrim.classList.add("show");
    btnToc.setAttribute("aria-expanded", "true");
    var active = tocList.querySelector("a.active");
    if (active) active.scrollIntoView({ block: "center" });
    (active || btnTocClose).focus();
  }
  function closeToc(){
    if (tocPanel.contains(doc.activeElement)) btnToc.focus();
    tocPanel.classList.remove("open");
    scrim.classList.remove("show");
    btnToc.setAttribute("aria-expanded", "false");
  }
  btnToc.addEventListener("click", function(){
    if (tocPanel.classList.contains("open")) closeToc(); else openTocPanel();
  });
  btnTocClose.addEventListener("click", closeToc);
  scrim.addEventListener("click", closeToc);

  /* ---------- Rendering chapters ---------- */
  function startBook(){
    docTitle.textContent = book.title + (book.author ? " — " + book.author : "");
    doc.title = book.title + " — " + BASE_TITLE;
    empty.hidden = true;
    content.hidden = false;
    chapNav.hidden = false;
    body.classList.add("viewing");
    lastScrollY = window.pageYOffset || 0;
    showHeader();                 // visible on open, then auto-hides after HEADER_TIMEOUT
    showChapter(0, "");
  }

  function showChapter(i, frag){
    if (!book || i < 0 || i >= book.spine.length) return;
    var item = book.spine[i];
    var f = book.zf(item.path);
    if (!f){ toast("Missing chapter file"); return; }
    var seq = ++chapterSeq;
    f.async("text").then(function(src){
      if (seq !== chapterSeq || !book) return;   // superseded by a newer navigation
      current = i;
      renderChapter(src, item.path, frag);
    }, function(){
      if (seq === chapterSeq) toast("Could not read this chapter");
    });
  }

  function renderChapter(src, path, frag){
    var parsed = new DOMParser().parseFromString(src, "text/html");
    var raw = parsed && parsed.body ? parsed.body.innerHTML : src;
    var html = window.DOMPurify
      ? DOMPurify.sanitize(raw, {
          // books get clean, color-adaptive typography: drop their styling and any form controls
          FORBID_TAGS: ["style", "form", "input", "button", "select", "textarea", "option", "optgroup", "fieldset", "legend"],
          FORBID_ATTR: ["style"]
        })
      : "";
    content.innerHTML = html;
    var pending = resolveResources(path);
    wireLinks(path);
    updateChapNav();
    highlightToc();
    if (frag){
      if (!scrollToFrag(frag)) window.scrollTo(0, 0);
      // images get real sizes only after their blob URLs resolve, which shifts
      // the layout; re-anchor once they've settled (unless we've moved on)
      var seq = chapterSeq;
      pending.then(waitForImages).then(function(){
        if (seq === chapterSeq) scrollToFrag(frag);
      });
    } else {
      window.scrollTo(0, 0);
    }
  }

  function waitForImages(){
    var imgs = content.querySelectorAll("img"), waits = [];
    for (var i = 0; i < imgs.length; i++){
      (function(img){
        if (img.complete || !img.getAttribute("src")) return;
        waits.push(new Promise(function(res){
          img.addEventListener("load", res, { once: true });
          img.addEventListener("error", res, { once: true });
          setTimeout(res, 3000);               // never hang on a stuck image
        }));
      })(imgs[i]);
    }
    return Promise.all(waits);
  }

  function attrSel(name, value){
    return "[" + name + '="' + value.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"]';
  }
  function findFrag(frag){
    return content.querySelector(attrSel("id", frag)) ||
           content.querySelector("a" + attrSel("name", frag));
  }
  function scrollToFrag(frag){
    var el = findFrag(frag);
    if (!el && frag.indexOf("%") !== -1){
      // nav/NCX hrefs are URLs, so non-ASCII ids arrive percent-encoded
      try { el = findFrag(decodeURIComponent(frag)); } catch (e) {}
    }
    if (!el) return false;
    el.scrollIntoView();
    return true;
  }

  function resolveResources(chapterPath){
    var baseDir = dirOf(chapterPath);
    var i, els, waits = [];

    els = content.querySelectorAll("img[src], audio[src], video[src], source[src]");
    for (i = 0; i < els.length; i++) waits.push(swapToBlob(els[i], "src", baseDir));
    els = content.querySelectorAll("video[poster]");
    for (i = 0; i < els.length; i++) waits.push(swapToBlob(els[i], "poster", baseDir));

    // SVG <image> references (common for full-page cover images)
    els = content.querySelectorAll("image");
    for (i = 0; i < els.length; i++){
      waits.push((function(el){
        var href = el.getAttribute("href") || el.getAttributeNS(XLINK_NS, "href") || el.getAttribute("xlink:href");
        if (!href || isExternal(href)) return null;
        return blobUrlFor(resolveHref(baseDir, href)).then(function(url){
          if (!url) return;
          el.setAttribute("href", url);
          el.setAttributeNS(XLINK_NS, "xlink:href", url);
        });
      })(els[i]));
    }
    return Promise.all(waits);
  }
  function swapToBlob(el, attr, baseDir){
    var v = el.getAttribute(attr);
    if (!v || isExternal(v) || v.charAt(0) === "#") return null;   // data: URLs load as-is
    el.removeAttribute(attr);
    return blobUrlFor(resolveHref(baseDir, v)).then(function(url){
      if (!url) return;
      el.setAttribute(attr, url);
      // a media element whose <source> children already failed selection
      // won't retry on its own — restart it (#9)
      var p = el.parentElement;
      if (el.tagName === "SOURCE" && p && (p.tagName === "AUDIO" || p.tagName === "VIDEO")) p.load();
    });
  }

  function wireLinks(chapterPath){
    var baseDir = dirOf(chapterPath);
    var links = content.querySelectorAll("a[href]");
    for (var i = 0; i < links.length; i++){
      (function(a){
        var href = a.getAttribute("href") || "";
        if (isExternal(href)){
          a.setAttribute("target", "_blank");
          a.setAttribute("rel", "noopener noreferrer");
          return;
        }
        if (href.charAt(0) === "#"){
          a.addEventListener("click", function(e){
            e.preventDefault();
            scrollToFrag(href.slice(1));
          });
          return;
        }
        var path = resolveHref(baseDir, href), frag = fragOf(href);
        var idx = spineIndexOf(path);
        if (idx == null){
          a.removeAttribute("href");                 // nothing sensible to open
          return;
        }
        a.addEventListener("click", function(e){
          e.preventDefault();
          var j = spineIndexOf(path);
          if (j != null) showChapter(j, frag);
        });
      })(links[i]);
    }
  }

  /* ---------- Chapter navigation ---------- */
  function updateChapNav(){
    var n = book.spine.length;
    chapPos.textContent = (current + 1) + " / " + n;
    btnPrev.disabled = current <= 0;
    btnNext.disabled = current >= n - 1;
  }
  function step(delta){
    if (!book) return;
    var i = current + delta;
    if (i >= 0 && i < book.spine.length) showChapter(i, "");
  }
  btnPrev.addEventListener("click", function(){ step(-1); });
  btnNext.addEventListener("click", function(){ step(1); });
  window.addEventListener("keydown", function(e){
    if (!id("routeCard").hidden){                       // §6.10 offer card is modal
      if (e.key === "Escape"){ hideRouteCard(); return; }
      if (e.key === "Tab"){                             // two-button wrap (Shift+Tab included)
        e.preventDefault();
        var go = id("routeGo"), no = id("routeDismiss");
        (doc.activeElement === go || go.disabled ? no : go).focus();
      }
      return;                                           // nothing else acts beneath the dialog
    }
    if (e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
    if (e.key === "Escape"){ closeToc(); return; }
    if (!book || tocPanel.classList.contains("open")) return;
    var t = e.target, tag = (t && t.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea" || tag === "select" || (t && t.isContentEditable)) return;
    if (e.key === "ArrowRight"){ e.preventDefault(); step(1); }
    else if (e.key === "ArrowLeft"){ e.preventDefault(); step(-1); }
  });

  /* ---------- Clearing ---------- */
  function clearAll(){
    chapterSeq++; bookSeq++;    // invalidate in-flight chapter/TOC loads
    book = null; current = -1; currentName = ""; syncQueryName("");
    revokeAll();
    content.innerHTML = "";
    content.hidden = true;
    empty.hidden = false;
    chapNav.hidden = true;
    tocList.textContent = "";
    closeToc();
    docTitle.textContent = BASE_TITLE;
    doc.title = BASE_TITLE;
    clearTimeout(headerTimer); headerTimer = null;
    body.classList.remove("viewing", "peek");
  }

  function openDialog(){ fileInput.click(); }

  fileInput.addEventListener("change", function(e){
    var f = e.target.files && e.target.files[0];
    if (f) readFile(f);
    fileInput.value = "";
  });

  // Copy the current chapter as plain text
  doc.getElementById("btnCopy").addEventListener("click", function(){
    var text = (!content.hidden && content.innerText || "").trim();
    if (!text){ toast("Nothing to copy yet"); return; }
    if (navigator.clipboard && navigator.clipboard.writeText){
      navigator.clipboard.writeText(text).then(
        function(){ toast("Chapter text copied"); },
        function(){ fallbackCopy(text); }
      );
    } else {
      fallbackCopy(text);
    }
  });
  function fallbackCopy(text){
    var ta = doc.createElement("textarea");
    ta.value = text; ta.setAttribute("readonly", "");
    ta.style.position = "fixed"; ta.style.opacity = "0";
    doc.body.appendChild(ta); ta.select();
    try { doc.execCommand("copy"); toast("Chapter text copied"); }
    catch (err){ toast("Copy not supported"); }
    doc.body.removeChild(ta);
  }

  doc.getElementById("btnClear").addEventListener("click", clearAll);

  // Hide the footer (far-right close button); it stays gone until reload
  doc.getElementById("btnFooterClose").addEventListener("click", function(){
    var f = doc.getElementById("footer");
    if (f) f.hidden = true;
  });

  // ---------- Family nav (hamburger flyout) ----------
  var btnMenu = doc.getElementById("btnMenu"), navBackdrop = doc.getElementById("navBackdrop");
  function setNav(open){
    if (open) closeToc();                 // don't stack the family nav over the TOC panel
    body.classList.toggle("nav-open", open);
    btnMenu.setAttribute("aria-expanded", open ? "true" : "false");
  }
  btnMenu.addEventListener("click", function(){ setNav(!body.classList.contains("nav-open")); });
  navBackdrop.addEventListener("click", function(){ setNav(false); });
  doc.addEventListener("keydown", function(e){ if (e.key === "Escape") setNav(false); });

  // Empty-state acts as an open button (great on mobile)
  empty.addEventListener("click", openDialog);
  empty.addEventListener("keydown", function(e){
    if (e.key === "Enter" || e.key === " "){ e.preventDefault(); openDialog(); }
  });

  /* ---------- Auto-hiding header: show on scroll up (or at top) & for HEADER_TIMEOUT after,
     hide on scroll down ---------- */
  var HEADER_TIMEOUT = 3000;
  var headerTimer = null, lastScrollY = 0, headerHovered = false;
  var topbarEl = doc.querySelector(".topbar");

  function armHeaderTimer(){
    clearTimeout(headerTimer);
    headerTimer = setTimeout(function(){
      headerTimer = null;
      if (!headerHovered) body.classList.remove("peek");
    }, HEADER_TIMEOUT);
  }
  function showHeader(){
    if (!body.classList.contains("viewing")) return;
    body.classList.add("peek");
    armHeaderTimer();
  }
  function hideHeader(){
    clearTimeout(headerTimer); headerTimer = null;
    if (!headerHovered) body.classList.remove("peek");
  }

  window.addEventListener("scroll", function(){
    if (!body.classList.contains("viewing")) return;
    var y = window.pageYOffset || root.scrollTop || 0;
    if (y <= 0) showHeader();               // at the very top, keep the header available
    else if (y < lastScrollY - 4) showHeader();   // scrolling up
    else if (y > lastScrollY + 4) hideHeader();   // scrolling down
    lastScrollY = y;
  }, { passive: true });

  // Don't let the timer yank the header away while the pointer is on it
  topbarEl.addEventListener("mouseenter", function(){ headerHovered = true; clearTimeout(headerTimer); headerTimer = null; });
  topbarEl.addEventListener("mouseleave", function(){ headerHovered = false; if (body.classList.contains("peek")) armHeaderTimer(); });

  // Reveal via the top strip / handle — hover, tap, or click (touch has no scroll-up-to-reveal)
  hoverZone.addEventListener("click", showHeader);
  hoverZone.addEventListener("mouseenter", showHeader);
  hoverZone.addEventListener("touchstart", function(){ showHeader(); }, { passive:true });

  /* ---------- Background color (chosen by the user, remembered in a cookie) ---------- */
  function setCookie(name, val){
    doc.cookie = name + "=" + encodeURIComponent(val) + "; max-age=31536000; path=/; SameSite=Lax";
  }
  function getCookie(name){
    var m = doc.cookie.match("(?:^|; )" + name.replace(/([.*+?^${}()|[\]\\])/g, "\\$1") + "=([^;]*)");
    return m ? decodeURIComponent(m[1]) : null;
  }
  function hexToRgb(h){
    h = h.replace("#", "");
    if (h.length === 3) h = h.charAt(0)+h.charAt(0)+h.charAt(1)+h.charAt(1)+h.charAt(2)+h.charAt(2);
    var n = parseInt(h, 16);
    return { r:(n>>16)&255, g:(n>>8)&255, b:n&255 };
  }
  function srgb(c){ c/=255; return c<=0.03928 ? c/12.92 : Math.pow((c+0.055)/1.055, 2.4); }
  function luminance(rgb){ return 0.2126*srgb(rgb.r) + 0.7152*srgb(rgb.g) + 0.0722*srgb(rgb.b); }
  function mix(a, b, t){
    return "rgb(" + Math.round(a.r+(b.r-a.r)*t) + "," + Math.round(a.g+(b.g-a.g)*t) + "," + Math.round(a.b+(b.b-a.b)*t) + ")";
  }
  function rgbStr(c){ return "rgb(" + c.r + "," + c.g + "," + c.b + ")"; }

  function applyColor(hex){
    if (!/^#([0-9a-f]{3}|[0-9a-f]{6})$/i.test(hex)) hex = "#ffffff";
    var bg = hexToRgb(hex);
    // Pick black or white text by whichever contrasts better (crossover ~0.179).
    var lightText = luminance(bg) <= 0.179;          // dark background -> light text
    var text = lightText ? { r:240, g:243, b:246 } : { r:31, g:35, b:40 };
    var accentHex = lightText ? "#8b93ff" : "#4f46e5";
    var ac = hexToRgb(accentHex);
    var s = root.style;
    s.setProperty("--bg", hex);
    s.setProperty("--surface", hex);
    s.setProperty("--text", rgbStr(text));
    s.setProperty("--code-text", rgbStr(text));
    s.setProperty("--muted", mix(bg, text, 0.45));
    s.setProperty("--border", mix(bg, text, 0.24));
    s.setProperty("--border-soft", mix(bg, text, 0.13));
    s.setProperty("--code-bg", mix(bg, text, 0.07));
    s.setProperty("--hover", mix(bg, text, 0.10));
    s.setProperty("--table-stripe", mix(bg, text, 0.05));
    s.setProperty("--quote-border", mix(bg, text, 0.26));
    s.setProperty("--accent", accentHex);
    s.setProperty("--accent-contrast", lightText ? "#0d1117" : "#ffffff");
    s.setProperty("--overlay", "rgba(" + ac.r + "," + ac.g + "," + ac.b + ",0.12)");
    s.setProperty("--shadow", lightText ? "rgba(0,0,0,0.6)" : "rgba(0,0,0,0.12)");
    s.setProperty("--header-bg", "rgba(" + bg.r + "," + bg.g + "," + bg.b + ",0.9)");
    s.colorScheme = lightText ? "dark" : "light";
    themeColor.setAttribute("content", hex);
  }

  function isHex6(v){ return /^#([0-9a-f]{6})$/i.test(v || ""); }
  function saveColor(val){
    setCookie("mykk-bg", val);                                  // primary
    try { localStorage.setItem("mykk-bg", val); } catch (e) {}  // fallback (e.g. file://)
  }
  function loadColor(){
    var v = getCookie("mykk-bg");
    if (!isHex6(v)) { try { v = localStorage.getItem("mykk-bg"); } catch (e) { v = null; } }
    return isHex6(v) ? v : ((window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches) ? "#0d1117" : "#ffffff");
  }

  var themeToggle=document.getElementById("themeToggle"),themeIconSun=document.getElementById("themeIconSun"),themeIconMoon=document.getElementById("themeIconMoon");
  var saved = loadColor();
  bgPicker.value = saved;
  applyColor(saved);
  syncThemeToggle();
  bgPicker.addEventListener("input", function(){
    applyColor(bgPicker.value);
    saveColor(bgPicker.value);
    syncThemeToggle();
  });
  function isDarkBg(){ try { return luminance(hexToRgb(bgPicker.value)) <= 0.179; } catch(e){ return false; } }
  function syncThemeToggle(){ if(!themeToggle) return; var dark=isDarkBg(); themeToggle.setAttribute("aria-pressed", dark?"true":"false"); themeToggle.setAttribute("aria-label", dark?"Switch to light theme":"Switch to dark theme"); if(themeIconSun){ if(dark) themeIconSun.setAttribute("hidden",""); else themeIconSun.removeAttribute("hidden"); } if(themeIconMoon){ if(dark) themeIconMoon.removeAttribute("hidden"); else themeIconMoon.setAttribute("hidden",""); } }
  if(themeToggle){ themeToggle.addEventListener("click", function(){ var next=isDarkBg()?"#ffffff":"#0d1117"; bgPicker.value=next; applyColor(next); saveColor(next); syncThemeToggle(); }); }

  /* ---------- Drag & drop (anywhere) ---------- */
  var dragDepth = 0;
  function showOverlay(s){ overlay.classList.toggle("show", s); }
  window.addEventListener("dragenter", function(e){
    if (e.dataTransfer && Array.prototype.indexOf.call(e.dataTransfer.types || [], "Files") === -1) return;
    e.preventDefault(); dragDepth++; showOverlay(true);
  });
  window.addEventListener("dragover", function(e){
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = "copy";
  });
  window.addEventListener("dragleave", function(e){
    e.preventDefault(); dragDepth--; if (dragDepth <= 0){ dragDepth = 0; showOverlay(false); }
  });
  window.addEventListener("drop", function(e){
    e.preventDefault(); dragDepth = 0; showOverlay(false);
    var dt = e.dataTransfer; if (!dt) return;
    if (dt.files && dt.files.length) readFile(dt.files[0]);
  });

  /* ---------- Paste a file to open it ---------- */
  window.addEventListener("paste", function(e){
    var cd = e.clipboardData || window.clipboardData;
    if (cd && cd.files && cd.files.length){ e.preventDefault(); readFile(cd.files[0]); }
  });

  // ---------- Family router (§6.10): wrong-viewer redirect offer + in-browser hand-off ----------
  // Data block copied byte-for-byte from the hub (file-viewer.us index.html);
  // canonical source is family-map.json in the hub repo. Deep-equality is
  // enforced by the harness (§6.10 governance).
  function id(s){ return doc.getElementById(s); }
        /* FV-MAP-START — generated from family-map.json (canonical); deep-equality enforced by the harness */
    var FAMILY = {
      audio:    { domain:"audio-viewer.us"     , label:"Audio Viewer"     , kind:"an audio file" },
      cert:     { domain:"cert-viewer.us"      , label:"Cert Viewer"      , kind:"a certificate" },
      data:     { domain:"data-viewer.us"      , label:"Data Viewer"      , kind:"a data file" },
      docx:     { domain:"docx-viewer.us"      , label:"DOCX Viewer"      , kind:"a Word document" },
      eml:      { domain:"eml-viewer.us"       , label:"EML Viewer"       , kind:"an email file" },
      epub:     { domain:"epub-viewer.us"      , label:"EPUB Viewer"      , kind:"an e-book" },
      html:     { domain:"html-viewer.us"      , label:"HTML Viewer"      , kind:"a web or source-code file" },
      image:    { domain:"image-viewer.us"     , label:"Image Viewer"     , kind:"an image" },
      log:      { domain:"log-viewer.us"       , label:"Log Viewer"       , kind:"a log file" },
      markdown: { domain:"markdown-viewer.us"  , label:"Markdown Viewer"  , kind:"a Markdown or text file" },
      pdf:      { domain:"pdf-viewer.us"       , label:"PDF Viewer"       , kind:"a PDF" },
      pptx:     { domain:"pptx-viewer.us"      , label:"PPTX Viewer"      , kind:"a presentation" },
      pub:      { domain:"pub-viewer.us"       , label:"PUB Viewer"       , kind:"a Publisher file" },
      sheets:   { domain:"sheets-viewer.us"    , label:"Sheets Viewer"    , kind:"a spreadsheet" },
      video:    { domain:"video-viewer.us"     , label:"Video Viewer"     , kind:"a video" }
    };
    var FAMILY_HUB = "file-viewer.us";
    var FAMILY_NAMES = {"robots.txt":"html"};
    var FAMILY_MAP = {
      // sheets
      "123":"sheets", xlsx:"sheets", xlsm:"sheets", xlsb:"sheets", xls:"sheets", xlt:"sheets", xltx:"sheets", xltm:"sheets",
      xlam:"sheets", ods:"sheets", fods:"sheets", dif:"sheets", prn:"sheets", dbf:"sheets", numbers:"sheets", xlml:"sheets",
      wk1:"sheets", wk3:"sheets", wks:"sheets", et:"sheets", uos:"sheets",
      // cert
      pem:"cert", crt:"cert", cer:"cert", der:"cert", csr:"cert", cert:"cert", p7b:"cert", p12:"cert",
      pfx:"cert",
      // data
      json:"data", jsonc:"data", json5:"data", jsonld:"data", ndjson:"data", yaml:"data", yml:"data", toml:"data",
      csv:"data", tsv:"data", xml:"data", rss:"data", atom:"data", graphql:"data", gql:"data",
      // docx
      docx:"docx", docm:"docx", dotx:"docx", dotm:"docx", doc:"docx", dot:"docx", rtf:"docx", odt:"docx",
      // eml
      eml:"eml", mbox:"eml", emlx:"eml", msg:"eml",
      // epub
      epub:"epub",
      // html
      html:"html", htm:"html", xhtml:"html", xht:"html", shtml:"html", shtm:"html", stm:"html", hta:"html",
      mhtml:"html", mht:"html", css:"html", scss:"html", sass:"html", less:"html", styl:"html", pcss:"html",
      postcss:"html", js:"html", mjs:"html", cjs:"html", jsx:"html", ts:"html", mts:"html", cts:"html",
      tsx:"html", coffee:"html", htaccess:"html", htpasswd:"html", env:"html", ini:"html", conf:"html", webmanifest:"html",
      map:"html", php:"html", phtml:"html", asp:"html", aspx:"html", ascx:"html", cshtml:"html", vbhtml:"html",
      jsp:"html", jspx:"html", cfm:"html", erb:"html", rhtml:"html", ejs:"html", hbs:"html", handlebars:"html",
      mustache:"html", njk:"html", liquid:"html", jinja:"html", j2:"html", twig:"html", pug:"html", jade:"html",
      haml:"html", slim:"html", vue:"html", svelte:"html", astro:"html",
      // image
      png:"image", jpg:"image", jpeg:"image", jpe:"image", jfif:"image", gif:"image", webp:"image", avif:"image",
      svg:"image", svgz:"image", bmp:"image", dib:"image", ico:"image", cur:"image", tif:"image", tiff:"image",
      tga:"image", targa:"image", icb:"image", vda:"image", vst:"image", qoi:"image", pcx:"image", ppm:"image",
      pgm:"image", pbm:"image", pnm:"image", pam:"image", ff:"image", dds:"image", heic:"image", heif:"image",
      jxl:"image", psd:"image",
      // log
      log:"log", out:"log", err:"log", trace:"log", syslog:"log",
      // markdown
      md:"markdown", markdown:"markdown", mdx:"markdown", txt:"markdown", rst:"markdown", adoc:"markdown",
      // pdf
      pdf:"pdf",
      // pptx
      pptx:"pptx", pptm:"pptx", ppsx:"pptx", ppsm:"pptx", potx:"pptx", potm:"pptx", ppt:"pptx",
      // pub
      pub:"pub",
      // audio
      mp3:"audio", wav:"audio", flac:"audio", m4a:"audio", aac:"audio", ogg:"audio", oga:"audio", opus:"audio",
      weba:"audio", mka:"audio", aif:"audio", aiff:"audio", wma:"audio", mid:"audio", midi:"audio",
      // video
      webm:"video", mp4:"video", m4v:"video", ogv:"video", mov:"video", mkv:"video", avi:"video", wmv:"video"
    };
    /* FV-MAP-END */
    var FAMILY_ORIGINS = Object.keys(FAMILY).map(function (k) { return "https://" + FAMILY[k].domain; })
      .concat("https://" + FAMILY_HUB);
  var DOMAIN = "epub-viewer.us";

  var routeFile = null, routeKey = "", routePrevFocus = null, handoff = null;
  function cancelHandoff(){                    // tear down a pending hand-off (sender below)
    if (!handoff) return;
    window.removeEventListener("message", handoff.onMsg);
    clearTimeout(handoff.timer);
    handoff = null;
  }
  function showRouteCard(file, key){
    cancelHandoff();                           // a new offer aborts any pending hand-off
    if (id("routeCard").hidden) routePrevFocus = doc.activeElement;  // don't capture our own button
    routeFile = file; routeKey = key;
    var t = FAMILY[key];
    // ⁨…⁩ (FSI…PDI) bidi-isolate the untrusted name so U+202E-style
    // overrides can't visually reorder the sentence.
    id("routeMsg").textContent = "“⁨" + file.name + "⁩” looks like " + t.kind + " — it belongs to " + t.label + ".";
    id("routeGo").textContent = "Open " + t.domain + " ↗";
    id("routeSub").textContent = "Your file stays on this device — nothing is uploaded.";
    id("routeGo").disabled = false;
    id("routeBackdrop").hidden = false; id("routeCard").hidden = false;
    id("routeGo").focus();
  }
  function hideRouteCard(){
    cancelHandoff();                           // dismissal aborts a pending hand-off
    id("routeBackdrop").hidden = true; id("routeCard").hidden = true;
    routeFile = null; routeKey = "";
    if (routePrevFocus && routePrevFocus.focus) routePrevFocus.focus();
  }
  function familyRoute(file){
    var n = String(file && file.name || "").toLowerCase();
    var key = FAMILY_NAMES[n];
    if (!key){
      var i = n.lastIndexOf(".");
      var ext = i >= 0 ? n.slice(i + 1) : "";
      key = FAMILY_MAP[ext];
    }
    if (!key || FAMILY[key].domain === DOMAIN) return false;  // unknown type, or our own type -> caller keeps its toast
    showRouteCard(file, key);
    return true;
  }

  // Sender — the routeGo click is a real user gesture, so no popup blocker.
  // Keep the window handle: it IS the message channel (trusted family only);
  // the receiver never touches window.opener except for the ready ping.
  id("routeGo").addEventListener("click", function(){
    if (!routeFile || id("routeGo").disabled) return;               // no double-fire
    cancelHandoff();
    var t = FAMILY[routeKey], origin = "https://" + t.domain, file = routeFile;
    var w = window.open(origin + "/#fvh=" + encodeURIComponent(file.name));
    if (!w){ id("routeSub").textContent = "Couldn’t open the tab — allow pop-ups for this site and try again."; return; }
    id("routeGo").disabled = true;
    var h = {};
    h.onMsg = function(e){
      if (e.source !== w || e.origin !== origin || !e.data) return;
      if (e.data.type === "fv-ready") w.postMessage({ type:"fv-file", file:file }, origin);
      else if (e.data.type === "fv-ack"){ hideRouteCard(); toast("Sent to " + t.label); }  // hideRouteCard tears the handshake down
    };
    h.timer = setTimeout(function(){
      if (handoff !== h) return;
      cancelHandoff();
      id("routeSub").textContent = "Tab opened — drop the file there.";   // Level-1 fallback
    }, 10000);
    handoff = h;
    window.addEventListener("message", h.onMsg);
  });
  id("routeDismiss").addEventListener("click", hideRouteCard);
  id("routeBackdrop").addEventListener("click", hideRouteCard);

  // Receiver — a sibling tab (or the hub) hands a File across via postMessage
  // structured clone: in-browser, never on the wire.
  window.addEventListener("message", function(e){
    if (FAMILY_ORIGINS.indexOf(e.origin) === -1) return;      // family origins only
    var d = e.data;
    if (d && d.type === "fv-file" && d.file instanceof File){ // clone re-creates a real File in this realm
      readFile(d.file);
      e.source.postMessage({ type:"fv-ack" }, e.origin);      // ack = received and handed to the loader
    }
  });
  var fvh = /[#&]fvh=([^&]*)/.exec(location.hash);
  if (fvh){
    var fvhName = fvh[1];                                   // ⚠️ stranger-controlled — textContent only
    try { fvhName = decodeURIComponent(fvhName); } catch (_) {}  // malformed %-escapes must not abort the receiver
    history.replaceState(null, "", location.pathname + location.search);  // always clear, opener or not
    if (window.opener){
      try { window.opener.postMessage({ type:"fv-ready" }, "*"); } catch(_){}
      window.opener = null;    // sever the reverse-navigation channel once the ping is out
      var emptySub = doc.querySelector(".empty-sub");
      if (emptySub){
        var emptySubText = emptySub.textContent;
        emptySub.textContent = "Receiving “⁨" + fvhName + "⁩”…";
        setTimeout(function(){ emptySub.textContent = emptySubText; }, 10000);  // revert if nothing arrives
      }
    }
  }

  // A bookmarked or shared link can carry the name of the file last viewed
  // (?name=, set by syncQueryName above). No content is ever recoverable
  // from a name alone — this only labels the empty state, and it never
  // fetches or renders anything on the strength of it. Skipped when an
  // #fvh hand-off is already customizing the same element.
  if (!fvh && !currentName){
    var qName = new URLSearchParams(location.search).get("name");
    if (qName){
      var lastSub = doc.querySelector(".empty-sub");
      if (lastSub){
        // Display-only, and it must stay that way: this string is read
        // straight from the URL, so it is exactly as stranger-controlled as
        // fvhName above. No fact is asserted about whether anyone actually
        // viewed it — only that the link names it.
        lastSub.textContent = "This link was shared for “⁨" + qName + "⁩”.";
      }
    }
  }

})();
