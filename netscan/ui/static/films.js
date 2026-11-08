/* SafeEel: filmele „cum repari” din aplicație (generate din previzualizarea de pe Desktop, vezi REGULI_ANIMATII.md). Regula: UN cadru = O singură acțiune, cu locul exact unde apeși.
   Mecanica (fără biblioteci):
   - data-show="1,2"   element vizibil doar în cadrele date
   - data-act="3"      primește .act de la cadrul 3 încolo (data-delay = după câte ms în acel cadru)
   - data-cls="2:flip" clasă de poziție pe cadre (routerul răsturnat etc.)
   - degetul: f = selector în scenă, pre = unde apasă întâi (opțional), tap = atinge
   În aplicație HTML-ul se va scrie din Jinja; JS-ul rămâne un fișier mic, local (compatibil cu CSP). */
(function () {
  "use strict";
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const SHOT_MS = 3400;
  const list = (a, b) => Array.from({ length: b - a + 1 }, (_, i) => a + i).join(",");

  /* ================= obiectele ================= */
  function box(cls, faces, attrs = "") {
    return `<div class="shadow ${cls}-shadow"></div><div class="actor box ${cls}" ${attrs}>
      <div class="face f-back">${faces.back || ""}</div><div class="face f-left"></div><div class="face f-bottom">${faces.bottom || ""}</div>
      <div class="face f-right"></div><div class="face f-top">${faces.top || ""}</div><div class="face f-front">${faces.front || ""}</div>
      ${faces.extra || ""}</div>`;
  }
  const routerBox = (cls) => box("router", {
    front: '<span class="led"></span><span class="led"></span><span class="led"></span><span class="led off"></span><span class="brand">ROUTER</span>',
    bottom: '<div class="foot f1"></div><div class="foot f2"></div><div class="sticker"><b>Router Wi-Fi</b><br>Adresă: <b>192.168.1.1</b><br>Utilizator: <b>admin</b><br>Parolă: <b>K7m-4tq-Z9</b></div>',
    extra: '<div class="ant a1"></div><div class="ant a2"></div>',
  }, `data-cls="${cls}"`);
  const printerBox = (cls) => box("printer", {
    front: '<div class="pr-panel"><span class="pr-lcd"></span><i></i><i></i><i class="go"></i></div><div class="pr-slot"><span class="pr-sheet"></span></div><div class="pr-cassette"></div><span class="pr-brand">PRINTER</span>',
    top: '<div class="pr-lid"></div>',
    back: '<div class="sticker small"><b>Imprimantă</b><br>Parolă (Pwd): <b>x8Fq2#Lm</b></div>',
  }, `data-cls="${cls}"`);
  const zoomRouter = (show) => `<div class="zoom" data-show="${show}"><span class="loupe"></span>Eticheta de sub router:<br>Adresă: <span class="hl">192.168.1.1</span><br>Utilizator: <span class="hl">admin</span><br>Parolă: <span class="hl">K7m-4tq-Z9</span></div>`;
  const zoomPrinter = (show) => `<div class="zoom" data-show="${show}"><span class="loupe"></span>Eticheta din spatele imprimantei:<br>Parolă (Pwd): <span class="hl">x8Fq2#Lm</span><br><span class="small-note">Adresa imprimantei o vezi în SafeEel, la dispozitiv: <b>192.168.1.40</b></span></div>`;

  /* laptopul: un browser cu mai multe pagini (fiecare pagină vizibilă în cadrele ei) */
  function laptop(show, url, pages, tab = "Router") {
    const urls = url.map((u) => `<span data-show="${u.show}">${u.lock ? '<i class="padlock"></i>' : ""}${u.typed ? `<span class="typed" data-act="${u.typed}">${esc(u.text)}</span><i class="caret" data-show="${u.typed}"></i>` : esc(u.text)}</span>`).join("");
    return `<div class="shadow laptop-shadow" data-show="${show}"></div><div class="actor laptop" data-show="${show}"><div class="lid"><div class="cam-dot"></div><div class="screen">
        <div class="tabs"><span class="tab">${esc(tab)}</span><span class="tab-plus">+</span></div><div class="bar"><i class="tl r"></i><i class="tl y"></i><i class="tl g"></i><div class="url" data-t="url">${urls}</div></div>
        ${pages.map((p) => `<div class="page slide" data-show="${p.show}">${p.html}</div>`).join("")}
      </div></div><div class="base"><div class="keys"></div><div class="pad"></div></div></div>`;
  }
  const loginPage = (title, user, shot) => `<h4>${esc(title)}</h4>
      ${user ? `Utilizator<div class="field"><span class="typed" data-act="${shot}" data-delay="300">${esc(user)}</span></div>` : ""}
      Parolă<div class="field"><span class="typed" data-act="${shot}" data-delay="${user ? 900 : 300}">••••••••••</span></div>
      <span class="btn" data-t="go">Intră</span>`;
  /* pagina routerului/imprimantei: meniu în stânga + conținut în dreapta */
  const menuItem = (m, i, active) => { const sub = m.startsWith("  "); return `<span class="${sub ? "sub " : ""}${i === active.go ? "pick" : ""}${i === active.on ? " on" : ""}" ${i === active.go ? `data-act="${active.shot}" data-delay="900" data-t="go"` : ""}>${esc(m.trim())}</span>`; };
  const sidePage = (menu, active, right) => `<div class="side"><div class="menu">${menu.map((m, i) => menuItem(m, i, active)).join("")}</div><div class="right">${right}</div></div>`;

  /* telefonul */
  function phone(cls, show, screens) {
    return `<div class="shadow phone-shadow ${cls}" data-show="${show}"></div><div class="actor phone ${cls}" data-show="${show}"><div class="notch"></div><div class="screen">
      <div class="sbar"><span>9:41</span><span class="bat"></span></div>${screens}</div></div>`;
  }
  const homeScreen = (show, special) => {
    const apps = [{ n: "Telefon", c: "linear-gradient(#5BF675,#21C83F)", glyph: "✆" }, { n: "Mesaje", c: "linear-gradient(#5BF675,#21C83F)", glyph: "▬" },
      { n: "Poze", c: "#fff", glyph: "✿", dark: true }, { n: "Ceas", c: "#111", glyph: "◷" }, special, { n: "Hărți", c: "linear-gradient(135deg,#9BE15D,#3BB2F6)", glyph: "➤" },
      { n: "Muzică", c: "linear-gradient(#FF5E7E,#FA233B)", glyph: "♪" }, { n: "Cameră", c: "linear-gradient(#D5D7DB,#9FA3A9)", glyph: "◉", dark: true }, { n: "Note", c: "linear-gradient(#FFFFFF 0 30%, #FFF6C9 30%)", glyph: "≡", dark: true }];
    return `<div class="ps home" data-show="${show}"><div class="icons">${apps.map((a) => `<div ${a === special ? 'data-t="go"' : ""}><div class="app${a.dark ? " dark" : ""}" data-style="background:${a.c}">${a.glyph ? (a === special ? a.glyph : `<span class="glyph">${a.glyph}</span>`) : ""}</div><i>${esc(a.n)}</i></div>`).join("")}</div><div class="dock"><span data-style="background:linear-gradient(#5BF675,#21C83F)"></span><span data-style="background:linear-gradient(#6AC6FF,#1E88F5)"></span><span data-style="background:linear-gradient(#5BF675,#21C83F)"></span><span data-style="background:linear-gradient(#FF5E7E,#FA233B)"></span></div></div>`;
  };
  const listScreen = (show, title, items, go, shot) => `<div class="ps slide" data-show="${show}"><h5>${esc(title)}</h5><div class="list">${items.map((it, i) =>
      `<span class="${i === go ? "pick" : ""}" ${i === go ? `data-act="${shot}" data-delay="900" data-t="go"` : ""}>${esc(it)} <i class="chev"></i></span>`).join("")}</div></div>`;

  /* ecranul Windows */
  function monitor(inner) {
    return `<div class="shadow monitor-shadow"></div><div class="actor monitor"><div class="panel"><div class="desk">${inner}
      <div class="taskbar"><div class="winlogo" data-t="start"></div><span class="clock">12:30</span><div class="trayic" data-t="tray"></div></div></div></div>
      <div class="neck"></div><div class="foot"></div></div>`;
  }
  const winWindow = (show, title, left, active, right) => `<div class="win slide" data-show="${show}"><div class="wbar"><span>${esc(title)}</span><span class="wbtn">— ▢ ✕</span></div>
      <div class="side"><div class="menu">${left.map((m, i) => menuItem(m, i, active)).join("")}</div><div class="right">${right}</div></div></div>`;
  const rows = (items, go, shot) => items.map((it, i) => `<div class="row ${i === go ? "pick" : ""}" ${i === go ? `data-act="${shot}" data-delay="900" data-t="go"` : ""}><span>${esc(it)}</span><i class="chev"></i></div>`).join("");

  const toggle = (shot, startOff, delay = 1300) => `<span class="tg ${startOff ? "start-off" : ""}" data-act="${shot}" data-delay="${delay}" data-t="tg"></span>`;
  const checkbox = (shot) => `<span class="cb" data-act="${shot}" data-delay="1300" data-t="tg"></span>`;
  const finger = '<div class="finger"></div>';
  const mouse = '<div class="finger mouse"><svg viewBox="0 0 12 19" width="13" height="20" aria-hidden="true"><path d="M1 1v15.2l3.6-3.4 2.2 5.1 2.1-.9-2.2-5h5z" fill="#fff" stroke="#000" stroke-width="1" stroke-linejoin="round"/></svg></div>';   /* pe laptop și calculator: săgeata mouse-ului */
  const done = (show, text) => `<div class="done" data-show="${show}"><span class="ok"></span><p>${esc(text)}</p></div>`;
  const tag = (show, cls, x, y, text) => `<div class="tag ${cls}" data-show="${show}" data-style="left:${x}px;top:${y}px">${esc(text)}</div>`;

  /* ================= fluxul „pagina web a aparatului” (router, imprimantă) =================
     cadre: 1 găsești aparatul · 2 citești eticheta · 3 scrii adresa · 4 intri cu parola · apoi câte un click pe cadru ·
     acțiunea · salvezi (bifa apare după apăsare). */
  /* CTX.generic = aparatul nu e router: filmul începe din SafeEel (adresa aparatului), nu de la eticheta routerului */
  const CTX = { generic: false, prog: "", dev: "", devip: "", lang: "ro", port: "" };
  const GENERIC_IP = "192.168.1.50";
  function webFilm(o) {
    if (CTX.generic && o.device !== "printer") return genericWebFilm(o);
    const isPrinter = o.device === "printer";
    const n = 4 + o.clicks.length;            // ultimul cadru cu click în meniu
    const act = n + 1, save = n + 2, last = save;
    const pages = [{ show: "4", html: loginPage(isPrinter ? "Imprimantă · autentificare" : "Intră în router", isPrinter ? "" : "admin", 4) }];
    o.clicks.forEach((c, i) => pages.push({ show: String(5 + i), html: c.html(5 + i) }));
    pages.push({ show: list(act, last), html: o.action.html(act, save) });
    const addr = isPrinter ? "192.168.1.40" : "192.168.1.1";
    const url = [{ show: "3", text: addr, typed: "3" }, { show: list(4, o.https ? act : last), text: "http://" + addr }];
    if (o.https) url.push({ show: String(save), text: "https://" + addr, lock: true });
    const deviceHtml = isPrinter ? printerBox("2:turn,3:away") + zoomPrinter("2") : routerBox("2:flip,3:away") + zoomRouter("2");
    const shots = [
      { cap: isPrinter ? "Mergi la imprimantă. Setarea nu e pe ecrănașul ei, ci pe pagina ei din browser." : "Găsește routerul: cutia cu antene pe care ai primit-o odată cu internetul, de la firma de internet." },
      { cap: isPrinter ? "Întoarce-o: pe eticheta din spate e parola (scrie „Pwd”). Adresa ei o vezi în SafeEel." : "Întoarce-l. Pe eticheta de dedesubt scrie adresa, utilizatorul și parola." },
      { cap: `Pe laptop, deschide browserul (programul cu care intri pe internet). Sus, scrie adresa aparatului și apasă Enter.`, f: '[data-t="url"]', tap: true },
      { cap: isPrinter ? "Scrie parola de pe etichetă și apasă „Intră”." : "Scrie utilizatorul și parola de pe etichetă, apoi apasă „Intră”.", f: '[data-shot-page] [data-t="go"]', tap: true },
      ...o.clicks.map((c) => ({ cap: c.cap, f: '[data-shot-page] [data-t="go"]', tap: true })),
      { cap: o.action.cap, f: '[data-shot-page] [data-t="tg"]', tap: true },
      { cap: o.save, f: '[data-shot-page] [data-t="save"]', tap: true },
    ];
    return {
      html: `<div class="floor"></div>${deviceHtml}${tag("1", "info", isPrinter ? 168 : 196, 50, isPrinter ? "imprimanta" : "routerul")}
        ${laptop(list(3, last), url, pages, isPrinter ? "Imprimantă" : "Router")}${o.extraHtml ? o.extraHtml(act, save) : ""}${done(String(last), o.done)}${mouse}`,
      shots, note: o.note,
    };
  }

  function genericWebFilm(o) {
    const n = 4 + o.clicks.length, act = n + 1, save = n + 2, last = save, addr = GENERIC_IP;
    const safeeel = `<div class="safeeel"><b>SafeEel</b> · Dispozitive<div class="row"><span>Aparatul cu problema</span></div>
        <div class="kv">Adresă: <span class="hl" data-t="go">${addr}</span></div><div class="kv tiny">Parola de administrare: pe aparat sau în manual</div></div>`;
    const pages = [{ show: "1,2", html: safeeel }, { show: "4", html: loginPage("Intră în aparat", "admin", 4) }];
    o.clicks.forEach((c, i) => pages.push({ show: String(5 + i), html: c.html(5 + i) }));
    pages.push({ show: list(act, last), html: o.action.html(act, save) });
    const url = [{ show: "1,2", text: "SafeEel" }, { show: "3", text: addr, typed: "3" }, { show: list(4, o.https ? act : last), text: "http://" + addr }];
    if (o.https) url.push({ show: String(save), text: "https://" + addr, lock: true });
    const shots = [
      { cap: `Adresa aparatului o vezi în SafeEel, sub numele problemei.`, f: '[data-shot-page] [data-t="go"]' },
      { cap: "Parola lui de administrare e de obicei pe o etichetă de pe aparat sau în manual." },
      { cap: `Pe laptop, deschide browserul (programul cu care intri pe internet). Sus, scrie adresa aparatului și apasă Enter.`, f: '[data-t="url"]', tap: true },
      { cap: "Scrie utilizatorul și parola aparatului, apoi apasă „Intră”.", f: '[data-shot-page] [data-t="go"]', tap: true },
      ...o.clicks.map((c) => ({ cap: c.cap, f: '[data-shot-page] [data-t="go"]', tap: true })),
      { cap: o.action.cap, f: '[data-shot-page] [data-t="tg"]', tap: true },
      { cap: o.save, f: '[data-shot-page] [data-t="save"]', tap: true },
    ];
    return {
      html: `<div class="floor"></div>${laptop(list(1, last), url, pages, "Aparat")}${o.extraHtml ? o.extraHtml(act, save) : ""}${done(String(last), o.done)}${mouse}`,
      shots, note: o.genericNote || "Meniurile diferă de la un aparat la altul. Caută cuvinte ca „Servicii”, „Administrare” sau „Securitate”.",
    };
  }
  /* o pagină a routerului/imprimantei cu meniul din stânga; `go` = pe ce apeși în cadrul acesta */
  const menuClick = (menu, onIdx, goIdx, rightHtml, cap) => ({ cap, html: (shot) => sidePage(menu, { on: onIdx, go: goIdx, shot }, rightHtml) });
  const finalToggle = (menu, onIdx, title, rowLabel, startOff, cap, saveLabel = "Salvează") => ({
    cap, html: (shot, save) => sidePage(menu, { on: onIdx, go: -1 }, `<h4>${esc(title)}</h4><div class="row"><span>${esc(rowLabel)}</span>${toggle(shot, startOff)}</div>
      <div class="save-row"><span class="btn" data-t="save" data-act="${save}">${esc(saveLabel)}</span></div>`),
  });

  /* ================= fluxul „telefon” ================= */
  function phoneFilm(o) {
    const s0 = o.context ? 2 : 1;          // cadrul în care apeși aplicația
    const clicks = o.screens.length;
    const act = s0 + clicks + 1, last = act + (o.save ? 1 : 0) + 1;
    let screens = homeScreen(list(1, s0), o.app);
    o.screens.forEach((sc, i) => { screens += listScreen(String(s0 + 1 + i), sc.title, sc.items, sc.go, s0 + 1 + i); });
    screens += `<div class="ps slide" data-show="${list(act, last)}">${o.final.html(act, act + 1)}</div>`;
    const shots = [];
    if (o.context) shots.push({ cap: o.context.cap });
    shots.push({ cap: `Pe telefon, deschide aplicația „${o.app.n}”.`, f: '[data-shot-page] [data-t="go"]', tap: true });
    o.screens.forEach((sc) => shots.push({ cap: sc.cap, f: '[data-shot-page] [data-t="go"]', tap: true }));
    shots.push({ cap: o.final.cap, f: '[data-shot-page] [data-t="tg"]', tap: true });
    if (o.save) shots.push({ cap: o.save, f: '[data-shot-page] [data-t="save"]', tap: true });
    shots.push({ cap: o.doneCap });
    return {
      html: `<div class="floor"></div>${o.context ? o.context.html : ""}${phone(o.context && o.context.html ? "right" : "", list(o.context && o.context.html ? 2 : 1, last), screens)}
        ${o.tagHtml || ""}${done(String(last), o.done)}${finger}`,
      shots, note: o.note,
    };
  }

  /* ================= fluxul „Windows” ================= */
  function windowsFilm(o) {
    const pre = o.pre ? o.pre.shots.length : 0;
    const sStart = pre + 1, sSet = pre + 2, sLeft = pre + 3;
    const rights = o.rights.length;
    const act = sLeft + rights + 1, last = act + 1;
    let inner = (o.pre ? o.pre.html : "") +
      `<div class="start slide-up" data-show="${sSet}"><input class="search" value="Caută" disabled><span>Explorer</span><span class="pick" data-act="${sSet}" data-delay="900" data-t="go">Setări</span><span>Browser</span></div>`;
    inner += winWindow(String(sLeft), "Setări", o.left.items, { go: o.left.go, shot: sLeft }, `<div class="muted-big">Bun venit în Setări. Alege o categorie din stânga.</div>`);
    o.rights.forEach((r, i) => {
      const shot = sLeft + 1 + i;
      inner += winWindow(String(shot), "Setări", o.left.items, { on: o.left.go, go: -1 }, `<b class="wt">${esc(r.title)}</b>${rows(r.items, r.go, shot)}`);
    });
    inner += winWindow(list(act, last), "Setări", o.left.items, { on: o.left.go, go: -1 }, `<b class="wt">${esc(o.final.title)}</b>${o.final.html(act)}`);
    const shots = [...(o.pre ? o.pre.shots : []),
      { cap: "Pe calculator, apasă butonul Start: pătratul albastru din bara de jos.", f: '[data-t="start"]', tap: true },
      { cap: "În meniul care se deschide, apasă „Setări” (rotița).", f: '[data-shot-page] [data-t="go"]', tap: true },
      { cap: o.left.cap, f: '[data-shot-page] [data-t="go"]', tap: true },
      ...o.rights.map((r) => ({ cap: r.cap, f: '[data-shot-page] [data-t="go"]', tap: true })),
      { cap: o.final.cap, f: '[data-shot-page] [data-t="tg"]', tap: true },
      { cap: o.doneCap }];
    return { html: `<div class="floor"></div>${monitor(inner)}${o.tagHtml || ""}${done(String(last), o.done)}${mouse}`, shots, note: o.note };
  }


  /* ================= fluxul „Mac”: simbolul din colțul stânga-sus → Setări de sistem → General → Partajare ================= */
  function macFilm(o) {
    const items = ["General", "Rețea", "Bluetooth", "Confidențialitate"];
    const menu = `<div class="macmenu slide-up" data-show="2"><span class="pick" data-act="2" data-delay="900" data-t="go">Setări de sistem…</span><span>Repornește…</span><span>Oprește…</span></div>`;
    const inner = `<div class="macbar"><span class="appleish" data-t="start"></span><b>Finder</b><span>Fișier</span><span>Editare</span></div>${menu}`
      + winWindow("3", "Setări de sistem", items, { go: 0, shot: 3 }, `<div class="muted-big">Alege o categorie din stânga.</div>`)
      + winWindow("4", "General", items, { on: 0, go: -1 }, `<b class="wt">General</b>${rows(["Despre", "Actualizare software", "Partajare", "Data și ora"], 2, 4)}`)
      + winWindow("5,6", "Partajare", items, { on: 0, go: -1 }, `<b class="wt">Partajare</b><div class="row dim"><span>Partajarea internetului</span></div><div class="row"><span>${esc(o.item)}</span>${toggle(5, false)}</div>`);
    const shots = [
      { cap: "Pe Mac, apasă simbolul din colțul din stânga-sus al ecranului." , f: '[data-t="start"]', tap: true },
      { cap: "În meniul care se deschide, apasă „Setări de sistem…”.", f: '[data-shot-page] [data-t="go"]', tap: true },
      { cap: "În stânga, apasă „General”.", f: '[data-shot-page] [data-t="go"]', tap: true },
      { cap: "În dreapta, apasă „Partajare”.", f: '[data-shot-page] [data-t="go"]', tap: true },
      { cap: o.cap, f: '[data-shot-page] [data-t="tg"]', tap: true },
      { cap: o.doneCap },
    ];
    return { html: `<div class="floor"></div>${monitor(inner).replace('class="actor monitor"', 'class="actor monitor mac"')}${done("6", o.done)}${mouse}`, shots, note: o.note };
  }

  /* ================= aparatul necunoscut: cum afli care e =================
     Legătura e ADRESA: SafeEel o arată, iar routerul o arată lângă fiecare aparat. Apoi testul simplu:
     stingi pe rând aparatele din casă; cel care dispare din listă e el. */
  function unknownFilm() {
    const IP = "192.168.1.23";
    const devRow = (icon, name, ip, extra = "") => `<div class="row devrow ${extra}"><span>${esc(name)}</span><span class="ipc">${ip}</span></div>`;
    const listHead = '<h4>Aparate conectate</h4><div class="row head"><span>Nume</span><span class="ipc">Adresă</span></div>';
    const pages = [
      { show: "1", html: `<div class="safeeel"><b>SafeEel</b> · Dispozitive<div class="row"><span>Dispozitiv necunoscut</span></div>
          <div class="kv">Adresă: <span class="hl" data-t="go">${IP}</span></div><div class="kv tiny">Producător: necunoscut</div></div>` },
      { show: "4", html: loginPage("Intră în router", "admin", 4) },
      { show: "5", html: sidePage(ROUTER_MENU, { on: 0, go: -1 }, '<h4>Stare</h4><div class="row"><span>Internet</span><b class="okc">Conectat</b></div><div class="row pick" data-act="5" data-delay="900" data-t="go"><span>Aparate conectate</span><b>5 ›</b></div>') },
      { show: "6", html: listHead + devRow("💻", "Laptopul meu", "192.168.1.10") + devRow("📱", "Telefonul meu", "192.168.1.12") +
          `<div class="row devrow pick" data-act="6" data-delay="700" data-t="go"><span>Necunoscut</span><span class="ipc"><span class="hl">${IP}</span></span></div>` },
      { show: "7", html: listHead + devRow("💻", "Laptopul meu", "192.168.1.10") + devRow("📱", "Telefonul meu", "192.168.1.12") +
          `<div class="row devrow gone" data-act="7" data-delay="1500" data-t="go"><span>Necunoscut <em class="off-note">deconectat</em></span><span class="ipc">${IP}</span></div>` },
      { show: "8", html: listHead + devRow("💻", "Laptopul meu", "192.168.1.10") + devRow("📱", "Telefonul meu", "192.168.1.12") +
          `<div class="row devrow named" data-t="tg"><span><span class="typed" data-act="8" data-delay="400">Televizor sufragerie</span></span><span class="ipc">${IP}</span></div>` },
      /* ramura a doua: ai stins tot și aparatul tot apare = nu e al nimănui din casă → îl blochezi și schimbi parola Wi-Fi */
      { show: "9", html: listHead + devRow("", "Laptopul meu", "192.168.1.10") + devRow("", "Telefonul meu", "192.168.1.12") +
          `<div class="row devrow pick" data-act="9" data-delay="300"><span>Necunoscut <em class="still-on">tot conectat</em></span><span class="btn danger" data-t="go" data-act="9">Blochează</span></div>` },
      { show: "10", html: sidePage(ROUTER_MENU, { on: 1, go: -1 }, `<h4>Wi-Fi</h4>Numele rețelei<div class="field">Casa-Popescu</div>Parola Wi-Fi<div class="field" data-t="tg"><span class="typed" data-act="10" data-delay="400">Brad-Lac-Soare-58</span></div><span class="btn" data-t="save">Salvează</span>`) },
    ];
    const url = [{ show: "1", text: "SafeEel" }, { show: "3", text: "192.168.1.1", typed: "3" }, { show: "4,5,6,7,8,9,10", text: "http://192.168.1.1" }];
    const tv = `<div class="actor tv" data-show="7,8"><div class="tvscreen" data-act="7" data-delay="900"></div><div class="tvstand"></div><span class="tvlabel">televizorul</span></div>`;
    return {
      html: `<div class="floor"></div>${routerBox("1:away,2:flip,3:away")}${zoomRouter("2")}
        ${laptop("1,3,4,5,6,7,8,9,10", url, pages)}${tv}${done("8", "Aparat identificat · Televizor sufragerie")}${done("10", "Aparat blocat · parolă Wi-Fi nouă")}${mouse}`,
      shots: [
        { cap: `În SafeEel, uită-te la adresa aparatului necunoscut. După ea îl recunoști în router.`, f: '[data-shot-page] [data-t="go"]' },
        { cap: "Găsește routerul: cutia cu antene pe care ai primit-o odată cu internetul, de la firma de internet. Întoarce-l: pe eticheta de dedesubt e adresa și parola lui." },
        { cap: "Pe laptop, scrie în browser adresa routerului: <b>192.168.1.1</b>. Apasă Enter.", f: '[data-t="url"]', tap: true },
        { cap: "Scrie utilizatorul și parola de pe etichetă, apoi apasă „Intră”.", f: '[data-shot-page] [data-t="go"]', tap: true },
        { cap: "Apasă „Aparate conectate”.", f: '[data-shot-page] [data-t="go"]', tap: true },
        { cap: `Caută în listă rândul cu aceeași adresă. El e aparatul.`, f: '[data-shot-page] [data-t="go"]' },
        { cap: "Nu știi ce e? Stinge pe rând aparatele din casă (televizorul, imprimanta…). Cel care trece pe „deconectat” e el.", f: '[data-shot-page] [data-t="go"]' },
        { cap: "L-ai găsit și e al tău? Dă-i un nume (aici: „Televizor sufragerie”), ca să-l recunoști data viitoare.", f: '[data-shot-page] [data-t="tg"]' },
        { cap: "Ai stins tot ce e în casă și tot apare „conectat”? Atunci nu e al tău. Apasă „Blochează” lângă el.", f: '[data-shot-page] [data-t="go"]', tap: true },
        { cap: "Apoi, în stânga, la „Wi-Fi”, scrie o parolă nouă și lungă și apasă „Salvează”. Pune-o din nou pe telefoanele și laptopurile tale.", f: '[data-shot-page] [data-t="save"]', tap: true },
      ],
      note: "Înainte să blochezi, întreabă și pe cei din casă: telefoanele noi apar uneori fără nume. Blocarea singură nu ajunge: cine are parola Wi-Fi poate intra de pe alt aparat, de aceea schimbi și parola.",
    };
  }


  /* ================= filmele paginilor (Live, Ce știe SafeEel): pagina se construiește în jurul lor ================= */
  const ntf = (shot, delay, title, text) => `<div class="ntf" data-act="${shot}" data-delay="${delay}"><b>${esc(title)}</b><span>${esc(text)}</span></div>`;

  /* parola hotspotului, pe telefon: Setări → Hotspot personal → Parola Wi-Fi → parolă nouă → Gata. s = primul cadru */
  function hotspotPw(s) {
    const settings = { n: "Setări", c: "linear-gradient(#AEB4BC,#8E8E93)", glyph: '<span class="glyph">⚙</span>' };
    const sh = list(s, s + 4);
    const screens = homeScreen(String(s), settings)
      + listScreen(String(s + 1), "Setări", ["Wi-Fi", "Bluetooth", "Hotspot personal", "Notificări"], 2, s + 1)
      + `<div class="ps slide" data-show="${s + 2}"><h5>Hotspot personal</h5><div class="list"><span>Permite altora să se conecteze</span><span class="pick" data-act="${s + 2}" data-delay="900" data-t="go">Parola Wi-Fi <i class="chev"></i></span></div></div>`
      + `<div class="ps slide" data-show="${s + 3},${s + 4}"><h5>Parola Wi-Fi</h5><div class="field" data-t="tg"><span class="typed" data-act="${s + 3}" data-delay="400">Brad-Lac-Soare-58</span></div><span class="btn" data-t="save">Gata</span></div>`;
    return {
      html: phone("", sh, screens) + done(String(s + 4), "Parolă nouă · străinul a ieșit"),
      shots: [
        { cap: "Pe telefonul cu hotspotul, deschide „Setări” (rotița gri).", f: '[data-shot-page] [data-t="go"]', tap: true, touch: true },
        { cap: "Apasă „Hotspot personal”.", f: '[data-shot-page] [data-t="go"]', tap: true, touch: true },
        { cap: "Apasă „Parola Wi-Fi”.", f: '[data-shot-page] [data-t="go"]', tap: true, touch: true },
        { cap: "Șterge parola veche și scrie una nouă, lungă. Apasă „Gata”.", f: '[data-shot-page] [data-t="save"]', tap: true, touch: true },
        { cap: "Gata: cine nu știe parola nouă iese din hotspot. Pune parola nouă și pe aparatele tale.", touch: true },
      ],
      note: "Pe alte telefoane: „Setări” → „Conexiuni” → „Hotspot mobil” → „Parolă”. La routerul de acasă, parola Wi-Fi se schimbă din pagina lui, la „Wi-Fi”.",
    };
  }
  function hotspotPwFilm() { const h = hotspotPw(1); return { html: `<div class="floor"></div>${h.html}${finger}`, shots: h.shots, note: h.note }; }
  /* Live: pornești protecția, apoi vezi pe loc cine intră în hotspot */
  function liveFilm() {
    const head = (on) => `<div class="safeeel"><b>SafeEel</b> · Live</div><div class="row"><span>Protecția live</span>${on ? '<b class="okc">● pornită</b>' : '<b class="offc">oprită</b>'}</div>`;
    const devs = '<div class="row devrow"><span>Laptopul meu</span><span class="ipc">acum</span></div><div class="row devrow"><span>Telefonul cu hotspotul</span><span class="ipc">acum</span></div>';
    const pages = [
      { show: "1", html: head(false) + '<div class="kv tiny">Urmărește cine intră în hotspot.</div><span class="btn" data-t="go">Pornește protecția</span>' },
      { show: "2", html: head(true) + '<h4>În hotspot acum</h4>' + devs },
      { show: "3", html: head(true) + '<h4>În hotspot acum</h4>' + devs + '<div class="row devrow newrow pick" data-act="3" data-delay="700" data-t="go"><span>Aparat nou</span><span class="ipc">acum</span></div>' + ntf(3, 1300, "SafeEel", "Aparat nou în hotspot") },
      { show: "4", html: head(true) + '<h4>În hotspot acum</h4>' + devs + '<div class="row devrow pick" data-act="4" data-delay="900" data-t="go"><span>Aparat nou</span><span class="ipc">acum</span></div>' },
      { show: "5", html: '<div class="safeeel"><b>SafeEel</b> · Aparat nou</div><div class="kv">Producător: <span class="hl">necunoscut</span></div><div class="kv">A intrat: <b>acum</b></div><div class="row"><span>Nu e al tău? Schimbă parola hotspotului.</span></div>' },
    ];
    const url = [{ show: "1,2,3,4,5", text: "SafeEel" }];
    const pw = hotspotPw(6);
    return {
      html: `<div class="floor"></div>${laptop("1,2,3,4,5", url, pages, "SafeEel")}${pw.html}${mouse}`,
      shots: [
        { cap: "Pe laptopul legat la hotspot, apasă „Pornește protecția”.", f: '[data-shot-page] [data-t="go"]', tap: true, touch: false },
        { cap: "Gata, e pornită. SafeEel vede aparatele din hotspot.", touch: false },
        { cap: "Intră cineva nou? Apare pe loc în listă și primești un mesaj.", f: '[data-shot-page] [data-t="go"]', touch: false },
        { cap: "Apasă pe el ca să vezi ce e.", f: '[data-shot-page] [data-t="go"]', tap: true, touch: false },
        { cap: "Nu-l cunoști? Schimbă parola hotspotului, pe telefon. Îți arătăm cum.", touch: false },
      ].concat(pw.shots),
      note: pw.note,
    };
  }
  /* Ce știe SafeEel: adresa unică ascunsă, totul rămâne pe calculator, doar rețeaua echipei, ștergi tot dintr-un buton */
  function trustFilm() {
    const mac = (shot) => `<span class="macx" data-act="${shot}" data-delay="1300"><span class="m-full">66:48:42:A1:B2:C3</span><span class="m-mask">66:48:42:XX:XX:XX</span></span>`;
    const pages = [
      { show: "1", html: `<div class="safeeel"><b>SafeEel</b> · Dispozitive</div><div class="row"><span>Imprimanta</span></div><div class="kv" data-t="go">Adresa unică: ${mac(1)}</div>` },
      { show: "2", html: '<div class="safeeel"><b>SafeEel</b> · Unde stau datele</div><div class="row"><span>Istoricul și alertele</span><b class="okc">pe acest laptop</b></div><div class="row"><span>Scanările</span><b class="okc">pe acest laptop</b></div><div class="row" data-t="go"><span>Internet</span><b class="offc">nimic trimis</b></div>' },
      { show: "3", html: '<div class="safeeel"><b>SafeEel</b> · Ce scanăm</div><div class="row" data-t="go"><span>Hotspotul echipei</span><b class="okc">da</b></div><div class="row"><span>Rețeaua vecinului</span><b class="offc">niciodată</b></div><div class="row"><span>Internetul</span><b class="offc">niciodată</b></div>' },
      { show: "4", html: '<div class="safeeel"><b>SafeEel</b> · Ce știe despre tine</div><div class="row"><span>Scanări salvate</span><b>4</b></div><div class="row"><span>Alerte</span><b>5</b></div><span class="btn danger" data-t="go">Șterge istoricul meu</span>' },
      { show: "5", html: '<div class="safeeel"><b>SafeEel</b> · Ce știe despre tine</div><div class="row dim"><span>Scanări salvate</span><b>0</b></div><div class="row dim"><span>Alerte</span><b>0</b></div>' },
    ];
    const url = [{ show: "1,2,3,4,5", text: "SafeEel" }];
    return {
      html: `<div class="floor"></div>${laptop("1,2,3,4,5", url, pages, "SafeEel")}${done("5", "Istoric șters")}${mouse}`,
      shots: [
        { cap: "Adresa unică a fiecărui aparat o ascundem. Rămâne doar începutul, care arată producătorul.", f: '[data-shot-page] [data-t="go"]' },
        { cap: "Tot ce vezi stă doar pe acest laptop. Nimic nu pleacă pe internet.", f: '[data-shot-page] [data-t="go"]' },
        { cap: "Verificăm doar hotspotul echipei. Nicio altă rețea.", f: '[data-shot-page] [data-t="go"]' },
        { cap: "Vrei să ștergi tot? Apasă „Șterge istoricul meu”.", f: '[data-shot-page] [data-t="go"]', tap: true },
        { cap: "Gata: pe laptop nu mai rămâne nimic." },
      ],
    };
  }


  /* Dispozitive: vezi tot ce e conectat; aparatul cu probleme → ce are → cum repari */
  function devicesFilm() {
    const lst = (pick) => `<div class="safeeel"><b>SafeEel</b> · Dispozitive</div>
      <div class="row"><span>Routerul</span><b class="okc">în regulă</b></div>
      <div class="row${pick ? " pick" : ""}" ${pick ? `data-act="${pick}" data-delay="900" data-t="go"` : 'data-t="go"'}><span>Imprimanta</span><b class="badc">2 probleme</b></div>
      <div class="row"><span>Telefonul meu</span><b class="okc">în regulă</b></div><div class="row"><span>Televizorul</span><b class="okc">în regulă</b></div>`;
    const pages = [
      { show: "1", html: lst(0) },
      { show: "2", html: lst(2) },
      { show: "3", html: '<div class="safeeel"><b>SafeEel</b> · Imprimanta</div><div class="row"><span>Oricine poate printa la tine</span><b class="badc">risc</b></div><div class="row"><span>Pagina ei e fără parolă</span><b class="badc">risc</b></div><span class="btn" data-t="go">Arată-mi cum repar</span>' },
      { show: "4", html: '<div class="safeeel"><b>SafeEel</b> · Acasă</div><div class="row"><span>Pasul 1: mergi la imprimantă</span></div><div class="row dim"><span>Pasul 2: întoarce-o</span></div><div class="row dim"><span>Pasul 3: deschide pagina ei</span></div>' },
    ];
    const url = [{ show: "1,2,3,4", text: "SafeEel" }];
    return {
      html: `<div class="floor"></div>${laptop("1,2,3,4", url, pages, "SafeEel")}${done("4", "Pașii te așteaptă pe Acasă")}${mouse}`,
      shots: [
        { cap: "Aici vezi tot ce e conectat la rețeaua ta.", f: '[data-shot-page] [data-t="go"]' },
        { cap: "Un aparat are probleme? Apasă pe el.", f: '[data-shot-page] [data-t="go"]', tap: true },
        { cap: "Vezi ce are. Apasă „Arată-mi cum repar”.", f: '[data-shot-page] [data-t="go"]', tap: true },
        { cap: "Gata: pe Acasă îți arătăm fiecare pas, pe rând." },
      ],
    };
  }
  /* Alerte: ce s-a schimbat în rețea, pe scurt */
  function journalFilm() {
    const head = '<div class="safeeel"><b>SafeEel</b> · Alerte</div>';
    const a1 = (c) => `<div class="row ${c}" data-act="1" data-delay="700"><span>Aparat nou în rețea</span><b class="warnc">nou</b></div>`;
    const a2 = (c) => `<div class="row ${c}" data-act="2" data-delay="700"><span>O problemă a dispărut</span><b class="okc">rezolvat</b></div>`;
    const a3 = (c) => `<div class="row ${c}" data-act="3" data-delay="700"><span>Scorul rețelei: 30 → 85</span><b class="okc">a crescut</b></div>`;
    const pages = [
      { show: "1", html: head + a1("newrow") },
      { show: "2", html: head + a1("") + a2("newrow") },
      { show: "3", html: head + a1("") + a2("") + a3("newrow") },
      { show: "4", html: head + a1("") + a2("") + a3("") + '<span class="btn" data-t="go">Vezi comparația</span>' },
      { show: "5", html: '<div class="safeeel"><b>SafeEel</b> · Înainte și acum</div><div class="row"><span>Probleme</span><b>6 → 2</b></div><div class="row"><span>Aparate</span><b>3 → 4</b></div><div class="row"><span>Scor</span><b class="okc">30 → 85</b></div>' },
    ];
    const url = [{ show: "1,2,3,4,5", text: "SafeEel" }];
    return {
      html: `<div class="floor"></div>${laptop("1,2,3,4,5", url, pages, "SafeEel")}${done("5", "Totul e notat")}${mouse}`,
      shots: [
        { cap: "Intră un aparat nou în rețea? Apare aici." },
        { cap: "Ai reparat ceva? Vezi și asta: „rezolvat”." },
        { cap: "Și vezi cum se schimbă scorul rețelei." },
        { cap: "Vrei detalii? Apasă „Vezi comparația”.", f: '[data-shot-page] [data-t="go"]', tap: true },
        { cap: "Vezi ce era înainte și ce e acum." },
      ],
    };
  }
  /* Progres: scorul crește când repari */
  function historyFilm() {
    const head = '<div class="safeeel"><b>SafeEel</b> · Progres</div>';
    const r1 = '<div class="row"><span>7 nov · prima scanare</span><b class="badc">30</b></div>';
    const r2 = (c) => `<div class="row ${c}" data-act="2" data-delay="700"><span>8 nov · după reparații</span><b class="okc">85 ▲</b></div>`;
    const bars = (grow) => `<div class="sbars"><div><i class="sb s30"></i><span>7 nov · 30</span></div><div><i class="sb s85${grow ? "" : " act"}" ${grow ? `data-act="${grow}" data-delay="500"` : ""}></i><span>8 nov · 85</span></div></div>`;
    const pages = [
      { show: "1", html: head + r1 },
      { show: "2", html: head + r1 + r2("newrow") },
      { show: "3", html: head + bars(3) },
      { show: "4", html: head + bars(0) + '<span class="btn" data-t="go">Vezi dovada</span>' },
      { show: "5", html: '<div class="safeeel"><b>SafeEel</b> · Dovada</div><div class="row"><span>Probleme rezolvate</span><b class="okc">4</b></div><div class="row"><span>Probleme rămase</span><b>2</b></div>' },
    ];
    const url = [{ show: "1,2,3,4,5", text: "SafeEel" }];
    return {
      html: `<div class="floor"></div>${laptop("1,2,3,4,5", url, pages, "SafeEel")}${done("5", "Rețeaua e mai sigură")}${mouse}`,
      shots: [
        { cap: "Fiecare scanare salvată apare aici, cu scorul ei." },
        { cap: "Repari, scanezi din nou, iar scorul crește." },
        { cap: "Graficul îți arată drumul, de la o scanare la alta." },
        { cap: "Apasă „Vezi dovada” ca să vezi ce s-a reparat.", f: '[data-shot-page] [data-t="go"]', tap: true },
        { cap: "Gata: vezi clar ce ai reparat." },
      ],
    };
  }


  /* Bun venit: ce face SafeEel, în 5 cadre (scanezi, apar aparatele, scorul, primul pas, verifici) */
  function welcomeFilm() {
    const head = (t) => `<div class="safeeel"><b>SafeEel</b> · ${t}</div>`;
    const devs = (act) => ["Routerul", "Imprimanta", "Telefonul tău"].map((n, k) =>
      `<div class="row newrow" data-act="${act}" data-delay="${600 + k * 700}"><span>${n}</span><b class="okc">găsit</b></div>`).join("");
    const pages = [
      { show: "1", html: head("Bun venit") + '<div class="kv tiny">Prima ta scanare completă</div><span class="btn" data-t="go">Scanează acum</span>' },
      { show: "2", html: head("Scanez") + '<div class="pbar"><i data-act="2" data-delay="200"></i></div><div class="kv tiny">Caut aparatele din hotspot…</div>' + devs(2) },
      { show: "3", html: head("Acasă") + '<div class="wscore"><span class="wnum">70</span><span>din 100</span></div><div class="row"><span>3 lucruri de reparat</span><b class="badc">vezi</b></div>' },
      { show: "4", html: head("Acasă") + '<div class="row"><span>Pasul 1: mergi la router</span></div><div class="row dim"><span>Pasul 2: întoarce-l</span></div><span class="btn" data-t="go">Am făcut asta, verifică</span>' },
      { show: "5", html: head("Acasă") + '<div class="wscore"><span class="wnum good">85</span><span>din 100</span></div><div class="row"><span>Pasul 1</span><b class="okc">reparat</b></div>' },
    ];
    const url = [{ show: "1,2,3,4,5", text: "SafeEel" }];
    return {
      html: `<div class="floor"></div>${laptop("1,2,3,4,5", url, pages, "SafeEel")}${done("5", "Rețeaua e mai sigură")}${mouse}`,
      shots: [
        { cap: "Apeși „Scanează acum”. SafeEel verifică singur rețeaua.", f: '[data-shot-page] [data-t="go"]', tap: true },
        { cap: "Găsește toate aparatele din hotspot: routerul, imprimanta, telefoanele." },
        { cap: "Primești un scor: cu cât e mai aproape de 100, cu atât ești mai în siguranță." },
        { cap: "Pentru fiecare problemă îți arătăm, pas cu pas, ce faci. Apoi apeși „verifică”.", f: '[data-shot-page] [data-t="go"]', tap: true },
        { cap: "Am verificat pe loc: problema a dispărut, iar scorul crește." },
      ],
    };
  }

  /* ================= filmele ================= */
  const ROUTER_MENU = ["Stare", "Wi-Fi", "Avansat", "Sistem"];
  const homeRight = '<h4>Stare</h4><div class="row"><span>Internet</span><b class="okc">Conectat</b></div><div class="row"><span>Aparate conectate</span><b>5</b></div>';

  const FILMS = [
    { code: "FTP_CLEARTEXT", title: "FTP pe hotspotul de pe telefon", make: () => phoneFilm({
      context: { cap: "Internetul tău vine din hotspotul acestui telefon. Pe telefon, serviciile lui nu se pot opri separat.", html: '' },
      app: { n: "Setări", c: "linear-gradient(#AEB4BC,#8E8E93)", glyph: '<span class="glyph">⚙</span>' },
      screens: [{ title: "Setări", items: ["Wi-Fi", "Bluetooth", "Hotspot personal", "Notificări"], go: 2, cap: "Apasă pe „Hotspot personal”." }],
      final: { cap: "Oprește „Permite altora să se conecteze” cât nu ai nevoie de hotspot.", html: (s) => `<h5>Hotspot personal</h5><div class="list"><span>Permite altora să se conecteze ${toggle(s, false).replace("span", "i").replace("</span>", "</i>")}</span><span>Parola Wi-Fi <i class="chev"></i></span></div><div class="note">Pornește-l din nou doar când ai nevoie de internet pe laptop.</div>` },
      doneCap: "Gata: nimeni nu mai intră în rețeaua telefonului cât hotspotul e oprit.", done: "Hotspot oprit",
      tagHtml: tag("1", "info", 14, 18, "telefonul cu hotspotul"),
    }) },
    { code: "UPNP_EXPOSED", title: "Uși deschise singure în router (UPnP)", make: () => webFilm({
      clicks: [
        menuClick(ROUTER_MENU, 0, 2, homeRight, "În meniul din stânga, apasă „Avansat”."),
        menuClick(["Stare", "Wi-Fi", "Avansat", "  NAT Forwarding", "  Firewall", "  Rețea oaspeți", "Sistem"], 2, 3, '<h4>Avansat</h4><div class="row"><span>NAT Forwarding</span><i class="chev"></i></div><div class="row"><span>Firewall</span><i class="chev"></i></div><div class="row"><span>Rețea pentru oaspeți</span><i class="chev"></i></div>', "Sub „Avansat” s-au deschis mai multe opțiuni. Dintre ele, apasă „NAT Forwarding”."),
      ],
      action: finalToggle(["Stare", "Wi-Fi", "Avansat", "  NAT Forwarding", "  Firewall", "  Rețea oaspeți", "Sistem"], 3, "NAT Forwarding › UPnP", "UPnP", false, "Găsește rândul „UPnP” și mută butonul pe „Oprit”."),
      save: "Apasă „Salvează”.", done: "Setări salvate · UPnP oprit",
      note: "Meniul diferă puțin de la un router la altul. Dacă nu găsești „NAT Forwarding”, caută „UPnP” la „WAN” sau „Avansat”.",
    }) },
    { code: "TELNET_OPEN", title: "Intrare veche, fără lacăt (Telnet)", make: () => webFilm({
      clicks: [
        menuClick(ROUTER_MENU, 0, 3, homeRight, "În meniul din stânga, apasă „Sistem” (la unele routere: „Administrare”)."),
        menuClick(["Stare", "Wi-Fi", "Avansat", "Sistem", "  Administrare", "  Actualizare firmware", "  Repornire"], 3, 4, '<h4>Sistem</h4><div class="row"><span>Administrare</span><i class="chev"></i></div><div class="row"><span>Actualizare firmware</span><i class="chev"></i></div><div class="row"><span>Ora și data</span><i class="chev"></i></div>', "Sub „Sistem” s-au deschis mai multe opțiuni. Dintre ele, apasă „Administrare”."),
      ],
      action: finalToggle(["Stare", "Wi-Fi", "Avansat", "Sistem", "  Administrare", "  Actualizare firmware", "  Repornire"], 4, "Administrare", "Telnet", false, "Găsește „Telnet” și mută butonul pe „Oprit”."),
      save: "Apasă „Salvează”. Apoi schimbă și parola routerului.", done: "Setări salvate · Telnet oprit",
      note: "Dacă nu găsești Telnet în meniu, actualizează routerul sau întreabă producătorul.",
    }) },
    { code: "SNMP_EXPOSED", title: "Aparatul își spune detaliile oricui (SNMP)", make: () => webFilm({
      clicks: [
        menuClick(ROUTER_MENU, 0, 3, homeRight, "În meniul din stânga, apasă „Sistem” (sau „Administrare”)."),
        menuClick(["Stare", "Wi-Fi", "Avansat", "Sistem", "  Administrare", "  Actualizare firmware", "  Repornire"], 3, 4, '<h4>Sistem</h4><div class="row"><span>Administrare</span><i class="chev"></i></div><div class="row"><span>Actualizare firmware</span><i class="chev"></i></div><div class="row"><span>Ora și data</span><i class="chev"></i></div>', "Sub „Sistem” s-au deschis mai multe opțiuni. Dintre ele, apasă „Administrare”."),
      ],
      action: finalToggle(["Stare", "Wi-Fi", "Avansat", "Sistem", "  Administrare", "  Actualizare firmware", "  Repornire"], 4, "Administrare", "SNMP", false, "Găsește „SNMP” și mută butonul pe „Oprit”."),
      save: "Apasă „Salvează”.", done: "Setări salvate · SNMP oprit",
      note: "Multe routere de casă nu au SNMP deloc în meniu. Atunci actualizează routerul.",
    }) },
    { code: "HTTP_ADMIN_CLEARTEXT", title: "Pagina de setări nu e criptată", make: () => webFilm({
      https: true,
      clicks: [
        menuClick(ROUTER_MENU, 0, 3, homeRight, "În meniul din stânga, apasă „Sistem”."),
        menuClick(["Stare", "Wi-Fi", "Avansat", "Sistem", "  Administrare", "  Actualizare firmware", "  Repornire"], 3, 4, '<h4>Sistem</h4><div class="row"><span>Administrare</span><i class="chev"></i></div><div class="row"><span>Actualizare firmware</span><i class="chev"></i></div><div class="row"><span>Ora și data</span><i class="chev"></i></div>', "Sub „Sistem” s-au deschis mai multe opțiuni. Dintre ele, apasă „Administrare”."),
      ],
      action: finalToggle(["Stare", "Wi-Fi", "Avansat", "Sistem", "  Administrare", "  Actualizare firmware", "  Repornire"], 4, "Administrare", "Acces local prin HTTPS", true, "Pornește „Acces local prin HTTPS”."),
      save: "Apasă „Salvează”. De acum intră doar pe adresa cu https:// (cu lacăt sus).", done: "Setări salvate · folosește https://",
    }) },
    { code: "OUTDATED_SERVICE", title: "Program vechi, cu defecte cunoscute", make: () => webFilm({
      clicks: [menuClick(ROUTER_MENU, 0, 3, homeRight, "În meniul din stânga, apasă „Sistem”.")],
      action: { cap: "Apasă „Actualizare firmware”, apoi „Actualizează”. Durează câteva minute.", html: (s, save) => sidePage(ROUTER_MENU, { on: 3, go: -1 }, `<h4>Actualizare firmware</h4>Versiune nouă disponibilă<div class="save-row"><span class="btn" data-t="tg">Actualizează</span></div><div class="progress"><i data-act="${s}" data-delay="1400"></i></div><div class="tiny" data-show="${save}">Gata, routerul a repornit singur.</div><span data-t="save"></span>`) },
      save: "Nu scoate routerul din priză până nu termină. Repornește singur.", done: "Router actualizat",
      extraHtml: (s) => tag(String(s), "bad", 64, 206, "Nu scoate routerul din priză!"),
    }) },
    { code: "UNKNOWN_DEVICE", title: "Aparat pe care nu l-am recunoscut", make: unknownFilm },
    { code: "PRINTER_RAW_EXPOSED", title: "Imprimanta printează pentru oricine", make: () => webFilm({
      device: "printer",
      clicks: [
        menuClick(["Stare", "Rețea", "Securitate"], 0, 1, '<h4>Stare</h4><div class="row"><span>Cerneală</span><b>70%</b></div>', "Sus sau în stânga, apasă „Rețea”."),
        menuClick(["Stare", "Rețea", "  Protocol", "  Wi-Fi", "  Adresă IP", "Securitate"], 1, 2, '<h4>Rețea</h4><div class="row"><span>Protocol</span><i class="chev"></i></div><div class="row"><span>Wi-Fi</span><i class="chev"></i></div><div class="row"><span>Adresă IP</span><i class="chev"></i></div>', "Sub „Rețea” s-au deschis mai multe opțiuni. Dintre ele, apasă „Protocol”."),
      ],
      action: { cap: "Debifează „Raw Port (9100)”. Lasă bifat „IPP” (prin el printezi de pe calculator).", html: (s, save) => sidePage(["Stare", "Rețea", "  Protocol", "  Wi-Fi", "  Adresă IP", "Securitate"], { on: 2, go: -1 }, `<h4>Protocol</h4><div class="row"><span>IPP</span><span class="cb keep"></span></div><div class="row"><span>Raw Port (9100)</span>${checkbox(s)}</div><div class="save-row"><span class="btn" data-t="save">Trimite</span></div>`) },
      save: "Apasă „Trimite” (sau „Aplică”).", done: "Setări salvate · Raw Port oprit",
      note: "Setarea e pe pagina imprimantei din browser, nu în driver. Numele diferă puțin de la o imprimantă la alta (RAW sau Port 9100). Dacă pagina nu se deschide, folosește aplicația imprimantei de pe telefon. Unele imprimante trebuie repornite după schimbare.",
    }) },
    { code: "CAMERA_STREAM_EXPOSED", title: "Imaginea camerei se vede din rețea", make: () => phoneFilm({
      context: { cap: "Camera ta are încă parola din fabrică. Pe aceea o găsește oricine pe internet.",
        html: '<div class="actor ccam"><div class="cc-wall"></div><div class="cc-plate"><i></i><i></i></div><div class="cc-arm"></div><div class="cc-joint"></div><div class="cc-cable"></div><div class="cc-body"><div class="cc-hood"></div><div class="cc-ring"></div><div class="cc-face"><span class="cc-ir"></span><span class="cc-lens"></span></div><span class="cc-led"></span></div></div>' + tag("1,2,3,4,5,6", "bad", 70, 186, "parola din fabrică: admin") },
      app: { n: "Camera mea", c: "linear-gradient(#5AC8FA,#3333FF)", glyph: '<span class="glyph">◉</span>' },
      screens: [
        { title: "Camera sufragerie", items: ["Live", "Înregistrări", "Setări"], go: 2, cap: "Apasă „Setări”." },
        { title: "Setări", items: ["Notificări", "Parolă dispozitiv", "Wi-Fi"], go: 1, cap: "Apasă „Parolă dispozitiv”." },
      ],
      final: { cap: "Scrie o parolă lungă, doar a ta (de exemplu trei cuvinte și un număr).", html: (s) => `<h5>Parolă dispozitiv</h5>Parolă nouă<div class="pw" data-t="tg"><span class="typed" data-act="${s}" data-delay="500">Soare-Lac-27!</span></div><div class="meter"><i data-act="${s}" data-delay="500"></i></div><div class="save-row"><span class="btn" data-t="save">Salvează</span></div>` },
      save: "Apasă „Salvează”.", doneCap: "Gata: doar tu mai vezi ce filmează camera.", done: "Parolă schimbată",
    }) },
    { code: "MQTT_EXPOSED", title: "Mesajele aparatelor smart, la vedere (MQTT)", make: () => phoneFilm({
      context: { cap: "Oricine din rețea poate da comenzi becurilor și senzorilor tăi. Chiar să le stingă.",
        html: '<div class="bulb-light" data-act="1" data-delay="1500"></div><div class="actor bulb2"><div class="cord"></div><div class="socket"></div><div class="screw"></div><div class="neck"></div><div class="glass2" data-act="1" data-delay="1500"></div></div>' + tag("1", "bad", 104, 120, "cineva din rețea l-a stins") },
      app: { n: "Casa mea", c: "linear-gradient(#FFD60A,#FF9F0A)", glyph: '<span class="glyph">⌂</span>' },
      screens: [
        { title: "Casa mea", items: ["Camere", "Automatizări", "Setări"], go: 2, cap: "Apasă „Setări”." },
        { title: "Setări", items: ["Cont", "Securitate", "Aparate"], go: 1, cap: "Apasă „Securitate”." },
      ],
      final: { cap: "Pornește „Cere parolă de la aparate”.", html: (s) => `<h5>Securitate</h5><div class="list"><span>Cere parolă de la aparate ${toggle(s, true).replace("span", "i").replace("</span>", "</i>")}</span><span>Criptare (TLS) <i class="tg start-off" data-act="${s}" data-delay="2000"></i></span></div><div class="note">Aparatele tale primesc parola automat, din aplicație.</div>` },
      doneCap: "Gata: comenzile străinilor sunt ignorate.", done: "Aparatele cer acum parolă",
    }) },
    { code: "RDP_EXPOSED", title: "Desktop la distanță, deschis în rețea (RDP)", make: () => windowsFilm({
      left: { items: ["Sistem", "Rețea și internet", "Aplicații", "Conturi"], go: 0, cap: "În stânga, apasă „Sistem”." },
      rights: [{ title: "Sistem", items: ["Ecran", "Sunet", "Desktop la distanță", "Despre"], go: 2, cap: "În dreapta, coboară și apasă „Desktop la distanță”." }],
      final: { title: "Desktop la distanță", cap: "Mută butonul „Desktop la distanță” pe „Dezactivat” și confirmă.", html: (s) => `<div class="row"><span>Desktop la distanță</span>${toggle(s, false)}</div>` },
      doneCap: "Gata: nimeni nu-ți mai poate controla calculatorul prin rețea.", done: "Desktop la distanță oprit",
    }) },
    { code: "SMB_EXPOSED", title: "Fișiere partajate, deschise în rețea (SMB)", make: () => windowsFilm({
      left: { items: ["Sistem", "Rețea și internet", "Aplicații", "Conturi"], go: 1, cap: "În stânga, apasă „Rețea și internet”." },
      rights: [
        { title: "Rețea și internet", items: ["Wi-Fi", "Ethernet", "VPN", "Setări avansate de rețea"], go: 3, cap: "Jos, apasă „Setări avansate de rețea”." },
        { title: "Setări avansate de rețea", items: ["Adaptoare de rețea", "Utilizarea datelor", "Setări avansate de partajare"], go: 2, cap: "La „Mai multe setări”, apasă „Setări avansate de partajare”." },
      ],
      final: { title: "Setări avansate de partajare", cap: "La „Rețele private” și la „Rețele publice”, oprește „Partajarea fișierelor și imprimantelor”.", html: (s) => `<div class="row"><span>Privată: partajarea fișierelor</span>${toggle(s, false)}</div><div class="row"><span>Publică: partajarea fișierelor</span>${toggle(s, false, 2000)}</div>` },
      doneCap: "Gata: folderele tale nu se mai văd în rețea.", done: "Partajare oprită",
    }) },
    { code: "SSH_OPEN", title: "Intrare criptată pentru administrare (SSH)", make: () => windowsFilm({
      left: { items: ["Sistem", "Rețea și internet", "Aplicații", "Conturi"], go: 0, cap: "În stânga, apasă „Sistem”." },
      rights: [{ title: "Sistem", items: ["Ecran", "Sunet", "Caracteristici opționale", "Despre"], go: 2, cap: "În dreapta, apasă „Caracteristici opționale”." }],
      final: { title: "Caracteristici opționale", cap: "Dacă nu-l folosești, apasă pe „Server OpenSSH”, apoi „Elimină”.", html: () => `<div class="row"><span>Server OpenSSH</span><span class="btn danger" data-t="tg">Elimină</span></div><div class="row dim"><span>Notepad</span></div>` },
      doneCap: "Gata: nimeni nu mai poate încerca parole pe calculatorul tău.", done: "Server OpenSSH eliminat",
      note: "Pe calculatoarele mai vechi, „Caracteristici opționale” e la Aplicații.",
    }) },
    { code: "DB_EXPOSED", title: "Bază de date deschisă în rețea", make: () => windowsFilm({
      left: { items: ["Sistem", "Rețea și internet", "Aplicații", "Conturi"], go: 2, cap: "În stânga, apasă „Aplicații”." },
      rights: [{ title: "Aplicații", items: ["Aplicații instalate", "Aplicații implicite", "Pornire"], go: 0, cap: "Apasă „Aplicații instalate”." }],
      final: { title: "Aplicații instalate", cap: "Găsește programul bazei de date. Dacă nu-l mai folosești: „⋯” → „Dezinstalează”.", html: () => `<div class="row"><span>Server de baze de date</span><span class="btn danger" data-t="tg">Dezinstalează</span></div><div class="row dim"><span>Browser</span></div>` },
      doneCap: "Nu știi ce e programul? Întreabă întâi pe cine l-a instalat.", done: "Program dezinstalat",
    }) },
    { code: "VNC_EXPOSED", title: "Ecranul, controlat de la distanță (VNC)", make: () => windowsFilm({
      pre: { html: '<div class="ctx slide-up" data-show="2"><span>Deschide</span><span>Opțiuni</span><span class="pick" data-act="2" data-delay="900" data-t="go">Ieșire</span></div>',
        shots: [
          { cap: "Jos în dreapta, lângă ceas, e iconița programului VNC. Click dreapta pe ea.", f: '[data-t="tray"]', tap: true },
          { cap: "Alege „Ieșire”. Programul se oprește.", f: '[data-shot-page] [data-t="go"]', tap: true },
        ] },
      left: { items: ["Sistem", "Rețea și internet", "Aplicații", "Conturi"], go: 2, cap: "Ca să nu mai pornească: în stânga, apasă „Aplicații”." },
      rights: [{ title: "Aplicații", items: ["Aplicații instalate", "Aplicații implicite", "Pornire"], go: 0, cap: "Apasă „Aplicații instalate”." }],
      final: { title: "Aplicații instalate", cap: "La programul VNC: „⋯” → „Dezinstalează”.", html: () => `<div class="row"><span>Program VNC</span><span class="btn danger" data-t="tg">Dezinstalează</span></div><div class="row dim"><span>Browser</span></div>` },
      doneCap: "Gata: nimeni nu-ți mai vede și nu-ți mai controlează ecranul.", done: "Program dezinstalat",
      tagHtml: tag("1", "bad", 196, 22, "iconița VNC, lângă ceas ↓"),
    }) },


    /* ===== „aparat necunoscut” într-un hotspot de telefon ===== */
    { code: "HOTSPOT_SELF", title: "Aparatul necunoscut e chiar telefonul cu hotspotul", make: () => {
      const screens = homeScreen("1", { n: "Setări", c: "linear-gradient(#AEB4BC,#8E8E93)", glyph: '<span class="glyph">⚙</span>' })
        + `<div class="ps slide" data-show="2,3"><h5>Hotspot personal</h5><div class="list"><span data-t="go">Permite altora să se conecteze <i class="chev"></i></span><span>Parola Wi-Fi <i class="chev"></i></span></div><div class="note">Acesta e telefonul care dă internetul laptopului.</div></div>`;
      return {
        html: `<div class="floor"></div>${phone("", "1,2,3", screens)}${done("3", "E telefonul tău · totul e în regulă")}${finger}`,
        shots: [
          { cap: "Aparatul „necunoscut” de la adresa .1 e chiar telefonul care face hotspotul: de la el vine internetul.", touch: true },
          { cap: "Îl recunoști după „Hotspot personal” pornit în Setări. E al tău, deci nu e un străin.", f: '[data-shot-page] [data-t="go"]', touch: true },
          { cap: "Nu ai nimic de reparat aici: apasă „Sar peste, pe riscul meu” și treci mai departe.", touch: true },
        ],
        note: "SafeEel nu poate afla singur numele telefonului (nu-l anunță în rețea). De aceea îl vede „necunoscut”.",
      };
    } },
    { code: "HOTSPOT_UNKNOWN", title: "Un aparat necunoscut în hotspotul de pe telefon", make: () => {
      const pw = hotspotPw(2);
      const ctx = `<div class="ps slide" data-show="1"><h5>Hotspot personal</h5><div class="list"><span data-t="go">Conectate acum: <b>4</b></span><span>Parola Wi-Fi <i class="chev"></i></span></div><div class="note">Pe telefon vezi doar câte aparate sunt, nu și care.</div></div>`;
      const html = pw.html.replace('<div class="sbar">', '<div class="sbar">').replace(/(<div class="actor phone[^"]*" data-show=")([^"]*)"/, (m, a, b) => `${a}1,${b}"`);
      return {
        html: `<div class="floor"></div>${html.replace('<div class="screen">\n      <div class="sbar"><span>9:41</span><span class="bat"></span></div>', '<div class="screen">\n      <div class="sbar"><span>9:41</span><span class="bat"></span></div>' + ctx)}${finger}`,
        shots: [{ cap: "Pe telefonul cu hotspotul vezi câte aparate sunt conectate, dar nu și care. Un străin nu poate fi dat afară separat.", f: '[data-shot-page] [data-t="go"]', touch: true }].concat(pw.shots),
        note: "Știi cine e (un telefon nou din casă)? Atunci nu e o problemă: apasă „Sar peste”. " + pw.note,
      };
    } },
    /* ===== calculatoare Windows: problema e un PROGRAM de pe calculator (pagină web, mesaje de casă inteligentă, FTP…) ===== */
    { code: "WIN_APP", title: "Un program de pe calculator, deschis în rețea", make: () => {
      const en = CTX.lang === "en";
      const port = CTX.port || "8080";
      const guess = CTX.prog ? esc(CTX.prog) : "";
      const dev = CTX.dev ? esc(CTX.dev) : "";
      const ip = CTX.devip ? esc(CTX.devip) : "192.168.1.50";
      const safe = `<div class="win slide" data-show="1"><div class="wbar"><span>SafeEel</span><span class="wbtn">— ▢ ✕</span></div>
          <div class="safe-hint"><b class="wt">Problema de pe ${dev || "calculator"}</b><div class="kv">adresa ${ip}</div>
          <div class="kv" data-t="go">portul <span class="hl">${port}</span>${guess ? ` · pare „${guess}”` : ""}</div></div></div>`;
      const start = `<div class="start slide-up" data-show="2"><input class="search" value="Monitor de resurse" disabled><span class="pick" data-act="2" data-delay="900" data-t="go">Monitor de resurse</span><span>Setări</span></div>`;
      const tabs = (on) => `<div class="rm-tabs"><span>Prezentare</span><span>CPU</span><span>Memorie</span><span>Disc</span><span class="${on ? "on" : "pick"}" ${on ? "" : 'data-act="3" data-delay="900" data-t="go"'}>Rețea</span></div>`;
      const ports = (pick) => `<b class="wt rm-sec">Porturi de ascultare</b><div class="rm-head"><span>Imagine</span><span>Port</span></div>
          <div class="row dim"><span>svchost.exe</span><b>135</b></div>
          <div class="row ${pick ? "pick" : ""}" ${pick ? `data-act="${pick}" data-delay="500" data-t="go"` : ""}><span class="rm-img">program-${port}.exe</span><b>${port}</b></div>
`;
      const W = (show, body) => `<div class="win slide rm" data-show="${show}"><div class="wbar"><span>Monitor de resurse</span><span class="wbtn">— ▢ ✕</span></div><div class="rm-body">${body}</div></div>`;
      /* cazul des întâlnit: portul e al unui container (numele e com.docker… / wslrelay / vmmem): îl oprești din programul de containere */
      const dock = `<div class="win slide dk" data-show="7,8"><div class="wbar"><span>Docker Desktop</span><span class="wbtn">— ▢ ✕</span></div>
          <div class="side"><div class="menu"><span class="on">Containers</span><span>Images</span><span>Volumes</span></div><div class="right">
          <b class="wt">Containers</b><div class="rm-head"><span>Nume</span><span>Port(s)</span></div>
          <div class="row pick" data-act="7" data-delay="500"><span>${guess || "web"}</span><b>${port}:80</b><span class="btn danger" data-t="stop">■</span></div>
          <div class="row dim"><span>alt container</span><b>—</b></div></div></div></div>`;
      const inner = safe + start + W("3", tabs(false) + `<div class="muted-big">Alege fila „Rețea”.</div>`) + W("4", tabs(true) + ports(4))
        + W("5,6", tabs(true) + `<b class="wt rm-sec">Porturi de ascultare</b><div class="rm-menu"><span>Terminare proces</span><span>Căutare online</span></div><div class="row pick act"><span class="rm-img">program-${port}.exe</span><b>${port}</b></div>`)
        + dock;
      return {
        html: `<div class="floor"></div>${monitor(inner).replace(/data-t="tg"/g, "")}${done("6", "Program găsit și oprit")}${done("8", "Container oprit")}${mouse}`,
        shots: [
          { cap: dev ? `În SafeEel vezi pe ce calculator e problema („${dev}”) și portul ei: ${port}. Mergi la acel calculator.` : `În SafeEel vezi portul problemei: ${port}. Mergi la calculatorul cu problema.`, f: '[data-shot-page] [data-t="go"]' },
          { cap: "Apasă Start și scrie „Monitor de resurse”. Deschide-l.", f: '[data-shot-page] [data-t="go"]', tap: true },
          { cap: "Sus, apasă fila „Rețea”.", f: '[data-shot-page] [data-t="go"]', tap: true },
          { cap: `Deschide „Porturi de ascultare” și caută rândul cu portul ${port}. În stânga, la „Imagine”, e numele programului.`, f: '[data-shot-page] [data-t="go"]', tap: true },
          { cap: "Nu-l folosești? Click dreapta pe el → „Terminare proces”. Apoi dezinstalează-l sau oprește-l din setările lui.", f: '.rm-menu span' , tap: true },
          { cap: "Gata. Apasă apoi „Am făcut asta, verifică” în SafeEel." },
          { cap: `La „Imagine” scrie „com.docker…”, „wslrelay” sau „vmmem”? Atunci portul e al unui container. Deschide Docker Desktop, la „Containers”, și caută portul ${port}.`, f: '[data-shot-page] .row.pick' },
          { cap: "Apasă ■ (Stop) lângă el. Îl folosești? Pornește-l din nou doar pentru acest calculator (portul pus ca 127.0.0.1).", f: '[data-shot-page] [data-t="stop"]', tap: true },
        ],
        note: "Numele e „com.docker…”, „wslrelay” sau „vmmem”? Programul rulează într-un program de containere sau de mașini virtuale: deschide acel program și oprește ce rulează în el. E un program pe care îl folosești? Nu-l opri: caută în setările lui „doar pe acest calculator”.",
      };
    } },
    { code: "WIN_SNMP", title: "SNMP pornit pe calculator", make: () => windowsFilm({
      left: { items: ["Sistem", "Rețea și internet", "Aplicații", "Conturi"], go: 0, cap: "În stânga, apasă „Sistem”." },
      rights: [{ title: "Sistem", items: ["Ecran", "Sunet", "Caracteristici opționale", "Despre"], go: 2, cap: "În dreapta, apasă „Caracteristici opționale”." }],
      final: { title: "Caracteristici opționale", cap: "Apasă pe „SNMP”, apoi „Elimină”.", html: () => `<div class="row"><span>SNMP</span><span class="btn danger" data-t="tg">Elimină</span></div><div class="row dim"><span>Notepad</span></div>` },
      doneCap: "Gata: calculatorul nu mai spune altora din rețea detalii despre el.", done: "SNMP eliminat",
      note: "Pe calculatoarele mai vechi, „Caracteristici opționale” e la Aplicații.",
    }) },
    { code: "WIN_UPNP", title: "Calculatorul se anunță în rețea (UPnP)", make: () => windowsFilm({
      left: { items: ["Sistem", "Rețea și internet", "Aplicații", "Conturi"], go: 1, cap: "În stânga, apasă „Rețea și internet”." },
      rights: [
        { title: "Rețea și internet", items: ["Wi-Fi", "Ethernet", "VPN", "Proxy"], go: 0, cap: "Apasă „Wi-Fi”." },
        { title: "Wi-Fi", items: ["Proprietățile rețelei la care ești conectat", "Rețele cunoscute", "Hardware"], go: 0, cap: "Apasă pe proprietățile rețelei la care ești conectat (primul rând)." },
      ],
      final: { title: "Tipul profilului de rețea", cap: "La „Tipul profilului de rețea”, alege „Public”.", html: (s) => `<div class="row"><span>Public (recomandat)</span>${checkbox(s)}</div><div class="row dim"><span>Privat</span></div>` },
      doneCap: "Gata: calculatorul nu se mai anunță altor aparate din rețea.", done: "Rețea setată ca Public",
    }) },
    { code: "WIN_UPDATE", title: "Program vechi pe calculator", make: () => windowsFilm({
      left: { items: ["Sistem", "Rețea și internet", "Aplicații", "Windows Update"], go: 3, cap: "În stânga, jos, apasă „Windows Update”." },
      rights: [],
      final: { title: "Windows Update", cap: "Apasă „Caută actualizări” și instalează tot ce apare.", html: () => `<div class="row"><span>Ultima verificare: acum o lună</span></div><span class="btn" data-t="tg">Caută actualizări</span>` },
      doneCap: "Gata: calculatorul are cele mai noi reparații de siguranță. Actualizează și programul arătat de SafeEel.", done: "Actualizări instalate",
      note: "Problema e într-un program anume (îl vezi în SafeEel)? Deschide-l și caută „Actualizare” sau „Verifică actualizări” în meniul lui.",
    }) },

    /* ===== Mac / Linux („Server” cu MAC aleatoriu, fără semne de Windows): Setări de sistem → General → Partajare ===== */
    { code: "MAC_SSH", title: "Login la distanță, pornit pe Mac", make: () => macFilm({ item: "Login la distanță",
      cap: "Mută butonul „Login la distanță” pe oprit.", doneCap: "Gata: nimeni nu mai poate încerca parole pe calculatorul tău.", done: "Login la distanță oprit",
      note: "Pe Linux: deschide Terminalul și scrie „sudo systemctl disable --now ssh”, sau cere ajutor celui care a instalat calculatorul." }) },
    { code: "MAC_VNC", title: "Partajarea ecranului, pornită pe Mac", make: () => macFilm({ item: "Partajarea ecranului",
      cap: "Mută butonul „Partajarea ecranului” pe oprit.", doneCap: "Gata: nimeni nu-ți mai vede și nu-ți mai controlează ecranul.", done: "Partajarea ecranului oprită",
      note: "Pe Linux: în Setări, la „Partajare”, oprește „Partajarea ecranului” / „Desktop la distanță”." }) },
    { code: "MAC_SMB", title: "Partajarea fișierelor, pornită pe Mac", make: () => macFilm({ item: "Partajarea fișierelor",
      cap: "Mută butonul „Partajarea fișierelor” pe oprit.", doneCap: "Gata: folderele tale nu se mai văd în rețea.", done: "Partajarea fișierelor oprită",
      note: "Pe Linux: în Setări, la „Partajare”, oprește „Partajarea fișierelor”." }) },
    { code: "FTP_WEB", title: "FTP pe pagina aparatului", make: () => webFilm({
      clicks: [menuClick(["Stare", "Rețea", "Servicii", "Sistem"], 0, 2, homeRight, "În meniul din stânga, apasă „Servicii”.")],
      action: finalToggle(["Stare", "Rețea", "Servicii", "Sistem"], 2, "Servicii", "Server FTP", false, "Găsește „Server FTP” și mută butonul pe „Oprit”."),
      save: "Apasă „Salvează”. Apoi schimbă și parola, pentru că s-ar putea să fi fost văzută.", done: "Setări salvate · FTP oprit",
    }) },
    { code: "SSH_WEB", title: "SSH pe pagina aparatului", make: () => webFilm({
      clicks: [menuClick(["Stare", "Rețea", "Servicii", "Sistem"], 0, 2, homeRight, "În meniul din stânga, apasă „Servicii”.")],
      action: finalToggle(["Stare", "Rețea", "Servicii", "Sistem"], 2, "Servicii", "Acces SSH", false, "Dacă nu-l folosești, găsește „Acces SSH” și mută butonul pe „Oprit”."),
      save: "Apasă „Salvează”.", done: "Setări salvate · SSH oprit",
    }) },
    { code: "DB_WEB", title: "Baza de date pe pagina aparatului", make: () => webFilm({
      clicks: [menuClick(["Stare", "Rețea", "Servicii", "Sistem"], 0, 2, homeRight, "În meniul din stânga, apasă „Servicii”.")],
      action: finalToggle(["Stare", "Rețea", "Servicii", "Sistem"], 2, "Servicii", "Bază de date: acces din rețea", false, "Oprește „Bază de date: acces din rețea”. Programul merge mai departe, doar nu se mai vede din rețea."),
      save: "Apasă „Salvează”. Nu știi ce e? Întreabă pe cine a instalat aparatul.", done: "Setări salvate · baza de date închisă",
    }) },
  ];


  /* ================= alegerea filmului: după problemă ȘI aparat =================
     Filmele de router doar pe router (sau gateway), cele de Windows doar pe calculatoare; pe hotspotul de pe telefon,
     filmul cu Setări → Hotspot personal. Fără potrivire: rămâne textul (nimic nu se schimbă). */
  const BY = { PAGE_LIVE: { make: liveFilm }, PAGE_TRUST: { make: trustFilm }, PAGE_DEVICES: { make: devicesFilm },
    PAGE_JOURNAL: { make: journalFilm }, PAGE_HISTORY: { make: historyFilm }, PAGE_WELCOME: { make: welcomeFilm }, PAGE_HOTSPOT_PW: { make: hotspotPwFilm } };
  FILMS.forEach((f) => { if (f.code === "FTP_CLEARTEXT" && /hotspot/i.test(f.title)) BY.HOTSPOT = f; else BY[f.code] = f; });   /* doar filmul „oprește hotspotul” e HOTSPOT */
  const ROUTER_CODES = ["UPNP_EXPOSED", "TELNET_OPEN", "SNMP_EXPOSED", "HTTP_ADMIN_CLEARTEXT", "OUTDATED_SERVICE"];
  const PC_CODES = ["RDP_EXPOSED", "SMB_EXPOSED", "SSH_OPEN", "DB_EXPOSED", "VNC_EXPOSED"];
  const PC_TYPES = ["pc_windows", "server", "phone_laptop", "unknown", ""];
  const WEB_ALT = { FTP_CLEARTEXT: "FTP_WEB", SSH_OPEN: "SSH_WEB", DB_EXPOSED: "DB_WEB" };
  const OWN_FILM = ["PRINTER_RAW_EXPOSED", "CAMERA_STREAM_EXPOSED", "MQTT_EXPOSED", "UNKNOWN_DEVICE"];
  /* întoarce [cheia filmului, varianta generică?] */
  /* probleme aflate pe un calculator Windows: ce program / ce setare din Windows */
  const WIN_EXTRA = { SNMP_EXPOSED: "WIN_SNMP", UPNP_EXPOSED: "WIN_UPNP", OUTDATED_SERVICE: "WIN_UPDATE",
    HTTP_ADMIN_CLEARTEXT: "WIN_APP", MQTT_EXPOSED: "WIN_APP", FTP_CLEARTEXT: "WIN_APP", TELNET_OPEN: "WIN_APP",
    PRINTER_RAW_EXPOSED: "WIN_APP", CAMERA_STREAM_EXPOSED: "WIN_APP" };
  /* pe un calculator fără semne de Windows („Server” cu MAC aleatoriu: de obicei Mac sau Linux): Partajare */
  const MAC_FILM = { SSH_OPEN: "MAC_SSH", VNC_EXPOSED: "MAC_VNC", SMB_EXPOSED: "MAC_SMB" };
  function choose(code, dtype, isRouter, net) {
    const hotspot = dtype.indexOf("hotspot") === 0;
    /* „aparat necunoscut” într-un hotspot de telefon: nu există router cu listă de aparate */
    if (code === "UNKNOWN_DEVICE" && hotspot) return ["HOTSPOT_SELF", false];
    if (code === "UNKNOWN_DEVICE" && net === "hotspot") return ["HOTSPOT_UNKNOWN", false];
    /* pe hotspotul de pe telefon: imprimanta, camera, aparatele smart și aparatul necunoscut au filmul lor;
       serviciile telefonului nu se pot opri separat, deci filmul cu oprirea hotspotului */
    if (hotspot) return [OWN_FILM.includes(code) ? code : "HOTSPOT", false];
    if (!isRouter && dtype === "pc_windows") {                     /* calculator Windows (și cele reetichetate) */
      if (PC_CODES.includes(code)) return [code, false];
      if (WIN_EXTRA[code]) return [WIN_EXTRA[code], false];
    }
    if (!isRouter && (dtype === "server" || dtype === "phone_laptop") && MAC_FILM[code]) return [MAC_FILM[code], false];
    if (OWN_FILM.includes(code)) return [code, false];
    const pc = ["pc_windows", "server", "phone_laptop"].includes(dtype);
    if (PC_CODES.includes(code) && pc && !isRouter) return [code, false];          /* calculator: Setările din Windows */
    const key = ROUTER_CODES.includes(code) ? code : WEB_ALT[code];
    if (!key) return [null, false];
    return [key, !isRouter];                                                       /* router: eticheta; altfel: din SafeEel */
  }

  /* ================= motorul (în aplicație) ================= */
  /* controalele, ca la un player video: doar iconițe (numele lor e în aria-label, pentru cititorul de ecran) */
  const svg = (d) => `<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" focusable="false"><path d="${d}" fill="currentColor"/></svg>`;
  const ICONS = {
    prev: svg("M15.4 5.4 14 4l-8 8 8 8 1.4-1.4L8.8 12z"),
    next: svg("M8.6 5.4 10 4l8 8-8 8-1.4-1.4 6.6-6.6z"),
    play: svg("M8 5v14l11-7z"),
    pause: svg("M7 5h4v14H7zm6 0h4v14h-4z"),
    max: svg("M4 4h6v2H6v4H4zm10 0h6v6h-2V6h-4zM4 14h2v4h4v2H4zm14 4v-4h2v6h-6v-2z"),
    min: svg("M8 4h2v6H4V8h4zm6 0h2v4h4v2h-6zM4 14h6v6H8v-4H4zm10 0h6v2h-4v4h-2z"),
  };
  const ICON_BTN = (a, label, icon, cls = "") => `<button type="button" class="icon-btn ${cls}" data-a="${a}" aria-label="${label}" title="${label}">${icon}</button>`;
  const live = new Set();
  const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* stilurile cu valori (poziții, culori) vin ca data-style și se pun prin CSSOM: compatibil cu CSP (style-src 'self') */
  function applyStyles(root) {
    root.querySelectorAll("[data-style]").forEach((el) => {
      el.getAttribute("data-style").split(";").forEach((decl) => {
        const i = decl.indexOf(":"); if (i < 0) return;
        el.style.setProperty(decl.slice(0, i).trim(), decl.slice(i + 1).trim());
      });
      el.removeAttribute("data-style");
    });
  }
  const capHtml = (s) => s.replace(/„([^”]+)”/g, "„<b>$1</b>”").replace(/“([^”]+)”/g, "“<b>$1</b>”");
  /* textele din interiorul filmului (meniuri, butoane, etichete), traduse nod cu nod */
  function translateText(root, tr) {
    const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const nodes = []; while (w.nextNode()) nodes.push(w.currentNode);
    nodes.forEach((n) => { const s = n.nodeValue.trim(); if (!s) return; const t = tr(s); if (t !== s) n.nodeValue = n.nodeValue.replace(s, t); });
  }

  const hideKey = (slot) => "safeeel-hide-film-" + slot.dataset.page;
  function hiddenPref(slot) { try { return localStorage.getItem(hideKey(slot)) === "1"; } catch (e) { return false; } }
  function setHidden(slot, v) { try { if (v) localStorage.setItem(hideKey(slot), "1"); else localStorage.removeItem(hideKey(slot)); } catch (e) { /* nimic */ } }
  /* filmul ascuns: rămâne doar un buton mic „Revezi cum merge” */
  function showReplay(slot) {
    const lang = slot.dataset.lang === "en" ? "en" : "ro";
    const b = document.createElement("button");
    b.type = "button"; b.className = "film-replay";
    b.innerHTML = `<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M8 5v14l11-7z" fill="currentColor"/></svg>${lang === "en" ? "Watch how it works" : "Revezi cum merge"}`;
    b.addEventListener("click", () => { setHidden(slot, false); b.remove(); slot.removeAttribute("data-mounted"); slot.classList.remove("film-off"); mount(slot); });
    slot.classList.add("film-off");
    slot.appendChild(b);
  }
  function mount(slot) {
    slot.setAttribute("data-mounted", "");
    if (reduce) return;
    if (slot.dataset.page && hiddenPref(slot)) { showReplay(slot); return; }
    const lang = slot.dataset.lang === "en" ? "en" : "ro";
    const EN = window.SAFEEEL_FILMS_EN || {};
    const tr = (s) => (lang === "en" && EN[s]) || s;
    const [key, generic] = slot.dataset.page ? ["PAGE_" + slot.dataset.page.toUpperCase(), false]
      : choose(slot.dataset.code || "", slot.dataset.dtype || "", slot.dataset.router === "1", slot.dataset.net || "");
    if (!key || !BY[key]) return;
    slot.dataset.film = key;   /* ce film s-a ales (util la verificare) */
    CTX.generic = generic; CTX.prog = (slot.dataset.prog || "").slice(0, 40);
    CTX.dev = (slot.dataset.devname || "").slice(0, 40); CTX.devip = (slot.dataset.devip || "").slice(0, 40); CTX.lang = lang; CTX.port = String(parseInt(slot.dataset.port || "", 10) || "");
    const f = BY[key].make(); CTX.generic = false; CTX.prog = ""; CTX.dev = ""; CTX.devip = ""; CTX.port = "";
    let html = f.html, shots = f.shots.map((s) => Object.assign({}, s, { cap: tr(s.cap) }));
    if (lang === "en" && f.note) f.note = tr(f.note);
    const ip = slot.dataset.ip || "";
    /* animația arată doar o adresă model; adresa reală e scrisă în pagină, sub numele problemei */

    const root = document.createElement("div");
    root.className = "film";
    root.setAttribute("role", "group");
    root.setAttribute("aria-label", tr("Cum repari, pas cu pas"));
    root.innerHTML = `<div class="film-view">${ICON_BTN("max", tr("Mărește"), ICONS.max, "film-max-btn")}<div class="stage" role="img" aria-label="${esc(shots.map((s, k) => `${k + 1}. ${s.cap.replace(/<[^>]+>/g, "")}`).join(" "))}">${html}</div></div>
      <div class="dots">${shots.map((_, k) => `<button type="button" aria-label="${tr("Pasul")} ${k + 1}" data-go="${k}"></button>`).join("")}</div>
      <div class="capline" aria-live="polite"><span class="n"></span><p></p></div>
      <div class="ctrl">${ICON_BTN("prev", tr("Pasul anterior"), ICONS.prev)}${ICON_BTN("pause", tr("Pauză"), ICONS.pause, "play")}${ICON_BTN("next", tr("Pasul următor"), ICONS.next)}</div>
      ${slot.dataset.cta ? `<a class="button film-cta" href="${esc(slot.dataset.ctaHref || "#")}">${esc(tr(slot.dataset.cta))} <span aria-hidden="true">↓</span></a>` : ""}
      ${f.note ? `<details class="film-note"><summary>${tr("Bine de știut")}</summary><p>${esc(f.note)}</p></details>` : ""}
      ${slot.dataset.page && slot.dataset.hide !== "no" ? `<button type="button" class="film-hide" data-a="hide">${tr("Am înțeles, ascunde animația")}</button>` : ""}`;
    applyStyles(root);
    if (lang === "en") translateText(root.querySelector(".stage"), tr);
    slot.appendChild(root);
    const box = slot.closest(".do-first, .problem-body");
    if (box) box.classList.add("has-film");
    const card = slot.closest(".worst");   /* pe Acasă: cardul păstrează doar riscul și numele problemei */
    if (card) card.classList.add("has-film");
    const film = { tr, root, slot, view: root.querySelector(".film-view"), stage: root.querySelector(".stage"), shots, n: 0, timer: null, visible: false, paused: false, delays: [], scale: 1, max: false };
    live.add(film);
    fit(film);
    /* primul cadru apare direct (fără să crească din gol): altfel, la fiecare actualizare a paginii, ecranul ar clipi */
    root.classList.add("film-instant");
    setShot(film, 0);
    requestAnimationFrame(() => requestAnimationFrame(() => root.classList.remove("film-instant")));
    io.observe(root);
    if (carryMax) {   /* venim din modul mărit: filmul vechi (mărit) pleacă, cel nou se deschide mărit, fără animație */
      carryMax = false;
      toggleMax(film, true);
      /* filmul vechi (mărit) se estompează lin peste cel nou, nu dispare dintr-odată */
      document.querySelectorAll(".film.film-max").forEach((old) => {
        if (old === root) return;
        old.classList.add("film-leaving");
        setTimeout(() => old.remove(), 340);
      });
    }
    root.addEventListener("click", (e) => onClick(film, e));
    /* „Începe acum ↓”: coboară lin la ce faci pe pagină și deschide pornirea (dacă e închisă) */
    const ctaBtn = root.querySelector(".film-cta");
    if (ctaBtn) ctaBtn.addEventListener("click", (e) => {
      const id = (ctaBtn.getAttribute("href") || "").slice(1); const dest = id && document.getElementById(id);
      if (!dest) return;
      e.preventDefault();
      const open = dest.querySelector("details:not([open]) > summary"); if (open) open.click();
      dest.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
      const f = dest.querySelector("summary, button, input, a[href]"); if (f) setTimeout(() => f.focus({ preventScroll: true }), 500);
    });
  }

  /* filmul se scalează la lățimea locului lui (și la ecran, când e mărit); interiorul rămâne 360×290 */
  /* cât loc îi rămâne animației pe Acasă ca pagina să nu se deruleze: fereastra minus antet, subsol și restul conținutului */
  function homeRoom(film) {
    if (film.max || !film.root.closest(".verdict.home-card")) return Infinity;
    const main = document.getElementById("main"); if (!main) return Infinity;
    const top = document.querySelector("header.top"), foot = document.querySelector("footer.foot");
    const ms = getComputedStyle(main), mt = main.getBoundingClientRect().top;
    let bottom = mt;
    for (const ch of main.children) { const r = ch.getBoundingClientRect(); if (r.height) bottom = Math.max(bottom, r.bottom); }
    const content = bottom - mt + parseFloat(ms.paddingBottom);
    const fixed = (top ? top.offsetHeight : 0) + (foot ? foot.offsetHeight : 0) + content - film.view.offsetHeight;
    return window.innerHeight - fixed - 8;
  }

  function fit(film) {
    const w = film.view.clientWidth || 360;
    /* modul mărit: înălțimea rămasă după tot ce e în jurul animației (rândul cu scorul, liniuțele, textul, butoanele) */
    let h = Infinity;
    if (film.max) {
      const cs = getComputedStyle(film.root);
      let used = parseFloat(cs.paddingTop) + parseFloat(cs.paddingBottom);
      for (const ch of film.root.children) {
        if (ch === film.view || getComputedStyle(ch).display === "none") continue;
        const m = getComputedStyle(ch);
        used += ch.offsetHeight + parseFloat(m.marginTop) + parseFloat(m.marginBottom);
      }
      h = Math.max(160, film.root.clientHeight - used - 16);
    }
    /* în pagină: cel mult ~jumătate din înălțimea ferestrei; mărit: cât încape (deci mereu mai mare decât în pagină) */
    let normalCap = Math.min(1.6, Math.max(1, (window.innerHeight * 0.5) / 290));
    /* Acasă: animația ia locul rămas până jos (cât să nu derulezi), dar rămâne mereu destul de mare */
    const room = homeRoom(film);
    if (room < Infinity) normalCap = Math.min(1.7, Math.max(0.75, room / 290));
    /* paginile cu film (Live, Dispozitive…): filmul, săgețile și „Vezi ↓” încap în primul ecran */
    if (!film.max && film.slot.dataset.page && !film.slot.dataset.ephemeral) {
      const top = film.root.getBoundingClientRect().top + window.scrollY;
      const below = film.root.offsetHeight - film.view.offsetHeight;
      const space = window.innerHeight - top - below - 12;
      normalCap = Math.min(normalCap, Math.max(0.8, space / 290));
    }   /* niciodată mai mică decât înainte: mai bine puțin scroll decât o animație mică */
    const s = film.max ? Math.min(w / 360, h / 290, 4) : Math.min(w / 360, normalCap);   /* mărit: exact cât încape, fără derulare */
    film.scale = s;
    film.view.style.height = (290 * s) + "px";
    /* zoom (nu transform): browserul redesenează la mărimea nouă, deci textul și aparatele rămân clare */
    if ("zoom" in film.stage.style) { film.stage.style.transform = ""; film.stage.style.zoom = s; film.stage.style.left = ((w - 360 * s) / 2 / s) + "px"; }
    else { film.stage.style.transform = `scale(${s})`; film.stage.style.left = ((w - 360 * s) / 2) + "px"; }
  }

  function setShot(film, n) {
    film.n = n;
    const shot = n + 1, st = film.stage;
    film.delays.forEach(clearTimeout); film.delays = [];
    st.dataset.shot = shot;
    st.querySelectorAll("[data-show]").forEach((el) => {
      const on = el.dataset.show.split(",").includes(String(shot));
      el.classList.toggle("vis", on);
      if (el.matches(".page, .ps, .win, .start, .ctx")) { if (on) el.setAttribute("data-shot-page", ""); else el.removeAttribute("data-shot-page"); }
    });
    st.querySelectorAll("[data-act]").forEach((el) => {
      const from = Number(el.dataset.act);
      if (shot < from) { el.classList.remove("act"); return; }
      if (shot === from && el.dataset.delay) { el.classList.remove("act"); film.delays.push(setTimeout(() => el.classList.add("act"), Number(el.dataset.delay))); }
      else el.classList.add("act");
    });
    st.querySelectorAll("[data-cls]").forEach((el) => {
      const map = Object.fromEntries(el.dataset.cls.split(",").map((p) => p.split(":")));
      const later = Object.keys(map).map(Number).filter((k) => k <= shot).sort((a, b) => b - a)[0];
      new Set(Object.values(map)).forEach((c) => el.classList.remove(c));
      if (later) el.classList.add(map[later]);
    });
    const fin = st.querySelector(".finger"), s = film.shots[n];
    const moveTo = (sel) => {
      const t = [...st.querySelectorAll(sel)].find((x) => x.getBoundingClientRect().width);
      if (!t) return false;
      const a = st.getBoundingClientRect(), b = t.getBoundingClientRect();
      const x = (b.left - a.left + b.width / 2) / film.scale, y = (b.top - a.top + b.height / 2) / film.scale;
      if (!fin.classList.contains("on")) { fin.style.transition = "none"; fin.style.left = (x + 26) + "px"; fin.style.top = (y + 22) + "px"; void fin.offsetWidth; fin.style.transition = ""; }
      requestAnimationFrame(() => { fin.style.left = x + "px"; fin.style.top = y + "px"; });
      return true;
    };
    if (s.touch !== undefined) fin.classList.toggle("mouse", !s.touch);
    fin.classList.remove("tap");
    if (!s.f) fin.classList.remove("on");
    if (s.f) film.delays.push(setTimeout(() => {
      if (moveTo(s.f)) { fin.classList.add("on"); if (s.tap) film.delays.push(setTimeout(() => { fin.classList.add("tap"); setTimeout(() => fin.classList.remove("tap"), 160); }, 850)); }
    }, 350));
    film.root.querySelectorAll(".dots button").forEach((d, k) => { d.classList.toggle("on", k <= n); d.setAttribute("aria-current", k === n ? "step" : "false"); });
    
    film.root.querySelector(".capline p").innerHTML = capHtml(s.cap);
    const cta = film.root.querySelector(".film-cta");
    if (cta && n === film.shots.length - 1) cta.classList.add("on");
  }

  function tick(film) {
    clearTimeout(film.timer);
    if (!film.root.isConnected) { live.delete(film); io.unobserve(film.root); return; }
    if (!(film.visible || film.max) || film.paused || document.hidden) return;
    const last = film.n === film.shots.length - 1;
    film.timer = setTimeout(() => { setShot(film, last ? 0 : film.n + 1); tick(film); }, last ? SHOT_MS + 2200 : SHOT_MS);
  }

  function onClick(film, e) {
    const b = e.target.closest("button"); if (!b || !film.root.contains(b)) return;
    if (b.dataset.go) setShot(film, Number(b.dataset.go));
    if (b.dataset.a === "pause") { film.paused = !film.paused; b.innerHTML = film.paused ? ICONS.play : ICONS.pause; b.setAttribute("aria-label", film.tr(film.paused ? "Pornește" : "Pauză")); b.title = b.getAttribute("aria-label"); }
    /* un singur rând de săgeți: la capătul filmului, › / ‹ trec la problema următoare / dinainte (paginarea de sus) */
    const pager = (cls) => { const box = film.slot.closest(".do-first"); const a = box && box.querySelector(cls); if (a) { a.click(); return true; } return false; };
    if (b.dataset.a === "next") { if (film.n === film.shots.length - 1) { carryMax = film.max; if (pager(".pager-next")) return; carryMax = false; } setShot(film, (film.n + 1) % film.shots.length); }
    if (b.dataset.a === "prev") { if (film.n === 0) { carryMax = film.max; if (pager(".pager-prev")) return; carryMax = false; } setShot(film, (film.n - 1 + film.shots.length) % film.shots.length); }
    if (b.dataset.a === "max") { toggleMax(film); return; }
    /* „Am înțeles, ascunde”: filmul dispare, rămâne „Revezi cum merge” (ținut minte în acest browser) */
    if (b.dataset.a === "hide") {
      clearTimeout(film.timer); film.delays.forEach(clearTimeout); live.delete(film); io.unobserve(film.root);
      setHidden(film.slot, true); film.root.remove(); showReplay(film.slot);
      const r = film.slot.querySelector(".film-replay"); if (r) r.focus();
      return;
    }
    tick(film);
  }

  /* „Mărește”: filmul crește lin din locul lui până umple fereastra (FLIP), fundalul se întunecă; Esc îl readuce */
  let backdrop = null;
  let carryMax = false;   /* trecerea la altă problemă din modul mărit: filmul nou se deschide direct mărit */
  function toggleMax(film, instant) {
    const el = film.root, btn = el.querySelector(".film-max-btn");
    const first = el.getBoundingClientRect();
    if (!film.max) {
      film.placeholder = document.createElement("div");
      film.placeholder.className = "film-placeholder";
      film.placeholder.style.height = first.height + "px";
      el.after(film.placeholder);
      document.body.appendChild(el);   /* direct în pagină: niciun card nu-l mai ține „înăuntru” */
      backdrop = backdrop || Object.assign(document.createElement("div"), { className: "film-backdrop" });
      document.body.appendChild(backdrop);
      requestAnimationFrame(() => backdrop.classList.add("on"));
      el.classList.add("film-max"); film.max = true;
      el.appendChild(btn);   /* butonul de micșorare: în colțul ferestrei mărite, nu peste animație */
      const ring = film.slot.dataset.ephemeral ? null : document.querySelector(".home-head .ring-wrap, .score .ring-wrap");
      if (ring) {   /* rândul de sus în modul mărit: scorul mic + verdictul, deasupra animației (nu peste ea) */
        const badge = document.createElement("div"); badge.className = "film-score"; badge.appendChild(ring.cloneNode(true));
        const v = document.getElementById("verdict-h"); if (v) { const p = document.createElement("p"); p.className = "film-score-text"; p.textContent = v.textContent.trim(); badge.appendChild(p); }
        el.insertBefore(badge, el.firstChild);
      }
      document.documentElement.classList.add("film-open");
      btn.innerHTML = ICONS.min; btn.setAttribute("aria-label", film.tr("Micșorează")); btn.title = btn.getAttribute("aria-label");
    } else if (film.slot.dataset.ephemeral) {
      /* animația deschisă de „Nu-l cunosc”: la închidere dispare de tot; focusul revine pe butonul care a deschis-o */
      backdrop && backdrop.classList.remove("on");
      clearTimeout(film.timer); film.delays.forEach(clearTimeout); live.delete(film); io.unobserve(el);
      document.documentElement.classList.remove("film-open");
      el.animate && !reduce ? el.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 180 }).onfinish = () => el.remove() : el.remove();
      film.slot.remove();
      setTimeout(() => backdrop && !document.querySelector(".film-max:not(.film-leaving)") && backdrop.remove(), 300);
      const back = document.querySelector("details.unknown-help > summary"); if (back) back.focus({ preventScroll: true });
      return;
    } else {
      backdrop && backdrop.classList.remove("on");
      el.classList.remove("film-max"); film.max = false;
      film.view.insertBefore(btn, film.view.firstChild);
      el.querySelectorAll(".film-score").forEach((b) => b.remove());
      film.slot.appendChild(el);
      film.placeholder && film.placeholder.remove();
      document.documentElement.classList.remove("film-open");
      btn.innerHTML = ICONS.max; btn.setAttribute("aria-label", film.tr("Mărește")); btn.title = btn.getAttribute("aria-label");
      setTimeout(() => backdrop && !document.querySelector(".film-max") && backdrop.remove(), 300);
    }
    fit(film); setShot(film, film.n);
    const last = el.getBoundingClientRect();
    /* deschiderea: o apariție lină (ușor mai mică și transparentă → mărimea finală), fără întinderi care deformează */
    if (!reduce && !instant && el.animate) {
      el.animate(film.max
        ? [{ opacity: 0, transform: "scale(.97)" }, { opacity: 1, transform: "none" }]
        : [{ opacity: 0 }, { opacity: 1 }], { duration: film.max ? 280 : 200, easing: "cubic-bezier(.2,.7,.2,1)" });
    }
    btn.focus();
    tick(film);
  }
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    live.forEach((f) => { if (f.max) toggleMax(f); });
  });

  const io = new IntersectionObserver((es) => es.forEach((e) => {
    live.forEach((f) => { if (f.root === e.target) { f.visible = e.isIntersecting; tick(f); } });
  }), { threshold: 0.35 });
  document.addEventListener("visibilitychange", () => live.forEach(tick));
  window.addEventListener("resize", () => live.forEach((f) => { fit(f); setShot(f, f.n); }));

  /* scorul mic de pe Acasă: cifra „numără” până la valoarea nouă (de la cea văzută ultima dată), ca schimbarea să se vadă */
  function animateScores() {
    document.querySelectorAll(".score-num:not([data-counted])").forEach((el) => {
      el.setAttribute("data-counted", "");
      const to = parseInt(el.textContent, 10); if (isNaN(to)) return;
      let from = 0; try { from = parseInt(sessionStorage.getItem("safeeel-score") || "0", 10) || 0; sessionStorage.setItem("safeeel-score", String(to)); } catch (e) { /* fără stocare: numără de la 0 */ }
      if (reduce || from === to) return;
      const t0 = performance.now(), dur = 900;
      const step = (now) => { const k = Math.min(1, (now - t0) / dur), e = 1 - Math.pow(1 - k, 3); el.textContent = String(Math.round(from + (to - from) * e)); if (k < 1) requestAnimationFrame(step); };
      el.textContent = String(from); requestAnimationFrame(step);
    });
  }

  /* inelul mic de pe Acasă: la click arată, într-o fereastră mică, ce înseamnă scorul (banda, progresul, scala) */
  function wireScore() {
    document.querySelectorAll(".home-head .score:not([data-wired])").forEach((score) => {
      score.setAttribute("data-wired", "");
      const ring = score.querySelector(".ring-wrap"); if (!ring) return;
      const lang = document.documentElement.lang === "en" ? "en" : "ro";
      ring.setAttribute("role", "button"); ring.setAttribute("tabindex", "0"); ring.setAttribute("aria-expanded", "false");
      ring.setAttribute("aria-label", lang === "en" ? "What this score means" : "Ce înseamnă scorul");
      const pop = document.createElement("div");
      pop.className = "score-pop"; pop.hidden = true; pop.setAttribute("role", "dialog");
      pop.setAttribute("aria-label", ring.getAttribute("aria-label"));
      ["score-label", "score-band", "score-after"].forEach((c) => { const el = score.querySelector("." + c); if (el) pop.appendChild(el.cloneNode(true)); });
      const body = score.querySelector(".how-score .fold-body"); if (body) { const b = body.cloneNode(true); b.className = "pop-body"; pop.appendChild(b); }
      score.appendChild(pop);
      const toggle = (open) => { pop.hidden = !open; ring.setAttribute("aria-expanded", String(open)); score.classList.toggle("score-open", open); };
      ring.addEventListener("click", (e) => { e.stopPropagation(); toggle(pop.hidden); });
      ring.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(pop.hidden); } });
      document.addEventListener("click", (e) => { if (!pop.hidden && !score.contains(e.target)) toggle(false); });
      document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !pop.hidden) { toggle(false); ring.focus(); } });
    });
  }

  /* scorul rămâne la îndemână: când rândul de sus iese din ecran, apare o bulină mică în colț (click = sus) */
  let floatObs = null;
  function floatScore() {
    const head = document.querySelector(".home-head"); const ring = head && head.querySelector(".ring-wrap");
    let fl = document.querySelector(".score-float");
    if (!head || !ring) { if (fl) fl.remove(); return; }
    if (!fl) {
      fl = document.createElement("button"); fl.type = "button"; fl.className = "score-float";
      fl.addEventListener("click", () => window.scrollTo({ top: 0, behavior: reduce ? "auto" : "smooth" }));
      document.body.appendChild(fl);
    }
    /* doar când s-a schimbat ceva (altfel propria actualizare ar declanșa din nou scanarea paginii) */
    const key = ring.textContent.trim();
    if (fl.dataset.v === key && fl.__head === head) return;
    fl.dataset.v = key; fl.__head = head;
    fl.setAttribute("aria-label", ((document.getElementById("verdict-h") || {}).textContent || "").trim());
    fl.innerHTML = ""; fl.appendChild(ring.cloneNode(true));
    if (floatObs) floatObs.disconnect();
    /* bulina stă în aceeași coloană cu inelul din card (stânga), ca scorul să pară că rămâne pe loc când derulezi */
    const place = () => { const r = ring.getBoundingClientRect(), w = fl.offsetWidth || 64; fl.style.left = Math.max(8, r.left + r.width / 2 - w / 2) + "px"; fl.style.right = "auto"; };
    place(); window.addEventListener("resize", place);
    floatObs = new IntersectionObserver((es) => es.forEach((e) => { place(); fl.classList.toggle("on", !e.isIntersecting && e.boundingClientRect.top < 0); }));
    floatObs.observe(head);
  }

  /* rezultatul verificării: un toast clar sus, în mijloc (textul rămâne și în pagină, pentru cititorul de ecran) */
  function toastVerify() {
    const msg = document.querySelector("#worst .verify-msg:not([data-toasted])"); if (!msg) return;
    msg.setAttribute("data-toasted", "");
    const en = document.documentElement.lang === "en";
    const kind = msg.classList.contains("verify-good") ? "good" : msg.classList.contains("verify-warn") ? "warn" : "info";
    /* „bifat, dar neverificat”: DE CE nu s-a putut verifica și CE faci, pe scurt (nu explicația lungă din pagină) */
    const WHY = {
      noanswer: en ? ["The device didn't answer", "It may be off. Turn it on and press “check” again."]
                   : ["Aparatul n-a răspuns", "Poate e oprit. Pornește-l și apasă din nou „verifică”."],
      noport: en ? ["Can't check this one here", "Run a new scan: it shows whether the problem is gone."]
                 : ["Pe asta n-o pot verifica de aici", "Fă o scanare nouă: îți arată dacă problema a dispărut."],
      udp: en ? ["Can't check this one here", "Run a new scan: it shows whether the problem is gone."]
              : ["Pe asta n-o pot verifica de aici", "Fă o scanare nouă: îți arată dacă problema a dispărut."],
      file_only: en ? ["Old scan: nothing checked", "To check for real, run a new scan on the team hotspot."]
                    : ["Scanare veche: n-am verificat nimic", "Ca să verifici de-adevăratelea, fă o scanare nouă pe hotspotul echipei."],
      other_device: en ? ["Another device is at that address", "Run a new scan to see where your device is now."]
                       : ["La adresa aia e acum alt aparat", "Fă o scanare nouă, ca să vezi unde e acum aparatul tău."],
    };
    const why = WHY[msg.dataset.check] || (en ? ["Step noted", "A new scan will confirm it."] : ["Am notat pasul", "O scanare nouă îl confirmă."]);
    const WARN = {
      noanswer: en ? ["The device didn't answer", "Turn it on, wait a moment and press “check” again."]
                   : ["Aparatul n-a răspuns", "Pornește-l, așteaptă puțin și apasă din nou „verifică”."],
      present: en ? ["It's still on the network", "Not yours? Change the Wi-Fi password, then check again."]
                  : ["E încă în rețea", "Nu e al tău? Schimbă parola Wi-Fi, apoi verifică din nou."],
    };
    WARN.noport = WARN.udp = en ? ["Couldn't check it right now", "Press “Try again” in a moment."] : ["N-am putut verifica acum", "Apasă „Reîncearcă” peste puțin."];
    WARN.file_only = en ? ["Couldn't check it", "Connect to the team hotspot, then try again."] : ["N-am putut verifica", "Conectează-te la hotspotul echipei, apoi reîncearcă."];
    WARN.other_device = en ? ["Another device is at that address", "Run a new scan, then try again."] : ["La adresa aia e alt aparat", "Fă o scanare nouă, apoi reîncearcă."];
    const w = WARN[msg.dataset.check];
    const title = { good: en ? "Fixed!" : "Reparat!", warn: w ? w[0] : (en ? "Not fixed yet" : "Încă nu e reparat"), info: why[0] }[kind];
    const text = kind === "info" ? why[1] : kind === "warn" && w ? w[1] : msg.textContent.trim();
    document.querySelectorAll(".verify-toast").forEach((x) => x.remove());
    const toast = document.createElement("div");
    toast.className = "verify-toast toast-" + kind; toast.setAttribute("aria-hidden", "true");
    const icon = { good: "M5 12.5l4.5 4.5L19 7.5", warn: "M12 7v6m0 4h.01", info: "M12 11v6m0-10h.01" }[kind];
    toast.innerHTML = `<span class="vt-icon"><svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true"><path d="${icon}" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
      <div class="vt-body"><p class="vt-title">${esc(title)}</p><p class="vt-text">${esc(text)}</p></div>
      ${kind === "warn" && w ? `<button type="button" class="vt-retry">${en ? "Try again" : "Reîncearcă"}</button>` : ""}
      <button type="button" class="vt-close" aria-label="${en ? "Close" : "Închide"}">✕</button>`;
    document.body.appendChild(toast);
    msg.classList.add("toasted");
    const close = () => { toast.classList.remove("on"); setTimeout(() => toast.remove(), 300); };
    toast.querySelector(".vt-close").addEventListener("click", close);
    const retry = toast.querySelector(".vt-retry");
    if (retry) retry.addEventListener("click", () => {
      close();
      const b = document.querySelector('#worst form[action$="/action/done"] button[type="submit"]:not([disabled])');
      if (b) b.click();
    });
    requestAnimationFrame(() => toast.classList.add("on"));
    setTimeout(close, 7000);
  }

  /* cifra scorului exact în centrul inelului: măsor unde e DESENATĂ cifra (nu cutia fontului) și o mut cât trebuie.
     Merge la orice font, zoom sau scalare de ecran. */
  const measureCtx = document.createElement("canvas").getContext("2d");
  function centerDigits() {
    document.querySelectorAll(".ring-wrap .score-num").forEach((el) => {
      const cs = getComputedStyle(el);
      measureCtx.font = `${cs.fontStyle} ${cs.fontWeight} ${cs.fontSize} ${cs.fontFamily}`;
      try { measureCtx.letterSpacing = cs.letterSpacing === "normal" ? "0px" : cs.letterSpacing; } catch (e) {}
      const m = measureCtx.measureText(el.textContent || "0");
      if (!m.fontBoundingBoxAscent) return;
      const shift = ((m.fontBoundingBoxDescent - m.fontBoundingBoxAscent) - (m.actualBoundingBoxDescent - m.actualBoundingBoxAscent)) / 2;
      /* și pe orizontală: centrul cernelii (nu al cutiei, care are spațierea literelor după ultima cifră) */
      const shiftX = m.width / 2 - (m.actualBoundingBoxRight - m.actualBoundingBoxLeft) / 2;
      const want = `translate(${shiftX.toFixed(2)}px, ${shift.toFixed(2)}px)`;
      if (el.style.transform !== want) el.style.transform = want;
    });
  }
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(centerDigits);
  window.addEventListener("resize", centerDigits);

  /* asistentul și confirmarea „Ești sigur?”: pagina derulează lin până la ele (nu trebuie să cauți tu în jos) */
  const smooth = reduce ? "auto" : "smooth";
  document.addEventListener("toggle", (e) => {
    const d = e.target;
    /* confirmarea din asistent apare peste card (nu se schimbă înălțimea): fără derulare. Celelalte se deschid lin,
       deci derulăm doar după ce s-au deschis și doar cât trebuie */
    if (d.matches && d.matches("details.skip-confirm:not(.nf-skip), details.step-title") && d.open) {
      setTimeout(() => d.scrollIntoView({ block: "nearest", behavior: smooth }), 360);
    }
  }, true);
  function scrollToWizard() {
    const w = document.querySelector("#worst .not-fixed:not([data-scrolled])"); if (!w) return;
    w.setAttribute("data-scrolled", "");
    setTimeout(() => w.scrollIntoView({ block: "nearest", behavior: smooth }), 200);
  }


  /* meniul de sus: pastila albastră alunecă spre pagina aleasă; una deschisă urmărește mouse-ul (stil Kokonut) */
  function navPill() {
    const nav = document.querySelector(".top nav");
    if (!nav || nav.dataset.pill) return;
    nav.dataset.pill = "1";
    nav.classList.add("has-pill");
    const pill = document.createElement("span"); pill.className = "nav-pill"; pill.setAttribute("aria-hidden", "true");
    const hov = document.createElement("span"); hov.className = "nav-hover"; hov.setAttribute("aria-hidden", "true");
    nav.prepend(hov); nav.prepend(pill);
    const links = () => [...nav.querySelectorAll("a")];
    const place = (el, a, instant) => {
      if (!a) { el.classList.remove("on"); return; }
      if (instant) el.classList.add("instant");
      el.style.width = a.offsetWidth + "px"; el.style.height = a.offsetHeight + "px";
      el.style.transform = `translate(${a.offsetLeft}px, ${a.offsetTop}px)`;
      el.classList.add("on");
      if (instant) { void el.offsetWidth; el.classList.remove("instant"); }
    };
    let cur = nav.querySelector('a[aria-current="page"]');
    /* pastila pornește de unde era pe pagina de dinainte (ținută minte la click) și alunecă spre pagina de acum.
       films.js blochează prima afișare (blocking="render"), deci pastila apare direct acolo: fără să clipească. */
    let from = null, sliding = false;
    try { from = JSON.parse(sessionStorage.getItem("safeeel-pill") || "null"); sessionStorage.removeItem("safeeel-pill"); } catch (e) { from = null; }
    if (from && cur && !reduce && Date.now() - from.t < 5000 && from.href !== cur.href) {
      pill.classList.add("instant", "on");
      pill.style.width = from.w + "px"; pill.style.height = from.h + "px";
      pill.style.transform = `translate(${from.x}px, ${from.y}px)`;
      cur.classList.add("pill-wait");
      void pill.offsetWidth; pill.classList.remove("instant");
      sliding = true;
      requestAnimationFrame(() => requestAnimationFrame(() => { place(pill, cur, false); cur.classList.remove("pill-wait"); }));
      setTimeout(() => { sliding = false; }, 450);
    } else {
      place(pill, cur, true);
    }
    links().forEach((a) => {
      a.addEventListener("mouseenter", () => { if (a !== cur) place(hov, a, !hov.classList.contains("on")); else hov.classList.remove("on"); });
      a.addEventListener("click", (e) => {
        if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || a === cur || reduce) return;
        /* fără așteptare: pastila alunecă aici, pe pagina de acum, cât se încarcă pagina nouă (browserul o ține
           pe ecran până e gata cea nouă); pe pagina nouă apare direct la locul ei, deci nu sare înapoi */
        hov.classList.remove("on");
        if (cur) {
          try { sessionStorage.setItem("safeeel-pill", JSON.stringify({ x: cur.offsetLeft, y: cur.offsetTop, w: cur.offsetWidth, h: cur.offsetHeight, href: cur.href, t: Date.now() })); } catch (err) { /* nimic */ }
        }
        cur = a;
      });
    });
    nav.addEventListener("mouseleave", () => hov.classList.remove("on"));
    window.addEventListener("resize", () => place(pill, cur, false));
    /* pagina întoarsă din istoric (Înapoi): pastila revine pe pagina curentă */
    window.addEventListener("pageshow", (e) => { if (!e.persisted) return; links().forEach((x) => x.classList.remove("pill-target", "pill-leave"));
      cur = nav.querySelector('a[aria-current="page"]'); place(pill, cur, true); });
    /* fonturile încărcate mai târziu pot muta puțin meniul: pastila se potrivește LIN, fără să taie alunecarea */
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => setTimeout(() => place(pill, cur, !sliding), sliding ? 460 : 0));
  }


  /* „Nu-l cunosc” (panoul live): în loc de text, animația cu schimbarea parolei hotspotului, direct pe tot ecranul.
     Stă în afara panoului (care se reîmprospătează singur), deci nu se întrerupe. Fără JavaScript: rămâne textul. */
  document.addEventListener("click", (e) => {
    const sum = e.target.closest && e.target.closest("details.unknown-help > summary");
    if (!sum || reduce) return;
    e.preventDefault();
    if (document.querySelector(".film-slot[data-ephemeral]")) return;
    const slot = document.createElement("div");
    slot.className = "film-slot film-ephemeral";
    Object.assign(slot.dataset, { page: "hotspot_pw", hide: "no", ephemeral: "1", lang: document.documentElement.lang === "en" ? "en" : "ro" });
    document.body.appendChild(slot);
    mount(slot);
    const film = [...live].find((f) => f.slot === slot);
    if (film) toggleMax(film); else slot.remove();
  }, true);

  document.addEventListener("change", (e) => {
    const inp = e.target.closest && e.target.closest("input[data-autosubmit-file]");
    if (inp && inp.files && inp.files.length && inp.form) {
      const lbl = inp.form.querySelector(".hm-import-btn"); if (lbl) lbl.classList.add("busy");
      inp.form.submit();
    }
  });


  /* ================= „Bun venit”: progresul scanării se actualizează singur ================= */
  /* doar caseta scanării se reîmprospătează (pagina și animația rămân pe loc); cronometrul numără invers de la 3:00 */
  (function () {
    const SKEY = "safeeel-wc-start", TOTAL = 180;
    const startAt = () => { try { let v = parseInt(sessionStorage.getItem(SKEY) || "0", 10);
      if (!v) { v = Date.now(); sessionStorage.setItem(SKEY, String(v)); } return v; } catch (e) { return Date.now(); } };
    const clearStart = () => { try { sessionStorage.removeItem(SKEY); } catch (e) { /* nimic */ } };
    /* toate numărătorile din pagină (Live și „Bun venit”): 3 minute de la începutul scanării (data-start, de la scanare) */
    function tickAll() {
      const en = document.documentElement.lang === "en";
      document.querySelectorAll(".scan-timer[data-start]").forEach((t) => {
        if (t.closest("#wc-scan")) return;
        const el = Math.max(0, Date.now() / 1000 - parseFloat(t.dataset.start)), left = Math.max(0, Math.round(TOTAL - el));
        t.textContent = left > 0 ? `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}` : (en ? "almost done" : "aproape gata");
      });
      document.querySelectorAll(".scan-bar[data-start]:not(.wc-bar) > span").forEach((s) => {
        const bar = s.parentElement, el = Math.max(0, Date.now() / 1000 - parseFloat(bar.dataset.start));
        s.style.width = Math.min(98, Math.max(parseFloat(bar.dataset.pct || "0"), (el / TOTAL) * 100)).toFixed(1) + "%";
      });
    }
    setInterval(tickAll, 1000);
    function tickTimer() {
      tickAll();
      const box = document.getElementById("wc-scan"); if (!box) return;
      const t = box.querySelector(".wc-timer"), fill = box.querySelector(".wc-fill");
      if (!t) return;
      const begin = t.dataset.start ? parseFloat(t.dataset.start) * 1000 : startAt();
      const el = Math.max(0, (Date.now() - begin) / 1000), left = Math.max(0, Math.round(TOTAL - el));
      const en = document.documentElement.lang === "en";
      if (left > 0) { t.textContent = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`; }
      else { t.textContent = en ? "almost done…" : "aproape gata…"; const l = box.querySelector(".wc-left"); if (l) l.textContent = ""; }
      if (fill) {   /* bara: cât arată nmap sau cât a trecut din cele 3 minute (cel mai mare), dar nu 100 până la final */
        const pct = Math.min(98, Math.max(parseInt(fill.dataset.pct || "0", 10), (el / TOTAL) * 100));
        fill.style.width = pct.toFixed(1) + "%";
      }
    }
    async function poll() {
      const box = document.getElementById("wc-scan");
      if (!box || !box.dataset.wcPoll) return;
      try {
        const r = await fetch("/bun-venit/stare", { headers: { "X-Requested-With": "fetch" }, credentials: "same-origin" });
        if (r.ok) {
          const html = await r.text();
          const next = new DOMParser().parseFromString(html, "text/html").getElementById("wc-scan");
          if (next) {
            if (next.dataset.state !== box.dataset.state || next.dataset.state !== "running") box.replaceWith(next);
            else {   /* tot rulează: schimbăm doar procentul și etapa, fără să clipească nimic */
              const f = box.querySelector(".wc-fill"), nf = next.querySelector(".wc-fill");
              if (f && nf) f.dataset.pct = nf.dataset.pct;
              const p = box.querySelector(".wc-phase"), np = next.querySelector(".wc-phase");
              if (p && np && p.textContent !== np.textContent) p.textContent = np.textContent;
            }
            if (next.dataset.state === "done") clearStart();
          }
        }
      } catch (e) { /* serverul nu răspunde: încercăm din nou */ }
      tickTimer();
      const cur = document.getElementById("wc-scan");
      if (cur && cur.dataset.wcPoll) setTimeout(poll, parseInt(cur.dataset.wcPoll, 10) || 2000);
    }
    function boot() {
      const box = document.getElementById("wc-scan"); if (!box) return;
      if (box.dataset.state === "running" || box.dataset.state === "waiting_next") startAt();
      if (box.dataset.state === "idle" || box.dataset.state === "done") clearStart();
      tickTimer();
      setInterval(tickTimer, 1000);
      if (box.dataset.wcPoll) setTimeout(poll, 2000);
    }
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
  })();

  /* ================= Turul aplicației: o casetă care arată, pe rând, fiecare parte (și pe celelalte pagini) =================
     Pornește cu ?tour=1 (după „Bun venit” sau din meniul „Scanarea din…”). Pasul curent stă în sessionStorage. */
  const TOUR = [
    { path: "/", sel: ".home-head .score, .home-head .ring-wrap",
      ro: ["Scorul rețelei tale", "E ca nota de la revizia mașinii: 100 înseamnă că totul e în regulă. Fiecare problemă scade din notă, iar fiecare reparație o ridică la loc."],
      en: ["Your network score", "It's like the grade from a car service: 100 means all is well. Each problem lowers it, each fix brings it back up."] },
    { path: "/", sel: ".step-title",
      ro: ["Ce trebuie reparat", "SafeEel îți arată întâi problema cea mai gravă, ca un medic care tratează mai întâi febra. Apasă săgeata de lângă titlu ca să afli de ce contează."],
      en: ["What needs fixing", "SafeEel shows the most serious problem first, like a doctor treating the fever first. Press the arrow next to the title to learn why it matters."] },
    { path: "/", sel: "#worst .film-slot .film-view, #worst .film-slot",
      ro: ["Cum o repari, pas cu pas", "E ca o rețetă video: îți arată exact pe ce apeși, pe telefon sau pe laptop. O poți opri, da înapoi sau mări pe tot ecranul."],
      en: ["How to fix it, step by step", "It's like a video recipe: it shows exactly what to press, on the phone or the laptop. You can pause it, go back or make it full screen."] },
    { path: "/", sel: "#worst .do-first-actions",
      ro: ["Ai făcut pasul? Verifică", "Apasă aici după ce ai făcut pasul. SafeEel verifică pe loc, ca atunci când încerci clanța după ce ai încuiat ușa. Dacă e reparat, scorul crește."],
      en: ["Done the step? Check it", "Press here after doing the step. SafeEel checks right away, like trying the handle after locking the door. If it's fixed, the score goes up."] },
    { path: "/", sel: ".home-menu > summary",
      ro: ["Scanările tale și raportul", "Aici găsești scanările mai vechi, poți aduce un fișier de scanare și poți descărca raportul. E ca dosarul pe care îl dai electricianului sau firmei de IT."],
      en: ["Your scans and the report", "Here you find older scans, can bring in a scan file and download the report. It's like the folder you hand to the electrician or the IT company."] },
    { path: "/", sel: ".ai-fab",
      ro: ["Întreabă-l pe SafeEel", "Nu înțelegi ceva? Întreabă-l cu cuvintele tale, de exemplu „ce e un router?”. Răspunde doar despre rețeaua ta."],
      en: ["Ask SafeEel", "Don't understand something? Ask in your own words, for example “what is a router?”. It answers only about your network."] },
    { path: "/protectie", sel: ".page-film .film-view, .page-film",
      ro: ["Live: paznicul rețelei", "Cât e pornită, protecția live e ca un paznic la intrare: îți spune pe loc dacă intră cineva nou în hotspot. Tot de aici pornești o scanare nouă."],
      en: ["Live: the network's guard", "While it's on, live protection is like a guard at the door: it tells you right away when someone new joins the hotspot. You also start a new scan here."] },
    { path: "/devices", sel: ".page-film .film-view, .page-film",
      ro: ["Dispozitive: cine e la tine acasă", "Lista cu tot ce e conectat: telefoane, laptopuri, imprimante, televizoare. Un aparat pe care nu-l cunoști e ca un musafir pe care nu l-ai invitat."],
      en: ["Devices: who's at your place", "The list of everything connected: phones, laptops, printers, TVs. A device you don't know is like a guest you didn't invite."] },
    { path: "/journal", sel: ".page-film .film-view, .page-film",
      ro: ["Alerte: ce s-a schimbat", "E ca jurnalul casei: aici vezi când a apărut un aparat nou sau când o problemă a dispărut."],
      en: ["Alerts: what changed", "It's like the house's diary: here you see when a new device showed up or when a problem went away."] },
    { path: "/history", sel: ".page-film .film-view, main .page-head",
      ro: ["Progres: cât de departe ai ajuns", "Ca un grafic al pașilor făcuți într-o lună: vezi cum crește scorul de la o scanare la alta și dovada a ce ai reparat."],
      en: ["Progress: how far you've come", "Like a chart of your steps over a month: you see the score grow from one scan to the next, with proof of what you fixed."] },
    { path: "/", sel: null,
      ro: ["Gata!", "Acum știi tot ce trebuie. Începe cu primul pas de pe Acasă: durează doar câteva minute. Turul îl poți relua oricând din meniul „Scanarea din…”."],
      en: ["All done!", "Now you know everything you need. Start with the first step on Home: it only takes a few minutes. You can take the tour again anytime from the “Scan from…” menu."] },
  ];
  const TKEY = "safeeel-tour";
  const tourGet = () => { try { const v = sessionStorage.getItem(TKEY); return v === null ? null : parseInt(v, 10); } catch (e) { return null; } };
  const tourSet = (i) => { try { if (i === null) sessionStorage.removeItem(TKEY); else sessionStorage.setItem(TKEY, String(i)); } catch (e) { /* nimic */ } };
  function tourGo(i) {
    if (i < 0 || i >= TOUR.length) { tourEnd(); return; }
    tourSet(i);
    if (TOUR[i].path !== location.pathname) { window.location.href = TOUR[i].path; return; }
    tourShow(i);
  }
  function tourEnd() {
    tourSet(null);
    document.querySelectorAll(".tour-spot, .tour-bubble, .tour-shade").forEach((x) => { x.classList.remove("on"); setTimeout(() => x.remove(), 250); });
    document.removeEventListener("keydown", tourKeys);
  }
  function tourKeys(e) {
    const i = tourGet(); if (i === null) return;
    if (e.key === "Escape") tourEnd();
    else if (e.key === "ArrowRight") tourGo(i + 1);
    else if (e.key === "ArrowLeft" && i > 0) tourGo(i - 1);
  }
  function tourShow(i) {
    const en = document.documentElement.lang === "en";
    const step = TOUR[i];
    const [title, text] = en ? step.en : step.ro;
    let shade = document.querySelector(".tour-shade"), spot = document.querySelector(".tour-spot"), bub = document.querySelector(".tour-bubble");
    if (!shade) { shade = Object.assign(document.createElement("div"), { className: "tour-shade" }); document.body.appendChild(shade); }
    if (!spot) { spot = Object.assign(document.createElement("div"), { className: "tour-spot" }); document.body.appendChild(spot); }
    if (!bub) {
      bub = Object.assign(document.createElement("div"), { className: "tour-bubble" });
      bub.setAttribute("role", "dialog"); bub.setAttribute("aria-modal", "false"); bub.setAttribute("aria-labelledby", "tour-h");
      document.body.appendChild(bub);
      document.addEventListener("keydown", tourKeys);
    }
    const last = i === TOUR.length - 1;
    bub.innerHTML = `<p class="tour-count">${i + 1} ${en ? "of" : "din"} ${TOUR.length}</p>
      <h2 id="tour-h">${esc(title)}</h2><p class="tour-text">${esc(text)}</p>
      <div class="tour-btns">${i > 0 ? `<button type="button" class="tour-back">${en ? "Back" : "Înapoi"}</button>` : ""}
        <button type="button" class="tour-next">${last ? (en ? "Finish" : "Gata") : (en ? "Next" : "Înainte")}</button></div>
      <button type="button" class="tour-close" aria-label="${en ? "Close the tour" : "Închide turul"}">✕</button>`;
    bub.querySelector(".tour-next").addEventListener("click", () => (last ? tourEnd() : tourGo(i + 1)));
    const back = bub.querySelector(".tour-back"); if (back) back.addEventListener("click", () => tourGo(i - 1));
    bub.querySelector(".tour-close").addEventListener("click", tourEnd);
    const target = step.sel ? step.sel.split(",").map((q) => document.querySelector(q.trim())).find((x) => x && x.getBoundingClientRect().width) : null;
    const place = () => {
      const vw = window.innerWidth, vh = window.innerHeight, pad = 10;
      if (!target) {
        spot.classList.remove("on"); shade.classList.add("on");
        bub.style.left = Math.max(16, (vw - bub.offsetWidth) / 2) + "px"; bub.style.top = Math.max(16, (vh - bub.offsetHeight) / 2) + "px";
      } else {
        shade.classList.remove("on");
        const r = target.getBoundingClientRect();
        const box = { x: Math.max(6, r.left - pad), y: Math.max(6, r.top - pad), w: Math.min(vw - 12, r.width + pad * 2), h: Math.min(vh - 12, r.height + pad * 2) };
        Object.assign(spot.style, { left: box.x + "px", top: box.y + "px", width: box.w + "px", height: box.h + "px" });
        spot.classList.add("on");
        const below = box.y + box.h + 14, above = box.y - bub.offsetHeight - 14;
        const top = below + bub.offsetHeight < vh - 8 ? below : (above > 8 ? above : Math.max(8, vh - bub.offsetHeight - 16));
        const left = Math.min(vw - bub.offsetWidth - 16, Math.max(16, box.x + box.w / 2 - bub.offsetWidth / 2));
        bub.style.left = left + "px"; bub.style.top = top + "px";
      }
      bub.classList.add("on");
    };
    if (target) {
      target.scrollIntoView({ block: "center", behavior: reduce ? "auto" : "smooth" });
      setTimeout(place, reduce ? 0 : 420);
    } else {
      place();
    }
    window.onresize = () => { if (tourGet() !== null) place(); };
    window.onscroll = () => { if (tourGet() !== null && target) place(); };
    setTimeout(() => { const n = bub.querySelector(".tour-next"); if (n) n.focus({ preventScroll: true }); }, 450);
  }
  function tourBoot() {
    const params = new URLSearchParams(location.search);
    if (params.get("tour") === "1") {
      tourSet(0);
      params.delete("tour");
      history.replaceState(null, "", location.pathname + (params.toString() ? "?" + params : "") + location.hash);
    }
    const i = tourGet();
    if (i !== null && TOUR[i] && TOUR[i].path === location.pathname) setTimeout(() => tourShow(i), 600);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", tourBoot); else tourBoot();

  /* montează filmele din pagină și pe cele care apar după o actualizare parțială (app.js înlocuiește #worst) */
  function scan() { navPill(); document.querySelectorAll(".film-slot:not([data-mounted])").forEach(mount); animateScores(); wireScore(); floatScore(); toastVerify(); centerDigits(); scrollToWizard(); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", scan); else scan();
  new MutationObserver(scan).observe(document.documentElement, { childList: true, subtree: true });
})();
