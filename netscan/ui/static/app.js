// Actualizări parțiale (fără reîncărcarea paginii), ca îmbunătățire progresivă.
// Fără JavaScript, formularele și linkurile merg normal (pagina se reîncarcă), deci nimic nu depinde de acest fișier.
// Răspunsul vine de la același server, deja escapat de Jinja; îl parsăm cu DOMParser (scripturile din el nu rulează).
(() => {
  "use strict";
  if (!window.fetch || !window.DOMParser) return;
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  async function swap(url, init, selectors, focusSel, keepUrl) {
    let res;
    try {
      res = await fetch(url, { ...init, credentials: "same-origin", headers: { "X-Requested-With": "fetch" } });
    } catch (_) {
      return false;
    }
    if (!res.ok) return false;
    const doc = new DOMParser().parseFromString(await res.text(), "text/html");
    const apply = () => {
      for (const sel of selectors) {
        const now = document.querySelector(sel);
        const next = doc.querySelector(sel);
        if (now && next) now.replaceWith(next);
        else if (now && !next) now.remove(); // de ex. o scanare ilizibilă nu are asistent
      }
      if (doc.title) document.title = doc.title;
    };
    // Focusul merge pe ce s-a schimbat (de ex. pasul nou), ca tastatura și cititorul de ecran să-l găsească.
    const focus = () => {
      const el = focusSel && document.querySelector(focusSel);
      if (el) el.focus({ preventScroll: true });
    };
    if (document.startViewTransition && !reduced) {
      document.startViewTransition(apply).updateCallbackDone.then(focus, focus);
    } else {
      apply();
      focus();
    }
    if (keepUrl) history.replaceState(null, "", res.url);
    return true;
  }

  const targets = (el) => (el.dataset.swap || "").split(",").map((s) => s.trim()).filter(Boolean);

  document.addEventListener("submit", async (e) => {
    const form = e.target.closest("form[data-swap]");
    if (!form || e.defaultPrevented) return;
    e.preventDefault();
    const method = (form.getAttribute("method") || "get").toUpperCase();
    const data = new FormData(form);
    let url = form.action.split("#")[0];
    const init = { method };
    if (method === "GET") url += (url.includes("?") ? "&" : "?") + new URLSearchParams(data).toString();
    else init.body = data;
    const busy = form.querySelector("button[type=submit]");
    if (busy) busy.disabled = true;
    const ok = await swap(url, init, targets(form), form.dataset.focus, method === "GET" || form.dataset.keepUrl === "1");
    if (!ok) form.submit(); // dacă ceva nu merge, revenim la comportamentul normal
  });

  document.addEventListener("click", async (e) => {
    const a = e.target.closest("a[data-swap]");
    if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    const ok = await swap(a.href.split("#")[0], { method: "GET" }, targets(a), a.dataset.focus, true);
    if (!ok) window.location.href = a.href;
  });

  // ---------- protecția live: panoul „Rețeaua ta acum” se reîmprospătează singur ----------
  // Aduce /live/panel (HTML de la același server, escapat de Jinja), îl parsează cu DOMParser ca swap() și
  // înlocuiește panoul doar dacă s-a schimbat ceva (data-version). Focusul rămâne pe același buton/titlu, iar
  // ultimul eveniment e anunțat o singură dată cititorului de ecran (#live-announce, în afara panoului).
  const liveEl = () => document.getElementById("live");
  const focusKey = (a, panel) => {
    if (!a || !panel.contains(a)) return null;
    if (a.id) return "#" + a.id;
    const form = a.closest("form");
    return form ? 'form[action="' + form.getAttribute("action") + '"] [type=submit]' : null;
  };
  let liveBusy = false;
  let liveNext = 0;
  window.setInterval(async () => {
    const el = liveEl();
    if (!el || liveBusy || document.visibilityState !== "visible") return;
    const ms = parseInt(el.dataset.poll || "0", 10);
    if (!ms || Date.now() < liveNext) return;
    liveBusy = true;
    try {
      const res = await fetch(el.dataset.panel, { credentials: "same-origin", headers: { "X-Requested-With": "fetch" } });
      if (res.ok) {
        const next = new DOMParser().parseFromString(await res.text(), "text/html").getElementById("live");
        const now = liveEl();
        if (next && now && next.dataset.version !== now.dataset.version) {
          const key = focusKey(document.activeElement, now);
          const before = now.dataset.latest || "";
          const fixesBefore = now.dataset.fixes || "0";
          now.replaceWith(next);
          // O reparație confirmată live: scorul (al motorului) și cardul dispozitivului se actualizează singure.
          if ((next.dataset.fixes || "0") !== fixesBefore && document.getElementById("score")) {
            swap(window.location.href.split("#")[0], { method: "GET" }, ["#score", "#worst"], null, false);
          }
          const f = key && document.querySelector(key);
          if (f) f.focus({ preventScroll: true });
          const say = document.getElementById("live-announce");
          if (say && next.dataset.latest && next.dataset.latest !== before) say.textContent = next.dataset.latest;
        }
      }
    } catch (_) { /* serverul s-a oprit: încercăm din nou la tura următoare */ }
    const cur = liveEl();
    liveNext = Date.now() + ((cur && parseInt(cur.dataset.poll || "0", 10)) || 2000);
    liveBusy = false;
  }, 1000);

  // Alegerea scanării: se schimbă direct când alegi din listă (butonul „Arată” rămâne pentru tastatură și fără JS).
  document.addEventListener("change", (e) => {
    const sel = e.target.closest("select[data-autosubmit]");
    if (sel && sel.form) sel.form.requestSubmit();
  });

  // ---------- asistentul AI: fereastra de chat (<dialog> nativ) ----------
  // Fără JS, butonul și formularele reîncarcă pagina cu fereastra deschisă. Cu JS: fereastră modală,
  // întrebările merg la /api/ask, iar răspunsul (JSON) se pune în pagină DOAR cu textContent.
  // Elementele se caută la fiecare acțiune: la schimbarea scanării, fereastra e înlocuită.
  const chatEl = () => {
    const c = document.getElementById("chat");
    return c && typeof c.showModal === "function" ? c : null;
  };
  const svg = (id) => {
    const ns = "http://www.w3.org/2000/svg";
    const s = document.createElementNS(ns, "svg");
    s.setAttribute("class", "icon");
    s.setAttribute("aria-hidden", "true");
    const u = document.createElementNS(ns, "use");
    u.setAttribute("href", "#i-" + id);
    s.appendChild(u);
    return s;
  };
  // Volt (mascota): copie din <template id="volt-tpl">, doar decor (aria-hidden); starea e scrisă și în text.
  const volt = (chat, state) => {
    const tpl = chat.querySelector("#volt-tpl");
    const s = tpl && tpl.content.querySelector("svg.s-" + state);
    return s ? s.cloneNode(true) : null;
  };
  const bubble = (log, cls, text, mascot) => {
    const el = document.createElement("div");
    el.className = "msg " + cls;
    const p = document.createElement("p");
    p.textContent = text;
    el.appendChild(p);
    let node = el;
    if (mascot) {
      node = document.createElement("div");
      node.className = "msg-row";
      const face = document.createElement("span");
      face.className = "msg-volt";
      face.appendChild(mascot);
      node.append(face, el);
    }
    log.appendChild(node);
    log.scrollTop = log.scrollHeight;
    return { el, node };
  };
  const openChat = (chat) => {
    if (chat.open) chat.close();
    chat.showModal();
    const log = chat.querySelector("#chat-log");
    if (log) log.scrollTop = log.scrollHeight;
    const input = chat.querySelector("#q");
    if (input) input.focus();
  };
  // Venit cu fereastra deschisă din server (link fără JS, sau ?ask=1): o facem modală.
  const first = chatEl();
  if (first && first.hasAttribute("open")) openChat(first);

  document.addEventListener("click", (e) => {
    const chat = chatEl();
    if (!chat) return;
    if (e.target === chat) { chat.close(); return; }       // click pe fundalul din jurul ferestrei
    const t = e.target.closest("[data-chat-open]");
    if (!t || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey) return;
    e.preventDefault();
    openChat(chat);
  });

  document.addEventListener("submit", async (e) => {
    const form = e.target.closest("form[data-chat-form]");
    const chat = chatEl();
    if (!form || !chat) return;
    e.preventDefault();
    const log = chat.querySelector("#chat-log");
    const input = chat.querySelector("#q");
    const q = ((e.submitter && e.submitter.name === "q" ? e.submitter.value : input && input.value) || "").trim().slice(0, 500);
    if (!q) { if (input) input.focus(); return; }
    const you = bubble(log, "msg-user", q).el;
    you.setAttribute("aria-label", (chat.dataset.you || "") + " " + q);
    if (input) input.value = "";
    const wait = bubble(log, "msg-bot msg-thinking", chat.dataset.thinking || "…", volt(chat, "gandeste")).node;
    const buttons = chat.querySelectorAll("form[data-chat-form] button");
    buttons.forEach((b) => { b.disabled = true; });
    let data = null;
    try {
      const res = await fetch(chat.dataset.api + "&q=" + encodeURIComponent(q), {
        credentials: "same-origin", headers: { "Accept": "application/json" },
      });
      if (res.ok) data = await res.json();
    } catch (_) { data = null; }
    wait.remove();
    const states = ["verificat", "prins", "fara-ai"];
    const state = data && data.ok && states.includes(data.state) ? data.state : "fara-ai";
    const answer = bubble(log, "msg-bot", data && data.text ? data.text : (chat.dataset.error || ""), volt(chat, state)).el;
    if (data && data.ok && data.source_label) {
      const src = document.createElement("p");
      src.className = "msg-src";
      src.appendChild(svg(["eel", "shield", "info"].includes(data.source_icon) ? data.source_icon : "info"));
      src.appendChild(document.createTextNode(data.source_label));
      answer.appendChild(src);
    }
    log.scrollTop = log.scrollHeight;
    buttons.forEach((b) => { b.disabled = false; });
    if (input) input.focus();
  });
})();
