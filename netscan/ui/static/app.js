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

  // Alegerea scanării: se schimbă direct când alegi din listă (butonul „Arată” rămâne pentru tastatură și fără JS).
  document.addEventListener("change", (e) => {
    const sel = e.target.closest("select[data-autosubmit]");
    if (sel && sel.form) sel.form.requestSubmit();
  });
})();
