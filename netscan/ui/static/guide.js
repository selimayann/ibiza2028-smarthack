// „Începe depanarea”: ghid pas cu pas într-un <dialog>. Îmbunătățire progresivă: fără JavaScript butonul duce la pagina dispozitivului.
// Nu scriem HTML din text: doar arătăm/ascundem scene deja randate (și escapate) de server.
(() => {
  "use strict";
  if (typeof HTMLDialogElement === "undefined") return;

  function setStep(dlg, i) {
    const scenes = Array.from(dlg.querySelectorAll("[data-scene]"));
    const n = Math.max(0, Math.min(i, scenes.length - 1));
    scenes.forEach((s, k) => { s.hidden = k !== n; });   // scena devine vizibilă => animațiile CSS pornesc de la capăt
    dlg.dataset.step = String(n);
    dlg.querySelectorAll(".guide-dots li").forEach((d, k) => d.classList.toggle("now", k === n));
    const count = dlg.querySelector("[data-guide-count]");
    if (count) count.textContent = (count.dataset.fmt || "%s / %s").replace("%s", String(n + 1)).replace("%s", String(scenes.length));
    const prev = dlg.querySelector("[data-guide-prev]");
    const next = dlg.querySelector("[data-guide-next]");
    if (prev) prev.disabled = n === 0;
    if (next) next.hidden = n === scenes.length - 1;     // pe ultimul pas rămâne doar „Am făcut asta, verifică”
    focusScene(dlg);
  }

  // Focusul pe textul scenei vizibile (cititorul de ecran îl citește). Doar cu fereastra deschisă: într-un
  // <dialog> închis focus() nu face nimic, iar showModal() l-ar muta oricum pe primul buton.
  function focusScene(dlg) {
    const text = dlg.open && dlg.querySelector("[data-scene]:not([hidden]) .scene-text");
    if (text) text.focus({ preventScroll: true });
  }

  document.addEventListener("click", (e) => {
    const open = e.target.closest("[data-guide-open]");
    if (open) {
      const dlg = document.getElementById("guide");
      if (!dlg || !dlg.showModal) return;
      e.preventDefault();
      if (dlg.open) dlg.close();   // showModal() pe un dialog deja deschis aruncă eroare (și nu se mai deschide)
      setStep(dlg, 0);
      dlg.showModal();
      focusScene(dlg);
      return;
    }
    const dlg = e.target.closest("dialog.guide");
    if (!dlg) return;
    const cur = Number(dlg.dataset.step || 0);
    if (e.target.closest("[data-guide-next]")) setStep(dlg, cur + 1);
    else if (e.target.closest("[data-guide-prev]")) setStep(dlg, cur - 1);
    else if (e.target.closest("[data-guide-close]") || e.target === dlg) dlg.close();   // click pe fundal închide
  });

  // După „Am făcut asta, verifică” închidem fereastra; app.js schimbă apoi zona paginii.
  document.addEventListener("submit", (e) => {
    const dlg = e.target.closest && e.target.closest("dialog.guide");
    if (dlg && dlg.open) dlg.close();
  }, true);
})();
