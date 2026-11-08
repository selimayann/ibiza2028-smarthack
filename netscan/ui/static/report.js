// Butonul „Tipărește sau salvează ca PDF” din raport (fișier local; CSP permite doar scripturi de pe același server).
document.getElementById("print-report")?.addEventListener("click", () => window.print());
// „Descarcă PDF”: aplicația face fișierul PDF (câteva secunde); butonul arată că lucrează.
document.getElementById("pdf-report")?.addEventListener("click", (e) => {
  const a = e.currentTarget, label = a.querySelector("span");
  if (a.classList.contains("busy")) { e.preventDefault(); return; }
  a.classList.add("busy");
  if (label && a.dataset.busy) { a.dataset.label = label.textContent; label.textContent = a.dataset.busy; }
  setTimeout(() => { a.classList.remove("busy"); if (label && a.dataset.label) label.textContent = a.dataset.label; }, 8000);
});
// Fără browser care să facă PDF-ul: aplicația ne-a trimis înapoi cu ?print=1 -> fereastra obișnuită de tipărire.
if (new URLSearchParams(location.search).get("print") === "1") window.addEventListener("load", () => setTimeout(() => window.print(), 300));

// La tipărire / „Salvează ca PDF”: raportul încape mereu pe O SINGURĂ pagină A4. Dacă e mai lung decât pagina,
// îl micșorăm cât trebuie (zoom), apoi revine la normal după tipărire.
(function () {
  const report = document.querySelector(".report");
  if (!report) return;
  // A4 cu marginile din report.css (9 mm sus/jos): înălțimea utilă, în pixeli CSS (96 px = 1 inch = 25,4 mm)
  const PAGE_H = ((297 - 18) * 96) / 25.4 - 6;
  const fit = () => {
    report.style.zoom = "";
    for (let i = 0; i < 3; i++) {   // micșorarea face rândurile mai late, deci textul ocupă mai puțin: reverificăm
      const z = parseFloat(report.style.zoom || "1");
      const h = report.getBoundingClientRect().height / z;
      const want = Math.min(1, PAGE_H / h);
      if (Math.abs(want - z) < 0.005) break;
      report.style.zoom = String(want);
    }
  };
  const reset = () => { report.style.zoom = ""; };
  const mq = window.matchMedia && window.matchMedia("print");
  if (mq && mq.addEventListener) mq.addEventListener("change", (e) => (e.matches ? fit() : reset()));
  window.addEventListener("beforeprint", () => requestAnimationFrame(fit));
  window.addEventListener("afterprint", reset);
})();
