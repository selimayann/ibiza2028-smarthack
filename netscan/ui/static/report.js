// Butonul „Tipărește sau salvează ca PDF” din raport (fișier local; CSP permite doar scripturi de pe același server).
document.getElementById("print-report")?.addEventListener("click", () => window.print());
