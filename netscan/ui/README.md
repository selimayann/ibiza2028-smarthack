# netscan/ui (RBRT)

- `app.py` — aplicația Flask, pagina „cel mai periculos dispozitiv — fă asta întâi”
- `storage.py` — istoricul SQLite, `diff()`, `delete_history()`
- `templates/` — pagini Jinja2 (autoescape; niciodată `|safe` pe date din scanare)
- `static/` — CSS/JS locale, fără CDN-uri

Folderele `templates/` și `static/` se creează când apar primele fișiere.
