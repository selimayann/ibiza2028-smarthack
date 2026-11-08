"""Testele nu citesc .env-ul local al cuiva (ex. NETSCAN_LOCAL_LLM=1 pe laptopul de demo): rulează la fel ca în CI.
Se dezactivează încă de la încărcare (înainte de colectare), ca nici un modul importat să nu apuce să-l citească."""
import netscan.cli
import netscan.ui.app


def _skip_env_file(*args, **kwargs) -> None:
    return None


netscan.cli.load_env_file = _skip_env_file
netscan.ui.app.load_env_file = _skip_env_file
