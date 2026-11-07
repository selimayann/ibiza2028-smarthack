#!/bin/bash
# netscan: pornire dintr-un dublu-click (macOS).
# Fără drepturi de administrator, fără comenzi de rețea, fără instalări: doar interfața locală pe 127.0.0.1.
# Portul 5055 (nu 5000): pe macOS, portul 5000 e folosit de AirPlay Receiver.
cd "$(dirname "$0")" || exit 1

if [ -f .venv/bin/activate ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

PY=python3
command -v python3 >/dev/null 2>&1 || PY=python

if ! "$PY" -c "import netscan" >/dev/null 2>&1; then
  echo "netscan nu e instalat. Urmează pașii din README, secțiunea Setup."
  echo "netscan is not installed. Follow the Setup steps in README."
  read -r -p "Apasă Enter pentru a închide / Press Enter to close. " _
  exit 1
fi

echo "Pornesc netscan pe http://127.0.0.1:5055/ . Închide fereastra sau apasă Ctrl+C ca să oprești."
echo "Starting netscan on http://127.0.0.1:5055/ . Close the window or press Ctrl+C to stop."
( sleep 3; open "http://127.0.0.1:5055/" ) &
exec "$PY" -m netscan ui --port 5055
