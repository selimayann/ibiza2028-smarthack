# Pitch · SafeEel (Ibiza2028) · 7 minutes

> The pitch is in English; all four of us speak. Each part lists **what to say**, **how long**, and **what is on screen**.
> About 140 spoken words per minute. Every figure below comes from the repo (see [technical.md](technical.md), "Cifre") and was re-checked on 8 Nov 2026 (screenshots: current UI, 8 Nov, 04:30).
> The app menu is **Home · Checks · Devices · Alerts · Progress**. Plan B screenshots are in [`docs/pitch/`](pitch/).

| Time | Part | Speaker |
|---|---|---|
| 0:00–1:00 | The problem | RBRT |
| 1:00–3:30 | Live demo | Radu |
| 3:30–4:45 | How it works | Ayan |
| 4:45–5:45 | Numbers | Oneata |
| 5:45–7:00 | Limits and next steps | RBRT |

---

## 0:00–1:00 · The problem (RBRT, 60 s)

**On screen:** SafeEel **Home**, already open in English: "Your network needs attention." No slides.

**Say:**
> Quick question: how many devices are connected to your home Wi-Fi right now? Most people guess five. The real number is usually closer to twenty: phones, the TV, a camera, a printer, a smart plug someone installed and forgot.
>
> Each of them can leave a door open. A camera that anyone on the network can watch. A router admin page that sends your password in plain sight.
>
> Tools exist to find this, like Wazuh. They are built for experts and companies: you need a server, agents on every machine, and an analyst to read the alerts. Families have nothing like that.
>
> So we built SafeEel. It checks your own network, tells you in plain words what is wrong, and gives you one fix at a time. It runs on your laptop, with no account and no cloud. Radu will show you.

---

## 1:00–3:30 · Live demo (Radu, 2 min 30 s)

**On screen:** `python -m netscan ui` on `127.0.0.1:5000`, with `NETSCAN_SCANS_DIR=fixtures/lab` (our lab: one hotspot, one scanner laptop, one target laptop with Docker). The demo laptop is on the hotspot, with `NETSCAN_EXPECTED_SSID` in `.env`.

**Right before the session:** with the lab **running**, press **Scan now** in SafeEel, so the newest check is of our network right now. "I did this, check it" only works on that newest scan, on our own hotspot; on an older scan or a file it is greyed out and says why. Save `scan_01_before.xml` and `scan_03_after.xml` to history for the before/after part. Full checklist: [demo.md](demo.md).

| Time | Click | Say |
|---|---|---|
| 1:00 | **Home**, the scan made just now | "This is our lab network, scanned a few minutes ago with the tool. The first thing you read is the verdict: your network needs attention, and the score next to it." |
| 1:15 | Point at the sentence under the verdict | "And right under it, the answer to the only question that matters: start with this device, do this." |
| 1:30 | Point at **Most dangerous device** | "It is this smart device. High risk, shown with a triangle and a word, not just a colour. One sentence says what is wrong, in words a twelve-year-old understands, and one line says what an attacker could do." |
| 1:50 | Point at **Do this first** and **Show me how, step by step** | "One step, not a list of forty. And if you don't know where that setting is, it shows you, step by step." |
| 2:00 | On the target laptop: `docker compose -f lab/docker-compose.yml stop redis`. Back in SafeEel, on the database step (use **Skip for now** to reach it): **I did this, check it** | "We just turned off the exposed database. Now, when I say I fixed it, SafeEel does not take my word for it: it knocks once on that port, only on our own hotspot. Nobody answers, so the step is confirmed, and the engine recalculates the score." |
| 2:35 | **Progress** tab: score over time | "Every scan is saved on this laptop. Here is the score over time." |
| 2:50 | **See the proof** on `scan_03_after.xml` (saved lab pair) | "Here is the proof from our lab: before and after, zero to thirty. Two problems fixed, two doors closed, and what is still open is still listed. Nothing hidden." |
| 3:10 | **Ask the AI assistant** → "What should I do first?" | "And if you are not sure, you just ask. The answer is built from your scan. Ayan will explain why you can trust it." |

If the target laptop is not reachable: skip the 2:00 row and say "on our hotspot this step is confirmed with a single connection; here the laptop is not on the network, so SafeEel refuses to touch it". That refusal is also the guardrail working.

---

## 3:30–4:45 · How it works (Ayan, 75 s)

**On screen:** a terminal next to the UI. At 4:20, run the validator demo.

**Say:**
> Our rule is simple: **code decides, the model words, code checks.**
>
> The findings, severities and score come only from deterministic code: the fifteen rules of the official catalog. No AI decides anything. Run it twice, you get the same file byte for byte.
>
> The live scan has a guardrail. It only scans the hotspot we are connected to. Public IPs, bigger ranges, the venue network, a VPN: refused before nmap even starts.
>
> Everything is local-first. No account, no cloud, nothing leaves the network. The optional AI is a small model on this laptop, and it only rewords text that the code already wrote.
>
> And we don't trust it blindly. Watch: I give the validator a made-up answer with a port, an IP and a phone number that are not in the scan.

**Run:**
```
python -m netscan ask fixtures/validation/V2_smart_home.xml x --verify-text "Close port 23 on 192.168.1.99 and call 0721 234 567." --lang en
```
Expected: `Validator: text REJECTED, the predefined answer would be shown. Reasons: IP:192.168.1.99, PORT:23, PHONE`

> Rejected. Anything the model invents, the user never sees.

---

## 4:45–5:45 · Numbers (Oneata, 60 s)

**On screen:** the "Cifre" section of [technical.md](technical.md), or one slide with the numbers below.

**Say:**
> On the official Validation Set we match the answer key exactly: **24 of 24** finding rows and **8 of 8** scores, including the broken file reported as an error instead of crashing.
>
> On top of that we wrote **24 trap files** of our own, and we have **1,608 automated tests**. Two runs of the analysis give identical files.
>
> In our own lab, the score went from **0 to 30** after we fixed two problems.
>
> A **17.7 MB** scan with almost **23,000 devices** is analysed in about **5 seconds** on a normal laptop.
>
> And the explanations pass an **automatic plain-language test**: no unexplained jargon, no sentence over twenty words, every step starts with an action, and an average readability index (LIX) of **40 in Romanian and 35 in English**. To be honest: that is an automatic test. We did not test it with a non-technical person.

| Figure | Where it comes from |
|---|---|
| 24/24 rows, 8/8 scores | `python -m netscan analyze fixtures/validation`, compared with `fixtures/validation/expected_*.csv`; also `results/` (the hour-16 check) |
| 24 trap files | `fixtures/traps/` (T01–T24) |
| 1,608 tests | `pytest -q` on `main`, 8 Nov 2026 (1,608 passed, 1 skipped); **re-check on the `final` tag** |
| 0 → 30 | `fixtures/lab/scan_01_before.xml` → `scan_03_after.xml`, [lab.md](lab.md) |
| 17.7 MB in ~5 s | measured 4.5–5.2 s (22,780 devices, 28,475 findings) under WSL |
| LIX 40 RO / 35 EN | `python scripts/plain_language_report.py` (40.4 / 35.3) |

> If someone tests the Romanian explanations with a non-technical person before the jury, say it here instead of "we did not". It is a bonus signal in the brief.

---

## 5:45–7:00 · Limits and next steps (RBRT, 75 s)

**On screen:** the "Limitări" section of [technical.md](technical.md), or one slide with two columns: *What we don't do (yet)* / *Next*.

**Say:**
> We want to be honest about the limits.
>
> One: UDP ports that nmap reports as "open or filtered" are not counted. Nmap cannot tell open from blocked there, and we would rather miss a problem than invent one.
>
> Two: modern phones and laptops use a random MAC address, so the exact rule calls them unknown devices. The app shows them as "private address" so nobody panics.
>
> Three: we only had a small hotspot. A full /24 home network with many devices may take longer than five minutes, and we could not verify that legally.
>
> Four: there is no login. That was a choice: the app only listens on this laptop, and it rejects requests from other websites.
>
> Next: protection with an authenticator app, profiles for more than one network, the local AI model built in instead of installed separately, and export and import of the history.
>
> SafeEel: your network, simply explained. Thank you.

---

## Likely jury questions

**Why no login?**
The UI only listens on `127.0.0.1`, without debug. It accepts only requests addressed to the local machine (protection against DNS rebinding). Every action needs a per-session token, and requests from other websites are refused. A password would only protect against someone already sitting at your unlocked laptop. For that case we plan protection with an authenticator app.

**Why don't you encrypt the database?**
It stays on your own disk and holds no passwords and no real MAC addresses: MACs are masked, and devices are identified by a hash with a local salt. The right layer is disk encryption (BitLocker / FileVault), which also protects everything else on the laptop. There is a "delete my history" button, and the page "What SafeEel knows about you" lists exactly what is stored.

**How do you know a fix really happened?**
"I did this, check it" makes one TCP connection to the problem's port, only if the device is on the hotspot we are connected to. If the port refuses, the step is confirmed and the engine recalculates the score shown under the standard one. If it still answers, the step stays to do. A newer scan of the same network confirms fixes too. The standard score of a saved scan never changes.

**What do you do with random MAC addresses?**
The rule stays exact: no vendor means `UNKNOWN_DEVICE`, as the catalog says. The UI explains it as a "private address" and tells the user to check their own phones first. In the history we recognise a device again by its IP when its MAC changed, and we say so on screen.

**How long does a /24 take?**
Honestly, we don't know. Our /28 with 2 devices took 3 min 25 s, with `--max-rate 100`, UDP and version detection. A /24 with many devices may go over five minutes, and we had no /24 we were allowed to scan.

**What if nmap identifies a service wrongly?**
Then we see it wrongly too: the rules decide on the service name nmap reports, as the mentors confirmed. We document it as a limit. Our trap files cover the tricky cases: the same service on an unusual port, UPnP on TCP vs UDP, HTTP vs HTTPS, and Samba version ranges.

**How do you guarantee a re-run gives the same result?**
The analysis is pure code with no clock, no randomness and no AI. The output is sorted in a fixed order, so two runs produce identical files (tested). For the Test Set we tag the exact commit as `final` and re-run from that tag.

---

## Plan B: if the live demo fails

Switch to the screenshots in [`docs/pitch/`](pitch/) and tell the same story. Don't debug on stage.

| File | Shows | Use at |
|---|---|---|
| `1_home_most_dangerous.png` | Home: verdict, risk labels, "start with", score, most dangerous device, what an attacker could do, "Do this first" (here "I did this, check it" is greyed out, because it is an older lab scan) | 1:00–2:00 |
| `2_device_steps.png` | One device: masked MAC, its problems, explanation and repair steps | 1:50 |
| `3_progress_trend.png` | Progress: score over time 0 → 30 | 2:35 |
| `4_before_after.png` | Proof: before and after, 2 problems fixed, 2 ports closed | 2:50 |
| `5_assistant.png` | Assistant answering "What should I do first?" | 3:10 |
| `6_devices.png` | "What is connected to me?" inventory | backup |
| `7_validator_en.txt` | Validator output (REJECTED, with the reasons) | 4:20 |

If the terminal fails too, read the validator line from `7_validator_en.txt`.
