# Pitch · SafeEel (Ibiza2028) · 7 minutes

> The pitch is in English; all four of us speak. Each part lists **what to say**, **how long**, and **what is on screen**.
> About 140 spoken words per minute. Every figure below comes from the repo (see [technical.md](technical.md), "Cifre") and was re-checked on 7 Nov 2026.
> Plan B screenshots are in [`docs/pitch/`](pitch/).

| Time | Part | Speaker |
|---|---|---|
| 0:00–1:00 | The problem | RBRT |
| 1:00–3:30 | Live demo | Radu |
| 3:30–4:45 | How it works | Ayan |
| 4:45–5:45 | Numbers | Oneata |
| 5:45–7:00 | Limits and next steps | RBRT |

---

## 0:00–1:00 · The problem (RBRT, 60 s)

**On screen:** the SafeEel overview page, already open (score card + "Most dangerous device"). No slides.

**Say:**
> Quick question: how many devices are connected to your home Wi-Fi right now? Most people guess five. The real number is usually closer to twenty: phones, the TV, a camera, a printer, a smart plug someone installed and forgot.
>
> Each of them can leave a door open. A camera that anyone on the network can watch. A router admin page that sends your password in plain sight.
>
> Tools exist to find this, like Wazuh. They are built for experts and companies: you need a server, agents on every machine, and an analyst to read the alerts. Families have nothing like that.
>
> So we built SafeEel. It scans your own network, tells you in plain words what is wrong, and gives you one fix at a time. It runs on your laptop, with no account and no cloud. Radu will show you.

---

## 1:00–3:30 · Live demo (Radu, 2 min 30 s)

**On screen:** `python -m netscan ui` on `127.0.0.1:5000`, with `NETSCAN_SCANS_DIR=fixtures/lab` (our lab: a hotspot, one scanner, one target laptop).

| Time | Click | Say |
|---|---|---|
| 1:00 | Overview of `scan_01_before.xml` | "This is our lab network, scanned with the tool. Score: zero out of a hundred. The page answers one question first: what is the most dangerous device?" |
| 1:20 | Point at the "Most dangerous device" card | "It is this smart device. In red, with a triangle, not just colour: high risk. One sentence says what is wrong, in words a twelve-year-old understands." |
| 1:40 | Point at "Do this first" + "What could an attacker do" (if shown) | "And here is the one thing to do first. Not a list of forty. One step." |
| 2:00 | Click **"I did this, check it"** | "When I say I fixed it, the app does not just believe me. It checks the real device, only on our own network, and the score only moves for confirmed steps." |
| 2:20 | Click **Next step** twice | "I can walk through the steps, in order of risk." |
| 2:40 | **History** tab: trend chart | "After we turned off the database and the old Telnet service on the target, we scanned again." |
| 2:55 | Open `scan_03_after.xml` → "Compared with the previous scan" | "Before and after: score zero to thirty. Two problems fixed, two doors closed, and the eight that remain are still listed. Nothing hidden." |
| 3:15 | Click **Ask the AI assistant** → "What should I do first?" | "And if you are not sure, you just ask. The answer is built from your scan. Ayan will explain why you can trust it." |

---

## 3:30–4:45 · How it works (Ayan, 75 s)

**On screen:** a terminal next to the UI. At 4:20, run the validator demo.

**Say:**
> Our rule is simple: **code decides, the model words, code checks.**
>
> The findings, severities and score come only from deterministic code: the fifteen rules of the official catalog. No AI decides anything. Run it twice, you get the same file byte for byte.
>
> The live scan has a guardrail. It only scans the hotspot we are connected to. Public IPs, bigger ranges, the venue network: refused before nmap even starts.
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
> We have **1,007 automated tests**. Two runs of the analysis give byte-identical files.
>
> In our own lab, the score went from **0 to 30** after we fixed two problems.
>
> A **17.7 MB** scan with almost **23,000 devices** is analysed in about **5 seconds** on a normal laptop.
>
> And the explanations pass an **automatic plain-language test**: no unexplained jargon, no sentence over twenty words, every step starts with an action, and an average readability index (LIX) of **40 in Romanian and 35 in English**. To be honest: that is an automatic test. We did not test it with a non-technical person.

| Figure | Where it comes from |
|---|---|
| 24/24 rows, 8/8 scores | `tests/test_validation_set.py`, `fixtures/validation/expected_*.csv` |
| 1,007 tests | `pytest` on branch `explain-plain` (1,007 passed, 1 skipped); **re-check on the `final` tag** |
| 0 → 30 | `fixtures/lab/scan_01_before.xml` → `scan_03_after.xml`, [lab.md](lab.md) |
| 17.7 MB in ~5 s | measured 4.5–5.2 s (22,780 devices, 28,475 findings) under WSL; see technical.md |
| LIX 40.2 RO / 34.7 EN | `python scripts/plain_language_report.py` |

> Note: an earlier draft said "17.7 MB in 2.5 s". That figure is not in the repo and we could not reproduce it, so the pitch uses the measured ~5 s. If someone re-measures on the demo laptop, update both technical.md and this line.

---

## 5:45–7:00 · Limits and next steps (RBRT, 75 s)

**On screen:** the "Limitări" section, or one slide with two columns: *What we don't do (yet)* / *Next*.

**Say:**
> We want to be honest about the limits.
>
> One: UDP ports that nmap reports as "open or filtered" are not counted. Nmap cannot tell open from blocked there, and we would rather miss a problem than invent one.
>
> Two: modern phones and laptops use a random MAC address, so the exact rule calls them unknown devices. The app shows them as "private address" so nobody panics.
>
> Three: we only had a small hotspot. A full /24 home network with many devices may take longer than five minutes, and we could not verify that legally.
>
> Four: there is no login. That was a choice: the app only listens on this laptop, and it rejects pages from other sites.
>
> Next: protection with an authenticator app, profiles for more than one network, the local AI model built in instead of installed separately, and export and import of the history.
>
> SafeEel: your network, simply explained. Thank you.

---

## Likely jury questions

**Why no login?**
The UI only listens on `127.0.0.1`, without debug. It accepts only requests addressed to the local machine (protection against DNS rebinding). Every action needs a per-session token, and requests from other websites are refused. A password would only protect against someone already sitting at your unlocked laptop. For that case we plan protection with an authenticator app.

**Why don't you encrypt the database?**
It stays on your own disk and holds no passwords and no real MAC addresses: MACs are masked, and devices are identified by a hash with a local salt. The right layer is disk encryption (BitLocker / FileVault), which also protects everything else on the laptop. And there is a "delete history" button.

**What do you do with random MAC addresses?**
The rule stays exact: no vendor means `UNKNOWN_DEVICE`, as the catalog says. The UI explains it as a "private address" and tells the user to check their own phones first. In the history we recognise a device again by its IP when its MAC changed, and we say so on screen.

**How long does a /24 take?**
Honestly, we don't know. Our /28 with 2 devices took 3 min 25 s, with `--max-rate 100`, UDP and version detection. A /24 with many devices may go over five minutes, and we had no /24 we were allowed to scan.

**What if nmap identifies a service wrongly?**
Then we see it wrongly too: the rules decide on the service name nmap reports, as the mentors confirmed. We document it as a limit. Our trap files cover the tricky cases: the same service on an unusual port, UPnP on TCP vs UDP, HTTP vs HTTPS, and Samba version ranges.

**How do you guarantee a re-run gives the same result?**
The analysis is pure code with no clock, no randomness and no AI. The output is sorted in a fixed order, so two runs produce byte-identical files (tested). For the Test Set we tag the exact commit as `final` and re-run from that tag.

---

## Plan B: if the live demo fails

Switch to the screenshots in [`docs/pitch/`](pitch/) and tell the same story. Don't debug on stage.

| File | Shows | Use at |
|---|---|---|
| `1_overview_worst_device.png` | Score, most dangerous device, "Do this first", step check | 1:00–2:20 |
| `2_device_steps.png` | One device: explanation and all repair steps | 1:40 |
| `3_history_trend.png` | Score over time 0 → 30 | 2:40 |
| `4_before_after.png` | Comparison: 2 problems fixed, 2 ports closed | 2:55 |
| `5_assistant.png` | Assistant answering "What should I do first?" | 3:15 |
| `6_devices.png` | "What is connected to me?" inventory | backup |
| `7_validator_en.txt` | Validator output (REJECTED, with the reasons) | 4:20 |

If the terminal fails too, read the validator line from `7_validator_en.txt`.
