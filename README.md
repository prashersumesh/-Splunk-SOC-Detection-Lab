# ============================================================
# Splunk SOC Detection Queries
# Author: Sumesh Kumar | May 2026
# Platform: Splunk Enterprise 10.2.3 + Sysmon v15.20
# ============================================================

# ------------------------------------------------------------
# D-001 — Brute Force Authentication
# MITRE: T1110
# Validated: runas /user:fakeuser cmd (6 attempts) — fired
# ------------------------------------------------------------
index=wineventlog EventCode=4625
| stats count by host, TargetUserName
| where count >= 3


# ------------------------------------------------------------
# D-002 — Encoded PowerShell (TUNED)
# MITRE: T1059.001 + T1027
# Validated: powershell.exe -enc <base64> — fired
# ------------------------------------------------------------
index=sysmon EventCode=1
Image="*powershell.exe"
CommandLine="*-enc *"
| table _time, host, User, CommandLine, ParentImage, Hashes


# ------------------------------------------------------------
# D-003 — Office Spawning Shell
# MITRE: T1566 + T1059
# Active rule (zero hits = clean lab)
# ------------------------------------------------------------
index=sysmon EventCode=1
(ParentImage="*winword.exe" OR ParentImage="*excel.exe" OR ParentImage="*outlook.exe")
(Image="*cmd.exe" OR Image="*powershell.exe" OR Image="*wscript.exe")
| table _time, ParentImage, Image, CommandLine, User


# ------------------------------------------------------------
# D-004 — Rare Process Hunt
# MITRE: T1218
# Validated: 20 results, all benign in lab
# ------------------------------------------------------------
index=sysmon EventCode=1
| stats count by Image
| sort count
| head 20


# ------------------------------------------------------------
# D-005 — Process Creation Triage (filtered baseline)
# MITRE: T1059
# ------------------------------------------------------------
index=sysmon EventCode=1
NOT Image="*splunk*"
NOT Image="*python3.13*"
| table _time, host, User, Image, CommandLine, ParentImage
| sort -_time


# ------------------------------------------------------------
# COMBINED MULTI-DETECTION RULE (TUNED)
# Eliminates WPS Office false positives via regex anchoring
# ------------------------------------------------------------
(index=wineventlog EventCode=4625) OR
(index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-enc *")
| eval Detection=case(
    EventCode==4625, "Brute Force (T1110)",
    match(CommandLine, "(?i)powershell.*\s-enc\s"), "Encoded PowerShell (T1059.001)"
  )
| eval User=coalesce(TargetUserName, User)
| where isnotnull(Detection)
| table _time, host, Detection, User, CommandLine
| sort -_time
| head 20


# ============================================================
# DASHBOARD PANEL QUERIES (24h windows)
# ============================================================

# Panel 1 — Brute Force Counter
index=wineventlog EventCode=4625 earliest=-24h | stats count

# Panel 2 — Encoded PowerShell Counter
index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-enc *" earliest=-24h
| stats count

# Panel 3 — Failed Login Timeline
index=wineventlog EventCode=4625 earliest=-24h
| timechart span=10m count by TargetUserName

# Panel 4 — Live Detection Feed (Combined Rule above)
