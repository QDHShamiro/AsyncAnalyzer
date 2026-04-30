# AsyncAnalyzer

Minecraft Mod Forensics + Cheat Detection Suite

Scans your mods folder for cheat mods, suspicious strings, obfuscation, and system-level threats. Verifies mod hashes against Modrinth.

---

## Run (no install required)

Open PowerShell and paste:

```powershell
powershell -ExecutionPolicy Bypass -Command "iex (irm 'https://raw.githubusercontent.com/QDHShamiro/AsyncAnalyzer/main/AsyncAnalyzer.ps1')"
```

You will be prompted to enter your mods folder path, or press Enter to use the default `.minecraft\mods`.

---

## What it checks

- Mod hashes against Modrinth + known cheat database
- Suspicious strings and cheat signatures inside JARs
- Obfuscation patterns
- Windows services, scheduled tasks, firewall, Defender
- Running JVM agents and localhost listeners

---

## Flags explained

| Status | Meaning |
|---|---|
| ✓ Verified | Hash matched on Modrinth — legitimate mod |
| ? Unknown | Not found in any database |
| FLAGGED | Contains cheat/malware signatures |

---

## Requirements

- Windows 10 / 11
- PowerShell 5.1+
- Run as Administrator for full system checks

---

Made by [QDHShamiro](https://github.com/QDHShamiro) · discord.gg/asyncstudios
