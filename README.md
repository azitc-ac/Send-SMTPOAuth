# Send-SmtpOAuth.ps1

Versendet E-Mails über **Microsoft 365 / Exchange Online** per echtem SMTP
(`smtp.office365.com:587`, STARTTLS) mit **OAuth2 / SASL XOAUTH2**.

Ein Skript, drei OAuth2-Flows:

| Flow | Einsatz | Login |
|------|---------|-------|
| `ClientCredentials` | App-only, unbeaufsichtigt – Automatisierung / Scheduled Tasks / Monitoring | kein interaktiver Login |
| `AuthorizationCode` | Persönliches Postfach, Browser auf diesem Rechner (PKCE) | einmalig interaktiv, danach Refresh-Token-Cache |
| `DeviceCode`        | Login an separatem Gerät/Browser per Code (z. B. Drucker/MFP) | einmalig interaktiv, danach Refresh-Token-Cache |

> .NET `SmtpClient` kann kein XOAUTH2 – das Skript spricht SMTP roh über `TcpClient` + `SslStream`
> (EHLO → STARTTLS → EHLO → `AUTH XOAUTH2` → MAIL/RCPT/DATA). Läuft unter **Windows PowerShell 5.1**
> (inkl. ISE) und PowerShell 7.

---

## Schnellstart

```powershell
# App-only – unbeaufsichtigt (Automatisierung / Scheduled Task / Monitoring)
.\Send-SmtpOAuth.ps1 -Flow ClientCredentials -TenantId contoso.onmicrosoft.com `
    -ClientId <appid> -ClientSecret '<secret>' -From alerts@contoso.com `
    -To admin@contoso.com -Subject 'Alert' -Body 'Hallo aus der Automatisierung'

# Interaktiver Login (Browser hier)
.\Send-SmtpOAuth.ps1 -Flow AuthorizationCode -TenantId organizations `
    -ClientId <appid> -From me@contoso.com -To you@contoso.com -Subject 'Hi' -Body 'Test'

# Device-Code (Login woanders; Code wird ins Clipboard kopiert + Browser geöffnet)
.\Send-SmtpOAuth.ps1 -Flow DeviceCode -TenantId organizations `
    -ClientId <appid> -From me@contoso.com -To you@contoso.com -Subject 'Hi' -Body 'Test'

# Shared Mailbox: anmelden als lizenzierter Benutzer, senden als Shared Mailbox
.\Send-SmtpOAuth.ps1 -Flow AuthorizationCode -TenantId organizations -ClientId <appid> `
    -AuthUser me@contoso.com -From info@contoso.com `
    -To you@contoso.com -Subject 'Hi' -Body 'Test'
```

---

## Welchen Flow wählen? – Vor- & Nachteile

**Faustregel:** Kein Mensch im Spiel → **ClientCredentials**. Mensch + Browser am selben Gerät →
**AuthorizationCode**. Mensch, aber Gerät ohne brauchbaren Browser (Drucker/MFP, IoT, headless) →
**DeviceCode**.

| Flow | Typischer Einsatz | Vorteile | Nachteile |
|------|-------------------|----------|-----------|
| **ClientCredentials** (app-only) | Unbeaufsichtigte Automatisierung: Scheduled Tasks, Monitoring/Alerting, Server-/Daemon-Dienste | Kein Benutzer nötig; unterliegt **keiner** Benutzer-CA/MFA; überlebt Passwort-Änderungen & Session-Revokes; erneuert sich rein über Secret/Zertifikat → **robustester Dauerläufer** | Aufwändigster Setup (Exchange-Service-Principal + `FullAccess`); Secret/Zertifikat muss rotiert werden; sendet „als App", nicht als Person |
| **AuthorizationCode** (PKCE) | Interaktives Tool auf einem Rechner **mit** Browser; persönliches oder Shared-Postfach | Einfacher Setup (nur App-Reg.); sendet **als der Benutzer** (Mail in „Gesendete Elemente"); per Refresh-Token **ebenfalls Dauerläufer** ohne erneuten Login | Einmaliger Browser-Login nötig; Refresh-Token an Benutzer-Lebenszyklus gebunden (s. u.) |
| **DeviceCode** | Geräte **ohne** brauchbaren Browser/Tastatur: Drucker/MFP (Kyocera!), IoT, headless Server, Remote-CLI | Login auf separatem Gerät per Code; keine Redirect-URI nötig; per Refresh-Token Dauerläufer | Setzt **„Allow public client flows = Yes"** voraus; Login interaktiv (einmalig); Refresh-Token an Benutzer gebunden |

### Dauerläufer ohne erneuten Login

Beide delegierten Flows (AuthorizationCode/DeviceCode) werden mit `offline_access` zu **unbeaufsichtigten
Dauerläufern** – genau wie viele SaaS-„Postfach einmal verbinden"-Dienste (und wie ein Kyocera-Drucker):

- Entra liefert ein **Refresh-Token** mit **gleitendem Fenster + Rotation**: Jeder Refresh erzeugt ein
  neues Access- **und** Refresh-Token. Solange es regelmäßig genutzt wird, verschiebt sich der Ablauf
  immer weiter → **effektiv unbegrenzt**. Erst **90 Tage komplette Inaktivität** lassen es verfallen.
- Dieses Skript cacht das Refresh-Token (DPAPI) und rotiert es bei jedem Lauf automatisch. Der
  interaktive Login ist also wirklich nur **einmalig**; per Scheduled Task läuft es dann unbeaufsichtigt.

**Aber:** Ein Refresh-Token ist an die **Benutzer-Identität** gebunden und wird **ungültig** bei
Passwort-Änderung/-Reset, Session-Revoke (`Revoke-MgUserSignInSession` / „Sign out everywhere"),
bestimmten Conditional-Access-/Risk-Events, MFA-Änderungen, deaktiviertem Konto oder >90 Tagen ohne
Nutzung. Dann ist **einmal** ein neuer interaktiver Login fällig.

→ **Für „als Benutzer X, läuft lange"**: AuthorizationCode/DeviceCode + Refresh-Token.
**Für „reiner Dienst, maximal wartungsarm"**: ClientCredentials (nicht an einen Benutzer gebunden).
Beide laufen dauerhaft unbeaufsichtigt – sie unterscheiden sich nur darin, *was* das Token am Leben
hält: Benutzer-Session vs. App-Credential.

---

## Voraussetzungen einrichten

Es gibt **drei** Bausteine. Welche du brauchst, hängt vom Flow ab:

1. **Entra-App-Registrierung** (immer) — Konfiguration je nach Flow unterschiedlich.
2. **SMTP AUTH in Exchange Online aktivieren** (immer) — sonst `535`, egal wie gut das Token ist.
3. **Exchange-Service-Principal + Postfachrecht** (nur ClientCredentials).

### 1a. App-Registrierung anlegen (für alle Flows)

[Entra Admin Center](https://entra.microsoft.com) → **App registrations** → **New registration** →
Namen vergeben → erstellen. Auf der **Overview**-Seite notieren:
- **Application (client) ID** → `-ClientId`
- **Directory (tenant) ID** → `-TenantId` (alternativ die Domain, oder `organizations`/`common`)

### 1b. App für die delegierten Flows (AuthorizationCode / DeviceCode)

1. **Authentication** → **Add a platform** → **Mobile and desktop applications**.
   - Für **AuthorizationCode**: Redirect-URI **`http://localhost`** eintragen (Loopback, Port egal).
   - Für **DeviceCode** ist keine Redirect-URI nötig.
2. **Authentication** → ganz unten **Advanced settings** → **Allow public client flows** = **Yes**.
   ⚠️ **Pflicht für DeviceCode** — sonst `AADSTS7000218`. (AuthorizationCode läuft dank Redirect-URI +
   PKCE auch ohne diesen Schalter, DeviceCode hat keine Redirect-URI und braucht ihn zwingend.)
3. **API permissions** → **Add a permission** → **APIs my organization uses** → *Office 365 Exchange Online*
   → **Delegated permissions** → **`SMTP.Send`** hinzufügen. `offline_access` fordert das Skript
   automatisch mit an (für das Refresh-Token).
4. Bei „Accounts in this organizational directory only": Admin-Consent auf der Permissions-Seite erteilen.

### 1c. App für ClientCredentials (App-only) — der aufwändigste Teil

1. **Certificates & secrets** → **New client secret** → den **Value** sofort kopieren → `-ClientSecret`.
   (Zertifikat geht auch, das Skript nutzt aktuell ein Secret.)
2. **API permissions** → **Add a permission** → **APIs my organization uses** → *Office 365 Exchange Online*
   → **Application permissions** → **`SMTP.SendAsApp`** → hinzufügen.
3. **Admin-Consent** für die App erteilen (Permissions-Seite → „Grant admin consent").
4. **Exchange-Service-Principal registrieren** (siehe Punkt 3 unten) — das ist zusätzlich nötig und
   wird gerne vergessen.

### 2. SMTP AUTH in Exchange Online aktivieren (für ALLE Flows)

SMTP AUTH ist standardmäßig oft deaktiviert — auch für OAuth. Ohne Aktivierung: `535`.

```powershell
Connect-ExchangeOnline
# Org-weit (False = erlaubt):
Get-TransportConfig | Format-List SmtpClientAuthenticationDisabled
# Falls True, org-weit erlauben ODER besser nur pro Postfach (überschreibt org-Default):
Set-CASMailbox -Identity user@contoso.com -SmtpClientAuthenticationDisabled $false
# Kontrolle (sollte False zeigen):
Get-CASMailbox -Identity user@contoso.com | Format-List SmtpClientAuthenticationDisabled
```
- Ein **leerer** Postfach-Wert = „erbt den org-Default". Effektiv aktiv ist SMTP AUTH nur, wenn
  weder org-weit noch am Postfach `True` steht.
- Alternativ im Admin Center: **Benutzer → Postfach → E-Mail → E-Mail-Apps verwalten → Authentifiziertes SMTP**.
- Änderungen brauchen **bis zu ~1 Stunde** (manchmal länger) bis sie greifen.
- **Wichtig:** SMTP AUTH wird von einer Conditional-Access-„Block legacy authentication"-Policy
  **nicht** blockiert, solange OAuth genutzt wird (OAuth-SMTP = *modern auth*). Eine CA-Grant-Policy
  (require MFA / compliant device) kann delegierte Flows aber treffen — app-only (ClientCredentials)
  unterliegt keiner Benutzer-CA.

### 3. Exchange-Service-Principal + Postfachrecht (nur ClientCredentials)

Nach dem Admin-Consent muss die App in Exchange als Service-Principal registriert und ihr der Zugriff
auf das/die Postfach/Postfächer erteilt werden ([MS-Doku](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth)):

```powershell
Connect-ExchangeOnline -Organization <tenantId>

# OBJECT_ID = Object ID aus ENTERPRISE APPLICATIONS (Overview), NICHT aus App registrations!
# (Entra → Enterprise applications → deine App → Object ID)
New-ServicePrincipal -AppId <APPLICATION_ID> -ObjectId <ENTERPRISE_APP_OBJECT_ID> `
    -DisplayName "EXO SP fuer <AppName>"

# Service-Principal-Identität holen:
$sp = Get-ServicePrincipal -Identity "EXO SP fuer <AppName>"

# Postfach-Zugriff geben (pro Postfach, das die App nutzen darf):
Add-MailboxPermission -Identity "alerts@contoso.com" -User $sp.Identity -AccessRights FullAccess
```

> ⚠️ **Häufigster Fehler:** als `OBJECT_ID` die Object ID der **App-Registrierung** zu nehmen.
> Es muss die Object ID der **Enterprise Application** (= Service Principal) sein — sonst
> Authentifizierungsfehler.

**Senden als Shared Mailbox (From ≠ das Postfach mit FullAccess):** zusätzlich SendAs erteilen:
```powershell
Add-RecipientPermission -Identity "info@contoso.com" -Trustee $sp.Identity -AccessRights SendAs
```

---

## Shared Mailbox

Bei einer Shared Mailbox unterscheidet sich Anmelde-Identität bewusst vom Absender:

| | Parameter | Bedeutung |
|---|-----------|-----------|
| **Anmelden als** | `-AuthUser` | lizenzierter Benutzer mit SendAs-Recht (XOAUTH2-`user=`, muss zum Token-`upn` passen) |
| **Senden als** | `-From` | Shared-Mailbox-Adresse (MAIL FROM / `From:`-Header) |

- **Delegiert (AuthorizationCode/DeviceCode):** `-AuthUser` = der Benutzer; er braucht **SendAs** auf
  die Shared Mailbox: `Add-RecipientPermission -Identity info@contoso.com -Trustee me@contoso.com -AccessRights SendAs`.
  Sein Postfach muss SMTP AUTH aktiviert haben.
- **App-only (ClientCredentials):** `-AuthUser` ist hier **bedeutungslos** und wird ignoriert — das
  XOAUTH2-`user=` ist immer `-From`. Die App braucht FullAccess (bzw. SendAs) auf die Shared Mailbox
  (siehe Schritt 3).
- Ohne `-AuthUser` sind Anmeldung und Absender identisch (Normalfall persönliches Postfach).

---

## Parameter & Schalter

| Parameter | Beschreibung |
|-----------|--------------|
| `-Flow` | `ClientCredentials` \| `AuthorizationCode` \| `DeviceCode` |
| `-TenantId` | Tenant-GUID, Domain, `organizations` oder `common` |
| `-ClientId` | Application (Client) ID der App-Registrierung |
| `-ClientSecret` | Nur ClientCredentials (SecureString oder Klartext) |
| `-From` | Absender (MAIL FROM / `From:`-Header) |
| `-AuthUser` | Shared Mailbox: anmeldender Benutzer (nur delegierte Flows) |
| `-To`, `-Cc` | Empfänger |
| `-Subject`, `-Body` | Inhalt; `-BodyAsHtml` für HTML |
| `-ForceLogin` | Delegiert: frischer Login + erzwungene Kontoauswahl (Cache ignorieren) |
| `-NoBrowser` | DeviceCode: Code **nicht** ins Clipboard + Browser **nicht** öffnen |
| `-SmtpServer`, `-Port` | Standard `smtp.office365.com:587` |
| `-RedirectPort` | Loopback-Port für AuthorizationCode (Standard 8400) |
| `-TokenCachePath` | Eigener Pfad fürs Refresh-Token-Cache |
| `-Verbose` | Zeigt SMTP-Dialog + Token-Claims (Token selbst wird nie geloggt) |

---

## Troubleshooting

| Symptom | Ursache & Lösung |
|---------|------------------|
| `535 5.7.139 ... SmtpClientAuthentication is disabled` | SMTP AUTH org-/postfachseitig aktivieren (Schritt 2). |
| `535 5.7.3 Authentication unsuccessful` | Token an sich gültig, aber abgelehnt: SMTP AUTH noch nicht propagiert, **oder** `user=` passt nicht zum Token (`-AuthUser`/`-From` prüfen, mit `-Verbose` die `Token upn`-Zeile ansehen). |
| `AADSTS7000218 ... client_assertion or client_secret` | App ist nicht als Public Client freigeschaltet → **Allow public client flows = Yes** (Schritt 1b). Tritt v. a. bei DeviceCode auf. |
| `AADSTS50011 redirect_uri mismatch` | `http://localhost` als Redirect-URI nachtragen (Schritt 1b). |
| `AADSTS65001 / invalid_grant (consent)` | Admin-Consent fehlt für `SMTP.Send`/`SMTP.SendAsApp`. |
| `Token scp` leer + app-only `roles` zeigt `SMTP.SendAsApp` | Korrekt — app-only nutzt App-Rollen statt Scopes. |
| Browser zeigt `ERR_CONNECTION_REFUSED`, Versand klappt trotzdem | Harmlos; der Code wurde bereits erfasst. |

---

## Hinweise

- **Refresh-Token-Cache:** Delegierte Flows cachen das Refresh-Token DPAPI-verschlüsselt unter
  `%LOCALAPPDATA%\SmtpOAuth\token.<ClientId>.<AuthUser>.xml` (pro Benutzer; nur derselbe
  Benutzer/Rechner kann es lesen). Weitere Sendungen kommen ohne erneuten Login aus; beim Wechsel
  des Postfachs wird nie das Token eines anderen Kontos wiederverwendet. Cache leeren = Datei löschen
  oder `-ForceLogin`.
- **Scopes:** Delegiert `https://outlook.office365.com/SMTP.Send offline_access`, app-only
  `https://outlook.office365.com/.default`.
- Microsoft schaltet Basic-SMTP-Auth ab (Stichtag 2026) — **OAuth/XOAUTH2 ist der unterstützte Weg**.
- Mit `-Verbose` lässt sich der komplette SMTP-Dialog mitlesen; das Access-Token wird dabei nie geloggt
  (nur die unkritischen Claims `aud`/`scp`/`upn`/`roles`).

## Lizenz
[MIT](LICENSE)
