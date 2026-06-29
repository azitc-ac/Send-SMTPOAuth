# Send-SmtpOAuth.ps1

Versendet E-Mails über **Microsoft 365 / Exchange Online** per echtem SMTP
(`smtp.office365.com:587`, STARTTLS) mit **OAuth2 / SASL XOAUTH2**.

Ein Skript, drei Flows:

| Flow | Einsatz | Login |
|------|---------|-------|
| `ClientCredentials` | App-only, unbeaufsichtigt – Automatisierung / Scheduled Tasks / Monitoring | kein interaktiver Login |
| `AuthorizationCode` | Persönliches Postfach, Browser auf diesem Rechner | einmalig interaktiv, danach Refresh-Token-Cache |
| `DeviceCode`        | Login an separatem Gerät/Browser per Code | einmalig interaktiv, danach Refresh-Token-Cache |

> .NET `SmtpClient` kann kein XOAUTH2 – das Skript spricht SMTP roh über `TcpClient` + `SslStream`
> (EHLO → STARTTLS → EHLO → `AUTH XOAUTH2` → MAIL/RCPT/DATA).

## Entra-ID-Setup

### Gemeinsam
1. **App-Registrierung** in Entra ID anlegen, `Application (Client) ID` und `Tenant ID` notieren.

### ClientCredentials (App-only)
2. **Client-Secret** erzeugen (Certificates & secrets).
3. **API-Berechtigung** → APIs my organization uses → *Office 365 Exchange Online* →
   **Application permissions** → `SMTP.SendAsApp` → **Admin-Consent** erteilen.
4. In **Exchange Online** den Service Principal registrieren und dem Postfach SendAs-Recht geben
   (PowerShell `New-ServicePrincipal` / `Add-MailboxPermission`, siehe MS-Doku
   *„Authenticate an IMAP, POP or SMTP connection using OAuth"*).
5. **SMTP AUTH** für das Postfach aktiviert lassen (org- und postfachseitig).

### AuthorizationCode / DeviceCode (delegiert)
2. Unter **Authentication** die Plattform *Mobile and desktop applications* hinzufügen,
   bei AuthorizationCode Redirect-URI `http://localhost` eintragen und
   **„Allow public client flows"** = *Yes* setzen.
3. **API-Berechtigung** → *Office 365 Exchange Online* → **Delegated** → `SMTP.Send` (+ `offline_access`).

## Beispiele

```powershell
# App-only – unbeaufsichtigt (Automatisierung / Scheduled Task / Monitoring)
.\Send-SmtpOAuth.ps1 -Flow ClientCredentials -TenantId contoso.onmicrosoft.com `
    -ClientId <appid> -ClientSecret '<secret>' -From alerts@contoso.com `
    -To admin@contoso.com -Subject 'Alert' -Body 'Hallo aus der Automatisierung'

# Interaktiver Login (Browser hier)
.\Send-SmtpOAuth.ps1 -Flow AuthorizationCode -TenantId organizations `
    -ClientId <appid> -From me@contoso.com -To you@contoso.com -Subject 'Hi' -Body 'Test'

# Device-Code (Login woanders)
.\Send-SmtpOAuth.ps1 -Flow DeviceCode -TenantId organizations `
    -ClientId <appid> -From me@contoso.com -To you@contoso.com -Subject 'Hi' -Body 'Test'
```

Nützliche Schalter: `-BodyAsHtml`, `-Cc`, `-ForceLogin` (Cache ignorieren),
`-TokenCachePath`, `-RedirectPort`, `-Verbose` (zeigt den SMTP-Dialog).

## Hinweise
- Delegierte Flows cachen das **Refresh-Token** DPAPI-verschlüsselt unter
  `%LOCALAPPDATA%\SmtpOAuth\token.<ClientId>.xml` (nur derselbe Benutzer/Rechner kann es lesen).
  Weitere Sendungen kommen dann ohne erneuten Login aus.
- Microsoft deaktiviert Basic-SMTP-Auth laufend – XOAUTH2 ist der unterstützte Weg.
- Bei `535 5.7.139 ... SmtpClientAuthentication is disabled` muss SMTP AUTH org-/postfachseitig
  aktiviert werden.
- Mit `-Verbose` lässt sich der komplette SMTP-Dialog mitlesen (Token wird dabei nicht geloggt).
