#Requires -Version 5.1
<#
.SYNOPSIS
    Versendet E-Mails ueber Microsoft 365 / Exchange Online per echtem SMTP (smtp.office365.com:587,
    STARTTLS) mit OAuth2-Authentifizierung (SASL XOAUTH2).

    Unterstuetzt drei OAuth2-Flows:
      - ClientCredentials : App-only, unbeaufsichtigt (Automatisierung / Scheduled Tasks / Monitoring)
      - AuthorizationCode : Interaktiver Benutzer-Login per lokalem Loopback-Listener (+ PKCE)
      - DeviceCode        : Login an separatem Geraet/Browser per Code

    Delegierte Flows (AuthorizationCode/DeviceCode) cachen das Refresh-Token, sodass weitere
    Sendungen ohne erneuten Login auskommen, solange das Refresh-Token gueltig ist.

.DESCRIPTION
    .NET System.Net.Mail.SmtpClient kann KEIN XOAUTH2. Daher implementiert dieses Skript einen
    schlanken rohen SMTP-Client ueber TcpClient + SslStream (EHLO -> STARTTLS -> EHLO ->
    AUTH XOAUTH2 -> MAIL FROM / RCPT TO / DATA).

    Voraussetzungen in Entra ID (Azure AD):
      ClientCredentials:
        - App-Registrierung mit Client-Secret (oder Zertifikat, hier Secret)
        - Application-Berechtigung "SMTP.SendAsApp" (Office 365 Exchange Online) + Admin-Consent
        - In Exchange Online: Service Principal registrieren und Mailbox-Berechtigung erteilen
          (siehe MS-Doku "Authenticate an IMAP, POP or SMTP connection using OAuth")
        - SMTP AUTH fuer das Postfach aktiviert
      AuthorizationCode / DeviceCode:
        - App-Registrierung als "Public client" (Mobile and desktop applications)
        - Delegierte Berechtigung "SMTP.Send" + offline_access
        - Bei AuthorizationCode: Redirect-URI "http://localhost" als Loopback erlaubt

.PARAMETER Flow
    ClientCredentials | AuthorizationCode | DeviceCode

.PARAMETER TenantId
    Entra-ID Tenant-GUID oder Domain (z.B. contoso.onmicrosoft.com). Fuer DeviceCode/AuthCode
    kann auch "organizations" oder "common" verwendet werden.

.PARAMETER ClientId
    Application (Client) ID der App-Registrierung.

.PARAMETER ClientSecret
    Client-Secret (nur fuer ClientCredentials erforderlich). Als SecureString oder Klartext.

.PARAMETER From
    Absenderadresse. Bei ClientCredentials das Postfach, fuer das die App SendAs-Recht hat.

.PARAMETER To
    Eine oder mehrere Empfaengeradressen.

.PARAMETER Cc
    Optionale CC-Empfaenger.

.PARAMETER Subject
    Betreff.

.PARAMETER Body
    Nachrichtentext.

.PARAMETER BodyAsHtml
    Body als text/html senden statt text/plain.

.PARAMETER SmtpServer
    Standard: smtp.office365.com

.PARAMETER Port
    Standard: 587 (STARTTLS)

.PARAMETER RedirectPort
    Lokaler Loopback-Port fuer den AuthorizationCode-Flow. Standard: 8400.

.PARAMETER TokenCachePath
    Pfad fuer das Refresh-Token-Cache (delegierte Flows). Standard: %LOCALAPPDATA%\SmtpOAuth\token.<ClientId>.xml
    Das Token wird mit DPAPI (Benutzer-/Maschinen-scoped) verschluesselt abgelegt.

.PARAMETER ForceLogin
    Erzwingt bei delegierten Flows einen neuen Login und ignoriert das Cache.

.EXAMPLE
    # App-only (unbeaufsichtigte Automatisierung)
    .\Send-SmtpOAuth.ps1 -Flow ClientCredentials -TenantId contoso.onmicrosoft.com `
        -ClientId 1111... -ClientSecret 'sec...' -From alerts@contoso.com `
        -To admin@contoso.com -Subject 'Test' -Body 'Hallo aus der Automatisierung'

.EXAMPLE
    # Interaktiver Login (Browser auf diesem Rechner)
    .\Send-SmtpOAuth.ps1 -Flow AuthorizationCode -TenantId organizations `
        -ClientId 1111... -From me@contoso.com -To you@contoso.com -Subject 'Hi' -Body 'Test'

.EXAMPLE
    # Device-Code (Login an anderem Geraet)
    .\Send-SmtpOAuth.ps1 -Flow DeviceCode -TenantId organizations `
        -ClientId 1111... -From me@contoso.com -To you@contoso.com -Subject 'Hi' -Body 'Test'

.NOTES
    Microsoft deaktiviert Basic-SMTP-Auth fortlaufend; OAuth2/XOAUTH2 ist der unterstuetzte Weg.
    SMTP AUTH muss organisations- und postfachseitig aktiviert sein.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('ClientCredentials', 'AuthorizationCode', 'DeviceCode')]
    [string]$Flow,

    [Parameter(Mandatory)]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [string]$ClientId,

    [object]$ClientSecret,

    [Parameter(Mandatory)]
    [string]$From,

    [Parameter(Mandatory)]
    [string[]]$To,

    [string[]]$Cc,

    [Parameter(Mandatory)]
    [string]$Subject,

    [string]$Body = '',

    [switch]$BodyAsHtml,

    [string]$SmtpServer = 'smtp.office365.com',

    [int]$Port = 587,

    [int]$RedirectPort = 8400,

    [string]$TokenCachePath,

    [switch]$ForceLogin
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# TLS 1.2 erzwingen (aeltere Windows-PowerShell-Defaults sind teils TLS 1.0)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#region Hilfsfunktionen ------------------------------------------------------

function ConvertFrom-SecureToPlain {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Security.SecureString]) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
        try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
    return [string]$Value
}

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function New-PkcePair {
    # code_verifier: 43-128 Zeichen unreserved; code_challenge = base64url(sha256(verifier))
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $verifier = ConvertTo-Base64Url $bytes
    $sha = [Security.Cryptography.SHA256]::Create()
    $challenge = ConvertTo-Base64Url $sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier))
    [pscustomobject]@{ Verifier = $verifier; Challenge = $challenge }
}

function Get-DefaultTokenCachePath {
    param([string]$ClientId)
    $dir = Join-Path $env:LOCALAPPDATA 'SmtpOAuth'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Join-Path $dir ("token.{0}.xml" -f $ClientId)
}

function Save-RefreshToken {
    param([string]$Path, [string]$RefreshToken)
    if ([string]::IsNullOrEmpty($RefreshToken)) { return }
    # DPAPI (CurrentUser) -> nur derselbe Benutzer auf demselben Rechner kann entschluesseln
    $secure = ConvertTo-SecureString $RefreshToken -AsPlainText -Force
    $secure | ConvertFrom-SecureString | Set-Content -Path $Path -Encoding UTF8
    Write-Verbose "Refresh-Token gecached: $Path"
}

function Read-RefreshToken {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    try {
        $enc = Get-Content -Path $Path -Raw -Encoding UTF8
        $secure = ConvertTo-SecureString $enc
        return ConvertFrom-SecureToPlain $secure
    } catch {
        Write-Warning "Cache konnte nicht gelesen werden ($($_.Exception.Message)) - neuer Login noetig."
        return $null
    }
}

function Get-WebErrorDetail {
    # Liest den HTTP-Antwort-Body eines fehlgeschlagenen Invoke-RestMethod/-WebRequest aus.
    # Funktioniert in Windows PowerShell 5.1 UND PowerShell 7:
    #   - 5.1: WebException -> .Response.GetResponseStream()
    #   - 7  : HttpResponseException -> Body liegt in $_.ErrorDetails.Message
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    # 1) ErrorDetails.Message enthaelt in beiden Versionen meist direkt den Response-Body
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        return $ErrorRecord.ErrorDetails.Message
    }
    # 2) Fallback: Stream der WebException (5.1)
    $ex = $ErrorRecord.Exception
    if ($ex.PSObject.Properties.Name -contains 'Response' -and $ex.Response) {
        try {
            $stream = $ex.Response.GetResponseStream()
            if ($stream) {
                $reader = New-Object IO.StreamReader($stream)
                $body = $reader.ReadToEnd()
                if ($body) { return $body }
            }
        } catch { }
    }
    # 3) Letzter Fallback: Exception-Text
    return $ex.Message
}

function Invoke-TokenEndpoint {
    param([string]$TokenUrl, [hashtable]$Form)
    try {
        return Invoke-RestMethod -Method Post -Uri $TokenUrl -Body $Form -ContentType 'application/x-www-form-urlencoded'
    } catch {
        throw "Token-Endpoint-Fehler: $(Get-WebErrorDetail $_)"
    }
}

#endregion

#region OAuth2-Flows ---------------------------------------------------------

# Resource/Scope fuer Exchange Online SMTP
$SmtpScopeDelegated = 'https://outlook.office365.com/SMTP.Send offline_access'
$SmtpScopeAppOnly   = 'https://outlook.office365.com/.default'

$Authority = "https://login.microsoftonline.com/$TenantId"
$TokenUrl  = "$Authority/oauth2/v2.0/token"

function Get-AccessToken-ClientCredentials {
    $secret = ConvertFrom-SecureToPlain $ClientSecret
    if ([string]::IsNullOrEmpty($secret)) {
        throw "ClientCredentials benoetigt -ClientSecret."
    }
    $form = @{
        client_id     = $ClientId
        client_secret = $secret
        scope         = $SmtpScopeAppOnly
        grant_type    = 'client_credentials'
    }
    $resp = Invoke-TokenEndpoint -TokenUrl $TokenUrl -Form $form
    return $resp.access_token
}

function Get-AccessToken-FromRefresh {
    param([string]$RefreshToken)
    $form = @{
        client_id     = $ClientId
        scope         = $SmtpScopeDelegated
        grant_type    = 'refresh_token'
        refresh_token = $RefreshToken
    }
    $secret = ConvertFrom-SecureToPlain $ClientSecret
    if (-not [string]::IsNullOrEmpty($secret)) { $form.client_secret = $secret }
    Invoke-TokenEndpoint -TokenUrl $TokenUrl -Form $form
}

function Get-AccessToken-DeviceCode {
    $dcUrl = "$Authority/oauth2/v2.0/devicecode"
    $resp = Invoke-RestMethod -Method Post -Uri $dcUrl -Body @{
        client_id = $ClientId
        scope     = $SmtpScopeDelegated
    } -ContentType 'application/x-www-form-urlencoded'

    Write-Host ""
    Write-Host $resp.message -ForegroundColor Yellow
    Write-Host ""

    $interval = [int]$resp.interval
    if ($interval -lt 1) { $interval = 5 }
    $deadline = (Get-Date).AddSeconds([int]$resp.expires_in)

    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $interval
        try {
            $tok = Invoke-RestMethod -Method Post -Uri $TokenUrl -Body @{
                grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                client_id   = $ClientId
                device_code = $resp.device_code
            } -ContentType 'application/x-www-form-urlencoded'
            return $tok
        } catch {
            $err = $null
            try { $err = (Get-WebErrorDetail $_ | ConvertFrom-Json).error } catch { }
            switch ($err) {
                'authorization_pending' { }                              # weiter warten
                'slow_down'             { $interval += 5 }
                'expired_token'         { throw "Device-Code abgelaufen - bitte erneut starten." }
                'authorization_declined'{ throw "Login wurde abgelehnt." }
                default                 { throw "Device-Code-Fehler: $($_.Exception.Message)" }
            }
        }
    }
    throw "Zeitueberschreitung beim Warten auf den Login."
}

function Get-AccessToken-AuthorizationCode {
    Add-Type -AssemblyName System.Web
    $pkce        = New-PkcePair
    $redirectUri = "http://localhost:$RedirectPort/"
    $state       = [Guid]::NewGuid().ToString('N')

    $authUrl = "$Authority/oauth2/v2.0/authorize?" + (@(
        "client_id=$ClientId"
        "response_type=code"
        "redirect_uri=$([Uri]::EscapeDataString($redirectUri))"
        "response_mode=query"
        "scope=$([Uri]::EscapeDataString($SmtpScopeDelegated))"
        "state=$state"
        "code_challenge=$($pkce.Challenge)"
        "code_challenge_method=S256"
    ) -join '&')

    # Lokalen Listener starten, BEVOR der Browser oeffnet
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($redirectUri)
    try {
        $listener.Start()
    } catch {
        throw "Loopback-Listener auf $redirectUri konnte nicht gestartet werden ($($_.Exception.Message)). " +
              "Anderen -RedirectPort waehlen oder Skript als Admin/mit netsh-Urlacl ausfuehren."
    }

    Write-Host "Browser wird geoeffnet fuer den Login..." -ForegroundColor Cyan
    Start-Process $authUrl

    try {
        $context  = $listener.GetContext()   # blockiert bis Redirect eintrifft
        $request  = $context.Request
        $code     = $request.QueryString['code']
        $retState = $request.QueryString['state']
        $oauthErr = $request.QueryString['error']

        # Browserseitige Rueckmeldung
        $html = if ($code) {
            "<html><body style='font-family:sans-serif'><h2>Login erfolgreich</h2>Dieses Fenster kann geschlossen werden.</body></html>"
        } else {
            "<html><body style='font-family:sans-serif'><h2>Login fehlgeschlagen</h2>$oauthErr</body></html>"
        }
        $buffer = [Text.Encoding]::UTF8.GetBytes($html)
        $context.Response.ContentLength64 = $buffer.Length
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
        $context.Response.OutputStream.Close()
    } finally {
        $listener.Stop()
        $listener.Close()
    }

    if ($oauthErr)              { throw "Authorization-Fehler: $oauthErr" }
    if ($retState -ne $state)   { throw "State stimmt nicht ueberein (moeglicher CSRF) - abgebrochen." }
    if (-not $code)             { throw "Kein Authorization-Code empfangen." }

    $form = @{
        client_id     = $ClientId
        scope         = $SmtpScopeDelegated
        grant_type    = 'authorization_code'
        code          = $code
        redirect_uri  = $redirectUri
        code_verifier = $pkce.Verifier
    }
    $secret = ConvertFrom-SecureToPlain $ClientSecret
    if (-not [string]::IsNullOrEmpty($secret)) { $form.client_secret = $secret }
    Invoke-TokenEndpoint -TokenUrl $TokenUrl -Form $form
}

function Get-AccessToken {
    if ($Flow -eq 'ClientCredentials') {
        Write-Host "Hole App-only Token (Client Credentials)..." -ForegroundColor Cyan
        return Get-AccessToken-ClientCredentials
    }

    # Delegierte Flows mit Refresh-Token-Cache
    if (-not $TokenCachePath) { $TokenCachePath = Get-DefaultTokenCachePath -ClientId $ClientId }

    if (-not $ForceLogin) {
        $cachedRt = Read-RefreshToken -Path $TokenCachePath
        if ($cachedRt) {
            try {
                Write-Host "Verwende gecachtes Refresh-Token..." -ForegroundColor Cyan
                $resp = Get-AccessToken-FromRefresh -RefreshToken $cachedRt
                if ($resp.PSObject.Properties.Name -contains 'refresh_token') {
                    Save-RefreshToken -Path $TokenCachePath -RefreshToken $resp.refresh_token
                }
                return $resp.access_token
            } catch {
                Write-Warning "Refresh fehlgeschlagen ($($_.Exception.Message)) - neuer Login."
            }
        }
    }

    $resp = if ($Flow -eq 'DeviceCode') { Get-AccessToken-DeviceCode } else { Get-AccessToken-AuthorizationCode }
    if ($resp.PSObject.Properties.Name -contains 'refresh_token') {
        Save-RefreshToken -Path $TokenCachePath -RefreshToken $resp.refresh_token
    }
    return $resp.access_token
}

#endregion

#region SMTP-Client (XOAUTH2) ------------------------------------------------

function New-Xoauth2Token {
    param([string]$User, [string]$AccessToken)
    # SASL XOAUTH2: "user=<user>^Aauth=Bearer <token>^A^A" (^A = 0x01), Base64
    $raw = "user=$User`x01auth=Bearer $AccessToken`x01`x01"
    [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($raw))
}

function Send-MailXoauth2 {
    param(
        [string]$Server, [int]$Port, [string]$User, [string]$AccessToken,
        [string]$From, [string[]]$To, [string[]]$Cc,
        [string]$Subject, [string]$Body, [bool]$Html
    )

    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.Connect($Server, $Port)
    $stream = $tcp.GetStream()
    $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::ASCII)
    $writer = New-Object IO.StreamWriter($stream, [Text.Encoding]::ASCII)
    $writer.NewLine = "`r`n"
    $writer.AutoFlush = $true

    function Read-Reply {
        param($Rdr)
        $lines = @()
        do {
            $line = $Rdr.ReadLine()
            if ($null -eq $line) { throw "Verbindung vom Server geschlossen." }
            $lines += $line
        } while ($line.Length -ge 4 -and $line[3] -eq '-')   # 'xyz-' = weitere Zeile folgt
        $code = [int]$line.Substring(0, 3)
        [pscustomobject]@{ Code = $code; Text = ($lines -join "`n") }
    }

    function Send-Cmd {
        param($Wtr, $Rdr, [string]$Cmd, [int[]]$Expect, [bool]$Secret = $false)
        if ($Cmd) {
            $Wtr.WriteLine($Cmd)
            Write-Verbose ("C: {0}" -f ($(if ($Secret) { '<redacted>' } else { $Cmd })))
        }
        $reply = Read-Reply -Rdr $Rdr
        Write-Verbose ("S: {0}" -f $reply.Text)
        if ($Expect -and ($reply.Code -notin $Expect)) {
            throw "SMTP unerwartete Antwort (erwartet $($Expect -join '/')): $($reply.Text)"
        }
        return $reply
    }

    try {
        Send-Cmd -Wtr $writer -Rdr $reader -Cmd $null              -Expect 220 | Out-Null   # Greeting
        Send-Cmd -Wtr $writer -Rdr $reader -Cmd "EHLO $($env:COMPUTERNAME)" -Expect 250 | Out-Null
        Send-Cmd -Wtr $writer -Rdr $reader -Cmd "STARTTLS"         -Expect 220 | Out-Null

        # TLS-Upgrade
        $ssl = New-Object System.Net.Security.SslStream($stream, $false)
        # SslProtocols (NICHT SecurityProtocolType) ist der korrekte Enum-Typ dieser Methode
        $ssl.AuthenticateAsClient($Server, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
        $reader = New-Object IO.StreamReader($ssl, [Text.Encoding]::ASCII)
        $writer = New-Object IO.StreamWriter($ssl, [Text.Encoding]::ASCII)
        $writer.NewLine = "`r`n"
        $writer.AutoFlush = $true

        Send-Cmd -Wtr $writer -Rdr $reader -Cmd "EHLO $($env:COMPUTERNAME)" -Expect 250 | Out-Null

        # XOAUTH2-Authentifizierung
        $xoauth = New-Xoauth2Token -User $User -AccessToken $AccessToken
        $auth = Send-Cmd -Wtr $writer -Rdr $reader -Cmd "AUTH XOAUTH2 $xoauth" -Expect @(235, 334) -Secret $true
        if ($auth.Code -eq 334) {
            # Server verlangt Fortsetzung -> Fehler-Challenge, mit Leerzeile beantworten um Detail zu sehen
            $err = Send-Cmd -Wtr $writer -Rdr $reader -Cmd "" -Expect @(235)
            if ($err.Code -ne 235) { throw "XOAUTH2 abgelehnt: $($err.Text)" }
        }

        # Umschlag
        Send-Cmd -Wtr $writer -Rdr $reader -Cmd "MAIL FROM:<$From>" -Expect 250 | Out-Null
        foreach ($rcpt in @($To + $Cc | Where-Object { $_ })) {
            Send-Cmd -Wtr $writer -Rdr $reader -Cmd "RCPT TO:<$rcpt>" -Expect @(250, 251) | Out-Null
        }
        Send-Cmd -Wtr $writer -Rdr $reader -Cmd "DATA" -Expect 354 | Out-Null

        # Nachricht (RFC5322)
        $date    = (Get-Date).ToUniversalTime().ToString('r')
        $msgId   = "<{0}@{1}>" -f ([Guid]::NewGuid().ToString('N')), $Server
        $ctype   = if ($Html) { 'text/html; charset=utf-8' } else { 'text/plain; charset=utf-8' }
        $headers = @(
            "From: $From"
            "To: $($To -join ', ')"
        )
        if ($Cc) { $headers += "Cc: $($Cc -join ', ')" }
        $headers += @(
            "Subject: $Subject"
            "Date: $date"
            "Message-ID: $msgId"
            "MIME-Version: 1.0"
            "Content-Type: $ctype"
            "Content-Transfer-Encoding: 8bit"
        )

        foreach ($h in $headers) { $writer.WriteLine($h) }
        $writer.WriteLine("")
        foreach ($line in ($Body -split "`r?`n")) {
            # Dot-Stuffing: Zeilen, die mit '.' beginnen, verdoppeln
            if ($line.StartsWith('.')) { $writer.WriteLine('.' + $line) }
            else                       { $writer.WriteLine($line) }
        }
        Send-Cmd -Wtr $writer -Rdr $reader -Cmd "." -Expect 250 | Out-Null
        try { Send-Cmd -Wtr $writer -Rdr $reader -Cmd "QUIT" -Expect 221 | Out-Null } catch { }
    } finally {
        $writer.Dispose(); $reader.Dispose()
        if ($ssl) { $ssl.Dispose() }
        $tcp.Close()
    }
}

#endregion

#region Hauptablauf ----------------------------------------------------------

$token = Get-AccessToken
if ([string]::IsNullOrEmpty($token)) { throw "Kein Access-Token erhalten." }
Write-Host "Access-Token erhalten." -ForegroundColor Green

Write-Host "Sende E-Mail ueber $SmtpServer`:$Port (XOAUTH2)..." -ForegroundColor Cyan
Send-MailXoauth2 -Server $SmtpServer -Port $Port -User $From -AccessToken $token `
    -From $From -To $To -Cc $Cc -Subject $Subject -Body $Body -Html:$BodyAsHtml.IsPresent

Write-Host "E-Mail erfolgreich versendet an: $($To -join ', ')" -ForegroundColor Green

#endregion
