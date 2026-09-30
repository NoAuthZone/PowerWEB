# SPDX-License-Identifier: MIT
Set-StrictMode -Version Latest

function Invoke-PowerWebCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Url,
        [ValidateRange(1,120)][int]$TimeoutSeconds = 15
    )
    $target = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$target) -or
        $target.Scheme -notin @('http','https') -or $target.UserInfo) {
        throw 'Please enter a complete HTTP/HTTPS URL without credentials.'
    }
    $rows = [Collections.Generic.List[object]]::new()
    function Add-Result([string]$Area,[string]$State,[string]$Detail) {
        $rows.Add([pscustomobject]@{ Bereich=$Area; Status=$State; Hinweis=$Detail })
    }
    $request = [Net.HttpWebRequest]::Create($target)
    $request.Method = 'GET'
    $request.AllowAutoRedirect = $false
    $request.Timeout = $TimeoutSeconds * 1000
    $request.ReadWriteTimeout = $TimeoutSeconds * 1000
    $request.MaximumResponseHeadersLength = 64
    $request.UserAgent = 'PowerWEB/1.0'
    $request.KeepAlive = $false
    $response = $null
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        try { $response = [Net.HttpWebResponse]$request.GetResponse() }
        catch [Net.WebException] {
            if ($null -ne $_.Exception.Response) { $response = [Net.HttpWebResponse]$_.Exception.Response }
            else { throw }
        }
        $watch.Stop()
        $code = [int]$response.StatusCode
        $state = if ($code -ge 400) { 'Review' } elseif ($code -ge 300) { 'Info' } else { 'OK' }
        Add-Result 'HTTP' $state ("Status {0}; response headers after {1} ms." -f $code,$watch.ElapsedMilliseconds)
        if ($code -ge 300 -and $code -lt 400) {
            Add-Result 'Redirect' 'Info' ('Target: {0}. Not followed automatically; the target can be tested separately.' -f $response.Headers['Location'])
        }
        if ($target.Scheme -eq 'https') {
            Add-Result 'Transport' 'OK' 'HTTPS connection established with the runtime default certificate check.'
            $rawCert = $request.ServicePoint.Certificate
            if ($null -ne $rawCert) {
                $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCert)
                try {
                    $days = [Math]::Floor(($cert.NotAfter.ToUniversalTime() - [DateTime]::UtcNow).TotalDays)
                    $certState = if ($days -lt 30) { 'Review' } else { 'OK' }
                    Add-Result 'Certificate' $certState ("{0}; valid until {1:u}; {2} days left. Issuer: {3}" -f $cert.Subject,$cert.NotAfter.ToUniversalTime(),$days,$cert.Issuer)
                } finally { $cert.Dispose() }
            } else { Add-Result 'Certificate' 'Info' 'Certificate details not available in this runtime.' }
        } else { Add-Result 'Transport' 'Review' 'Unencrypted HTTP connection.' }

        $headers = $response.Headers
        $csp = $headers['Content-Security-Policy']
        if ($csp) {
            Add-Result 'Content-Security-Policy' 'Info' 'Present. Effectiveness requires review in the application context.'
            if ($csp -match "'unsafe-inline'|'unsafe-eval'") {
                Add-Result 'CSP exceptions' 'Review' 'unsafe-inline or unsafe-eval present; consider nonces, hashes and browser rules in the assessment.'
            }
        } else { Add-Result 'Content-Security-Policy' 'Review' 'No enforcing CSP header. Relevant for HTML pages; meta policies are not examined.' }
        $nosniff = $headers['X-Content-Type-Options']
        if ($nosniff -and $nosniff.Trim() -ieq 'nosniff') { Add-Result 'MIME protection' 'OK' 'X-Content-Type-Options: nosniff' }
        else { Add-Result 'MIME protection' 'Review' 'X-Content-Type-Options: nosniff missing or a different value.' }
        $frame = $headers['X-Frame-Options']
        if (($frame -and $frame.Trim() -match '^(DENY|SAMEORIGIN)$') -or $csp -match '(?i)(^|;)\s*frame-ancestors\s+') {
            Add-Result 'Embedding protection' 'Info' 'X-Frame-Options or CSP frame-ancestors present; review allowed sources manually.'
        } else { Add-Result 'Embedding protection' 'Review' 'No detected protection against foreign frame embedding in the response headers.' }
        foreach ($name in @('Referrer-Policy','Permissions-Policy')) {
            if ($headers[$name]) { Add-Result $name 'Info' 'Header present; content not semantically validated.' }
            else { Add-Result $name 'Info' 'Header missing; need depends on the application.' }
        }
        if ($target.Scheme -eq 'https') {
            $hsts = $headers['Strict-Transport-Security']
            if ($hsts -match '(?i)(^|;)\s*max-age\s*=\s*([0-9]+)\s*(;|$)' -and $Matches[2] -match '[1-9]') {
                Add-Result 'HSTS' 'OK' 'Strict-Transport-Security with a positive max-age present.'
            } else { Add-Result 'HSTS' 'Review' 'HSTS missing, invalid or max-age is 0.' }
        }
        $cookies = @($headers.GetValues('Set-Cookie') | Where-Object { $_ })
        if ($cookies.Count -eq 0) { Add-Result 'Cookies' 'Info' 'This response sets no cookies.' }
        foreach ($cookie in $cookies) {
            $parts = $cookie -split ';'
            $cookieName = ($parts[0] -split '=',2)[0].Trim()
            $attributes = @{}
            foreach ($part in ($parts | Select-Object -Skip 1)) {
                $pair = $part.Trim() -split '=',2
                $attributes[$pair[0].ToLowerInvariant()] = if ($pair.Count -gt 1) { $pair[1].Trim() } else { '' }
            }
            $issues = [Collections.Generic.List[string]]::new()
            if (-not $attributes.ContainsKey('secure')) { $issues.Add('Secure missing') }
            if (-not $attributes.ContainsKey('httponly')) { $issues.Add('HttpOnly missing (weigh for cookies intentionally used by JavaScript)') }
            if (-not $attributes.ContainsKey('samesite')) { $issues.Add('SameSite not set explicitly') }
            elseif ($attributes['samesite'] -notmatch '^(Lax|Strict|None)$') { $issues.Add('SameSite value invalid') }
            elseif ($attributes['samesite'] -ieq 'None' -and -not $attributes.ContainsKey('secure')) { $issues.Add('SameSite=None requires Secure') }
            if ($issues.Count) { Add-Result ("Cookie: {0}" -f $cookieName) 'Review' ($issues -join '; ') }
            else { Add-Result ("Cookie: {0}" -f $cookieName) 'OK' 'Secure, HttpOnly and a valid SameSite present.' }
        }
        # Cookie values, raw headers and response bodies are deliberately not retained.
        return [pscustomobject]@{
            Tool = 'PowerWEB'; Version = '1.0.0'; Url = $target.AbsoluteUri
            ZeitpunktUtc = [DateTime]::UtcNow.ToString('o'); HttpStatus = $code
            DauerMs = $watch.ElapsedMilliseconds; Ergebnisse = $rows.ToArray()
        }
    } finally {
        if ($null -ne $response) { $response.Close() }
        $request.Abort()
    }
}

function Export-PowerWebReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Report,[Parameter(Mandatory)][string]$Path,
          [ValidateSet('HTML','JSON')][string]$Format = 'HTML')
    if ($Format -eq 'JSON') { $content = $Report | ConvertTo-Json -Depth 8 }
    else {
        function Encode([object]$Value) { [Net.WebUtility]::HtmlEncode([string]$Value) }
        $lines = foreach ($row in $Report.Ergebnisse) {
            '<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (Encode $row.Bereich),(Encode $row.Status),(Encode $row.Hinweis)
        }
        $content = @"
<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>PowerWEB report</title><style>body{font:16px system-ui;margin:40px auto;max-width:1100px;padding:0 20px;color:#172337;background:#f4f7fb}table{border-collapse:collapse;width:100%;background:white}th,td{text-align:left;padding:14px;border-bottom:1px solid #ddd;vertical-align:top;overflow-wrap:anywhere}h1{color:#125ca5}small{color:#526174}</style>
<h1>PowerWEB</h1><p>$(Encode $Report.Url)</p><p>UTC: $(Encode $Report.ZeitpunktUtc) | HTTP: $(Encode $Report.HttpStatus) | $(Encode $Report.DauerMs) ms</p>
<table><thead><tr><th>Area</th><th>Status</th><th>Detail</th></tr></thead><tbody>$($lines -join "`n")</tbody></table>
<p><small>Snapshot of a single response. Hints are not confirmed vulnerabilities. Not a complete security assessment.</small></p></html>
"@
    }
    [IO.File]::WriteAllText($Path,$content,[Text.UTF8Encoding]::new($false))
}

Export-ModuleMember -Function Invoke-PowerWebCheck,Export-PowerWebReport
