# SPDX-License-Identifier: MIT
# Independently written PowerWEB assessment engine. Original implementation.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-PWUri {
    param([Parameter(Mandatory)][string]$Url)
    $uri=$null
    if (-not [Uri]::TryCreate($Url,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -notin @('http','https') -or $uri.UserInfo) {
        throw 'An absolute HTTP/HTTPS URL without embedded credentials is required.'
    }
    $builder=[UriBuilder]::new($uri); $builder.Fragment=''
    return $builder.Uri
}

function Test-PWScope {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Url,[AllowEmptyString()][string]$ScopeUrl,[string[]]$Exclude=@())
    # Scope is optional. With no scope configured every reachable URL is allowed;
    # exclusions still apply, so a tester can carve out logout/delete without a
    # scope. A configured scope is enforced by scheme/host/port and optional path.
    if ([string]::IsNullOrWhiteSpace($ScopeUrl)) {
        try { $uri=ConvertTo-PWUri $Url } catch { return $false }
        if ($uri.AbsolutePath -match '(?i)%2f|%5c|%2e|%25') { return $false }
        $candidate=[Uri]::UnescapeDataString($uri.AbsolutePath + $uri.Query)
        foreach ($item in $Exclude) { if ($item -and $candidate.IndexOf($item,[StringComparison]::OrdinalIgnoreCase) -ge 0) { return $false } }
        return $true
    }
    try { $uri=ConvertTo-PWUri $Url; $scope=ConvertTo-PWUri $ScopeUrl } catch { return $false }
    if ($uri.Scheme -ne $scope.Scheme -or $uri.IdnHost -ne $scope.IdnHost -or $uri.Port -ne $scope.Port) { return $false }
    # Decode once for conservative path exclusions; encoded path separators/dots are rejected.
    if ($uri.AbsolutePath -match '(?i)%2f|%5c|%2e|%25') { return $false }
    $path=$scope.AbsolutePath.TrimEnd('/')
    if ($path -and -not ($uri.AbsolutePath.Equals($path,[StringComparison]::Ordinal) -or $uri.AbsolutePath.StartsWith($path+'/',[StringComparison]::Ordinal))) { return $false }
    $candidate=[Uri]::UnescapeDataString($uri.AbsolutePath + $uri.Query)
    foreach ($item in $Exclude) {
        if ($item -and $candidate.IndexOf($item,[StringComparison]::OrdinalIgnoreCase) -ge 0) { return $false }
    }
    return $true
}

function ConvertFrom-PWHeaderText {
    param([string]$Text='')
    $headers=@{}
    foreach ($line in ($Text -split '\r?\n')) {
        if (-not $line.Trim()) { continue }
        $pair=$line -split ':',2
        if ($pair.Count -ne 2 -or $pair[0] -notmatch '^[A-Za-z0-9!#$%&''*+.^_`|~-]+$') { throw "Invalid header line: $($pair[0])" }
        $name=$pair[0]
        if ($name -in @('Host','Content-Length','Transfer-Encoding','Connection','Proxy-Authorization','Expect','Range','Date','Upgrade')) { throw "Header $name is managed by the connection and cannot be set." }
        if ($headers.ContainsKey($name)) { throw "Duplicate header: $name" }
        $headers[$name]=$pair[1].Trim()
    }
    return $headers
}

function Invoke-PWHttp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Url,[AllowEmptyString()][string]$ScopeUrl='',
        [ValidateSet('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS')][string]$Method='GET',
        [hashtable]$Headers=@{},[string]$Body='', [string[]]$Exclude=@(),
        [ValidateRange(1,60)][int]$TimeoutSeconds=15,[ValidateRange(1024,2097152)][int]$MaxBytes=262144,
        [hashtable]$Control,[Net.CookieContainer]$CookieContainer
    )
    if (-not (Test-PWScope $Url $ScopeUrl $Exclude)) { throw 'URL is outside the defined scope or excluded.' }
    if ($Control -and $Control.Cancel) { throw 'Abgebrochen.' }
    $uri=ConvertTo-PWUri $Url
    $request=[Net.HttpWebRequest]::Create($uri)
    if ($null -ne $CookieContainer -and -not $Headers.ContainsKey('Cookie')) { $request.CookieContainer=$CookieContainer }
    $request.Method=$Method; $request.AllowAutoRedirect=$false
    $request.Timeout=$TimeoutSeconds*1000; $request.ReadWriteTimeout=$TimeoutSeconds*1000
    $request.MaximumResponseHeadersLength=64; $request.KeepAlive=$false
    $request.UserAgent='PowerWEB/4.0'; $request.AllowWriteStreamBuffering=$false
    $request.AutomaticDecompression=[Net.DecompressionMethods]::GZip -bor [Net.DecompressionMethods]::Deflate
    foreach ($key in $Headers.Keys) {
        if ([string]$Headers[$key] -match '[\r\n]') { throw 'Line breaks in header values are not allowed.' }
        switch ($key.ToLowerInvariant()) {
            'content-type' { $request.ContentType=$Headers[$key] }
            'accept' { $request.Accept=$Headers[$key] }
            'user-agent' { $request.UserAgent=$Headers[$key] }
            'referer' { $request.Referer=$Headers[$key] }
            default { $request.Headers[$key]=[string]$Headers[$key] }
        }
    }
    if ($Body -and $Method -in @('GET','HEAD')) { throw 'GET/HEAD are sent without a request body here.' }
    $response=$null; $bufferStream=$null
    $watch=[Diagnostics.Stopwatch]::StartNew()
    if ($Control) { $Control.Request=$request }
    try {
        if ($Control -and $Control.Cancel) { throw 'Abgebrochen.' }
        if ($Body -or $Method -in @('POST','PUT','PATCH')) {
            $bytes=[Text.Encoding]::UTF8.GetBytes($Body); $request.ContentLength=$bytes.Length
            if (-not $request.ContentType) { $request.ContentType='application/json; charset=utf-8' }
            $stream=$request.GetRequestStream()
            try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
        }
        try { $response=[Net.HttpWebResponse]$request.GetResponse() }
        catch [Net.WebException] {
            if ($null -eq $_.Exception.Response) { throw }
            $response=[Net.HttpWebResponse]$_.Exception.Response
        }
        $headerMs=$watch.ElapsedMilliseconds
        $responseHeaders=@{}
        foreach ($key in $response.Headers.AllKeys) { $responseHeaders[$key]=$response.Headers[$key] }
        $cookies=@($response.Headers.GetValues('Set-Cookie') | Where-Object { $_ })
        if ($null -ne $CookieContainer -and $Headers.ContainsKey('Cookie')) {
            foreach ($cookie in $cookies) { try { $CookieContainer.SetCookies($uri,$cookie) } catch {} }
        }
        $certificate=$null
        if ($uri.Scheme -eq 'https' -and $null -ne $request.ServicePoint.Certificate) {
            $cert=[Security.Cryptography.X509Certificates.X509Certificate2]::new($request.ServicePoint.Certificate)
            try { $certificate=[pscustomobject]@{ Subject=$cert.Subject; Issuer=$cert.Issuer; ExpiresUtc=$cert.NotAfter.ToUniversalTime().ToString('o'); DaysLeft=[Math]::Floor(($cert.NotAfter.ToUniversalTime()-[DateTime]::UtcNow).TotalDays) } }
            finally { $cert.Dispose() }
        }
        $bufferStream=[IO.MemoryStream]::new(); $bodyText=''; $truncated=$false
        $isText=$response.ContentType -match '(?i)text/|json|xml|javascript|x-www-form-urlencoded'
        if ($Method -ne 'HEAD' -and $isText) {
            $stream=$response.GetResponseStream(); $buffer=New-Object byte[] 8192
            while ($bufferStream.Length -le $MaxBytes) {
                if ($Control -and $Control.Cancel) { throw 'Abgebrochen.' }
                if ($watch.Elapsed.TotalSeconds -gt $TimeoutSeconds) { throw 'Time limit reached while reading the response.' }
                $read=$stream.Read($buffer,0,[Math]::Min($buffer.Length,$MaxBytes+1-[int]$bufferStream.Length))
                if ($read -eq 0) { break }
                $bufferStream.Write($buffer,0,$read)
            }
            $truncated=$bufferStream.Length -gt $MaxBytes
            $encoding=[Text.Encoding]::UTF8
            if ($response.ContentType -match '(?i)charset\s*=\s*["'']?([^;\s"'']+)') {
                try { $encoding=[Text.Encoding]::GetEncoding($Matches[1]) } catch { }
            }
            $bodyText=$encoding.GetString($bufferStream.ToArray(),0,[Math]::Min($MaxBytes,[int]$bufferStream.Length))
        }
        return [pscustomobject]@{ Url=$uri.AbsoluteUri; Method=$Method; Status=[int]$response.StatusCode; HeaderMs=$headerMs; Headers=$responseHeaders; Cookies=$cookies; Body=$bodyText; Truncated=$truncated; BodyRead=$isText; BytesRead=$bufferStream.Length; Certificate=$certificate }
    } finally {
        if ($bufferStream) { $bufferStream.Dispose() }
        if ($response) { $response.Close() }
        $request.Abort()
        if ($Control) { $Control.Request=$null }
    }
}

function New-PWFinding {
    param([string]$Title,[string]$Risk,[string]$Url,[string]$Evidence,[string]$Fix,[string]$Source='Passive')
    [pscustomobject]@{ Id=[Guid]::NewGuid().ToString('N').Substring(0,10); Risiko=$Risk; Titel=$Title; Url=$Url; Status='Open'; Quelle=$Source; Nachweis=$Evidence; Empfehlung=$Fix }
}

function Get-PWPassiveFindings {
    param([Parameter(Mandatory)]$Response)
    $h=$Response.Headers; $url=$Response.Url; $html=$h['Content-Type'] -match '(?i)text/html|application/xhtml'
    if (([Uri]$url).Scheme -eq 'http') { New-PWFinding 'Unencrypted transport' 'Medium' $url 'Response received over HTTP.' 'Serve over HTTPS and redirect HTTP in a controlled way.' }
    elseif (-not $h['Strict-Transport-Security'] -or $h['Strict-Transport-Security'] -notmatch '(?i)(^|;)\s*max-age\s*=\s*0*[1-9][0-9]*\s*(;|$)') {
        New-PWFinding 'HSTS missing or disabled' 'Low' $url 'No positive max-age value detected.' 'After a successful HTTPS rollout, set a suitable HSTS policy.'
    }
    if ($Response.Certificate -and $Response.Certificate.DaysLeft -lt 30) { New-PWFinding 'Certificate expires soon' 'Medium' $url ("Expiry: {0}" -f $Response.Certificate.ExpiresUtc) 'Renew the certificate in time and monitor automatic renewal.' }
    if ($h['X-Content-Type-Options'] -ne 'nosniff') { New-PWFinding 'MIME protection missing' 'Low' $url 'X-Content-Type-Options is not nosniff.' 'Set X-Content-Type-Options: nosniff and serve correct content types.' }
    if ($html) {
        if (-not $h['Content-Security-Policy']) { New-PWFinding 'CSP header missing' 'Low' $url 'No enforcing CSP header; meta policies not evaluated.' 'Develop and test a CSP that fits the frontend.' }
        elseif ($h['Content-Security-Policy'] -match "'unsafe-inline'|'unsafe-eval'") { New-PWFinding 'CSP with broad exceptions' 'Info' $url 'unsafe-inline or unsafe-eval detected; nonces/hashes may change the assessment.' 'Review the directives and their actual browser effect manually.' }
        if ($h['X-Frame-Options'] -notmatch '^(DENY|SAMEORIGIN)$' -and $h['Content-Security-Policy'] -notmatch '(?i)(^|;)\s*frame-ancestors\s+') { New-PWFinding 'Frame protection not detected' 'Low' $url 'Neither a valid X-Frame-Options nor frame-ancestors detected.' 'Restrict allowed embedding via CSP frame-ancestors.' }
        if (([Uri]$url).Scheme -eq 'https' -and $Response.Body -match '(?i)(src|action)\s*=\s*["'']http://') { New-PWFinding 'HTTP resource in HTTPS document' 'Medium' $url 'A src or action attribute references HTTP; HTML heuristic.' 'Move resources and form targets to HTTPS; confirm in the browser.' }
        if ($Response.Body -match '(?i)<input\b[^>]*type\s*=\s*["'']?password' -and ([Uri]$url).Scheme -eq 'http') { New-PWFinding 'Password field on HTTP page' 'High' $url 'Password input field detected in HTML served unencrypted.' 'Serve login pages over HTTPS only.' }
    }
    foreach ($cookie in $Response.Cookies) {
        $name=($cookie -split '=',2)[0]; $issues=[Collections.Generic.List[string]]::new()
        if ($cookie -notmatch '(?i);\s*Secure\s*(;|$)') { $issues.Add('Secure missing') }
        if ($cookie -notmatch '(?i);\s*HttpOnly\s*(;|$)') { $issues.Add('HttpOnly missing') }
        if ($cookie -notmatch '(?i);\s*SameSite\s*=\s*(Lax|Strict|None)\s*(;|$)') { $issues.Add('SameSite missing or invalid') }
        if ($cookie -match '(?i);\s*SameSite\s*=\s*None\s*(;|$)' -and $cookie -notmatch '(?i);\s*Secure\s*(;|$)') { $issues.Add('SameSite=None without Secure') }
        if ($issues.Count) { New-PWFinding 'Review cookie attributes' 'Low' $url ("Cookie {0}: {1}" -f $name,($issues -join ', ')) 'Set attributes per purpose; weigh HttpOnly where JavaScript access is required.' }
    }
    if ($Response.Body -match '(?i)SQL syntax.*MySQL|Unclosed quotation mark|ORA-\d{5}|Traceback \(most recent call last\)|System\.Data\.SqlClient\.SqlException') { New-PWFinding 'Technical error message in content' 'Low' $url 'Database or stack-trace pattern detected; no confirmed injection evidence.' 'Log errors internally and return neutral messages externally.' }
    if ($h['Access-Control-Allow-Origin'] -eq '*') { New-PWFinding 'CORS allows any origin' 'Info' $url 'Access-Control-Allow-Origin: *; intended for public resources.' 'Assess the resource sensitivity and browser behaviour.' }
    if ($Response.Truncated) { New-PWFinding 'Response only partially analysed' 'Info' $url 'Text response larger than the configured read limit.' 'Inspect the affected content manually in full.' }
}

function Get-PWLinks {
    param([Parameter(Mandatory)]$Response)
    $base=[Uri]$Response.Url
    # A bounded, non-executing HTML heuristic; no browser, scripts or form submission.
    if ($Response.Headers['Content-Type'] -match '(?i)text/html|application/xhtml') {
        $baseMatch=[regex]::Match($Response.Body,'(?is)<base\b[^>]*href\s*=\s*["'']([^"'']+)["'']')
        if ($baseMatch.Success) { try { $base=[Uri]::new($base,[Net.WebUtility]::HtmlDecode($baseMatch.Groups[1].Value)) } catch { } }
        $pattern='(?is)<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|''([^'']*)''|([^\s>]+))'
        # Avoid clobbering the automatic $Matches variable populated by -match.
        $linkMatches=[regex]::Matches($Response.Body,$pattern)
        $count=0
        foreach ($match in $linkMatches) {
            if (++$count -gt 1000) { break }
            $value=($match.Groups[1].Value+$match.Groups[2].Value+$match.Groups[3].Value)
            if (-not $value -or $value.StartsWith('#')) { continue }
            try { (ConvertTo-PWUri ([Uri]::new($base,[Net.WebUtility]::HtmlDecode($value)))).AbsoluteUri } catch { }
        }
    }
    if ($Response.Status -ge 300 -and $Response.Status -lt 400 -and $Response.Headers['Location']) {
        try { (ConvertTo-PWUri ([Uri]::new([Uri]$Response.Url,$Response.Headers['Location']))).AbsoluteUri } catch { }
    }
}

function New-PWChecklist {
    $items=@(
        @('Engagement and scope','Document target systems, exclusions, test window and contacts.'),
        @('Attack surface','Inventory pages, APIs, roles and especially sensitive flows.'),
        @('Transport and configuration','Check HTTPS, certificates, security headers, debug and error messages.'),
        @('Authentication','Test login, MFA, password change, recovery and lockout behaviour with test accounts.'),
        @('Sessions','Test cookie attributes, session rotation, expiry, logout and reuse of old tokens.'),
        @('Roles and object access','Replay requests with different test accounts; check horizontal and vertical privileges.'),
        @('Input validation','Check parameters and file uploads for context, type, length and server-side validation.'),
        @('XSS and browser','Assess reflection in the browser; examine HTML, attribute, JavaScript and DOM contexts.'),
        @('Injection','Examine SQL, template and other interpreter boundaries on authorized test cases.'),
        @('CSRF and CORS','Examine state-changing requests, token binding, SameSite and origin checks.'),
        @('Business logic','Test ordering, limits, prices, approvals and repeated execution against business rules.'),
        @('Wrap-up and retest','Reproduce findings, justify risks, sanitise evidence, record remediation and retest.')
    )
    foreach ($item in $items) { [pscustomobject]@{ Bereich=$item[0]; Status='Open'; Anleitung=$item[1]; Notizen='' } }
}

function New-PWProject {
    param([string]$Name='New pentest',[string]$ScopeUrl='')
    [pscustomobject]@{ SchemaVersion=2; Tool='PowerWEB'; Version='4.0'; Name=$Name; ScopeUrl=$ScopeUrl; CreatedUtc=[DateTime]::UtcNow.ToString('o'); Findings=@(); History=@(); Checklist=@(New-PWChecklist); Runs=@(); Notes=''; Settings=[pscustomobject]@{ MaxPages=20; MaxDepth=2; DelayMs=250; TimeoutSeconds=15; Active=$false; Seeds=@(); Excludes=@('logout','signout','delete','remove','unsubscribe') } }
}

function Invoke-PWAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScopeUrl,[string[]]$SeedUrls=@(),
        [ValidateRange(1,200)][int]$MaxPages=20,[ValidateRange(0,10)][int]$MaxDepth=2,
        [ValidateRange(0,10000)][int]$DelayMs=250,[ValidateRange(1,60)][int]$TimeoutSeconds=15,
        [string[]]$Exclude=@('logout','signout','delete','remove','unsubscribe'),
        [hashtable]$Headers=@{},[switch]$Active,[hashtable]$Control,[Net.CookieContainer]$CookieContainer
    )
    $root=ConvertTo-PWUri $ScopeUrl
    if (-not $Control) { $Control=[hashtable]::Synchronized(@{ Cancel=$false; Request=$null; Message='' }) }
    $findings=[Collections.Generic.List[object]]::new(); $history=[Collections.Generic.List[object]]::new()
    $queue=[Collections.Generic.Queue[object]]::new()
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($seed in (@($root.AbsoluteUri)+$SeedUrls)) {
        if (-not (Test-PWScope $seed $ScopeUrl $Exclude)) { throw "Start URL outside scope or excluded: $seed" }
        $normalized=(ConvertTo-PWUri $seed).AbsoluteUri
        if ($seen.Add($normalized)) { $queue.Enqueue([pscustomobject]@{ Url=$normalized; Depth=0 }) }
    }
    $pages=0; $blocked=0; $errors=0; $start=[DateTime]::UtcNow
    function Send-AuditRequest([string]$Url,[string]$Method='GET',[hashtable]$RequestHeaders=$Headers,[string]$Kind='Crawler') {
        if ($Control.Cancel) { return $null }
        $until=[DateTime]::UtcNow.AddMilliseconds($DelayMs)
        while ([DateTime]::UtcNow -lt $until) { if ($Control.Cancel) { return $null }; Start-Sleep -Milliseconds 25 }
        $Control.Message="${Kind}: $Url"
        try {
            $r=Invoke-PWHttp -Url $Url -ScopeUrl $ScopeUrl -Method $Method -Headers $RequestHeaders -Exclude $Exclude -TimeoutSeconds $TimeoutSeconds -Control $Control -CookieContainer $CookieContainer
            $history.Add([pscustomobject]@{ ZeitpunktUtc=[DateTime]::UtcNow.ToString('o'); Methode=$Method; Url=$r.Url; Status=$r.Status; DauerMs=$r.HeaderMs; Typ=$Kind; Fehler='' })
            return $r
        } catch {
            if (-not $Control.Cancel) {
                $history.Add([pscustomobject]@{ ZeitpunktUtc=[DateTime]::UtcNow.ToString('o'); Methode=$Method; Url=$Url; Status=0; DauerMs=0; Typ=$Kind; Fehler=$_.Exception.Message })
            }
            return $null
        }
    }
    while ($queue.Count -gt 0 -and $pages -lt $MaxPages -and -not $Control.Cancel) {
        $item=$queue.Dequeue(); $pages++
        $response=Send-AuditRequest $item.Url
        if (-not $response) { continue }
        foreach ($finding in @(Get-PWPassiveFindings $response)) { $findings.Add($finding) }
        foreach ($link in @(Get-PWLinks $response)) {
            if (-not (Test-PWScope $link $ScopeUrl $Exclude)) { $blocked++; continue }
            if ($item.Depth -lt $MaxDepth -and $seen.Count -lt 2000 -and $seen.Add($link)) { $queue.Enqueue([pscustomobject]@{ Url=$link; Depth=$item.Depth+1 }) }
        }
        if ($Active -and -not $Control.Cancel) {
            $probeHeaders=$Headers.Clone(); $probeHeaders['Origin']='https://powerweb-test.invalid'
            $cors=Send-AuditRequest $item.Url 'GET' $probeHeaders 'CORS test'
            if ($cors -and $cors.Headers['Access-Control-Allow-Origin'] -eq 'https://powerweb-test.invalid') {
                $risk=if ($cors.Headers['Access-Control-Allow-Credentials'] -eq 'true') { 'Medium' } else { 'Info' }
                $findings.Add((New-PWFinding 'Test origin reflected in CORS response' $risk $item.Url 'Foreign test origin accepted. Exploitability and sensitive content not confirmed.' 'Review the origin allowlist and access to protected data in the browser.' 'Active'))
            }
            $options=Send-AuditRequest $item.Url 'OPTIONS' $Headers 'Method hint'
            if ($options -and $options.Headers['Allow']) { $findings.Add((New-PWFinding 'Advertised HTTP methods' 'Info' $item.Url ("Allow: {0}. The methods were not executed." -f $options.Headers['Allow']) 'Review the required methods and their access controls manually.' 'Active')) }
            # Inert marker, no script/SQL payload. At most 3 existing parameters per page.
            $u=[Uri]$item.Url
            if ($u.Query.Length -gt 1) {
                $pairs=$u.Query.Substring(1).Split('&')
                for ($index=0; $index -lt [Math]::Min(3,$pairs.Length); $index++) {
                    if ($Control.Cancel) { break }
                    $key=($pairs[$index] -split '=',2)[0]
                    $decoded=[Uri]::UnescapeDataString($key)
                    if ($decoded -match '(?i)token|secret|pass|auth|csrf|session|key|signature') { continue }
                    $marker='PW'+[Guid]::NewGuid().ToString('N')
                    $modified=[string[]]$pairs.Clone(); $modified[$index]=$key+'='+$marker
                    $builder=[UriBuilder]::new($u); $builder.Query=$modified -join '&'
                    $reflected=Send-AuditRequest $builder.Uri.AbsoluteUri 'GET' $Headers 'Reflection test'
                    if ($reflected -and $reflected.Body.Contains($marker)) { $findings.Add((New-PWFinding 'Parameter reflected in content' 'Info' $item.Url ("Parameter: {0}; neutral test marker found. No XSS evidence." -f $decoded) 'Examine output context, encoding and browser effect manually.' 'Active')) }
                }
            }
        }
    }
    $errors=@($history | Where-Object { $_.Status -eq 0 }).Count
    $completion=if ($Control.Cancel) { 'Cancelled' } elseif ($errors -gt 0) { 'Completed with errors' } else { 'Finished' }
    [pscustomobject]@{
        Findings=$findings.ToArray(); History=$history.ToArray()
        Summary=[pscustomobject]@{ StartUtc=$start.ToString('o'); EndeUtc=[DateTime]::UtcNow.ToString('o'); Scope=$ScopeUrl; Status=$completion; Seiten=$pages; Anfragen=$history.Count; Fehler=$errors; AusserhalbScope=$blocked; RestQueue=$queue.Count; MaxSeiten=$MaxPages; MaxTiefe=$MaxDepth; PauseMs=$DelayMs; Aktiv=[bool]$Active; Ausschluesse=($Exclude -join ', '); Hinweis='Only discovered links/redirects within the depth; no browser, no complete pentest evidence.' }
    }
}

function Save-PWProject {
    param([Parameter(Mandatory)]$Project,[Parameter(Mandatory)][string]$Path)
    [IO.File]::WriteAllText($Path,($Project | ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
}

function Invoke-PWFuzz {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Template,[AllowEmptyString()][string]$ScopeUrl='',
        [Parameter(Mandatory)][string[]]$Payloads,[hashtable]$Headers=@{},[string[]]$Exclude=@(),
        [ValidateRange(0,10000)][int]$DelayMs=250,[ValidateRange(1,60)][int]$TimeoutSeconds=15,[hashtable]$Control,[Net.CookieContainer]$CookieContainer)
    if (($Template.Split(@('{{PAYLOAD}}'),[StringSplitOptions]::None)).Count -ne 2) { throw 'The URL must contain exactly one {{PAYLOAD}} placeholder.' }
    $probe=[Uri]($Template.Replace('{{PAYLOAD}}','PWTEST'))
    if (-not $probe.Query.Contains('PWTEST') -or $probe.AbsolutePath.Contains('PWTEST') -or $probe.Host.Contains('pwtest')) { throw 'The placeholder must be in the query part of the URL.' }
    if ($Payloads.Count -lt 1 -or $Payloads.Count -gt 50) { throw '1 to 50 test values are allowed.' }
    if (-not $Control) { $Control=[hashtable]::Synchronized(@{ Cancel=$false; Request=$null; Message='' }) }
    $history=[Collections.Generic.List[object]]::new(); $rows=[Collections.Generic.List[object]]::new(); $findings=[Collections.Generic.List[object]]::new()
    foreach ($payload in $Payloads) {
        if ($payload.Length -gt 2048) { throw 'A test value may hold at most 2048 characters.' }
        if ($Control.Cancel) { break }
        $url=$Template.Replace('{{PAYLOAD}}',[Uri]::EscapeDataString($payload))
        if (-not (Test-PWScope $url $ScopeUrl $Exclude)) { throw 'Test URL is outside scope or excluded.' }
        $Control.Message='Parameter test: '+($rows.Count+1)+' / '+$Payloads.Count
        $until=[DateTime]::UtcNow.AddMilliseconds($DelayMs)
        while ([DateTime]::UtcNow -lt $until) { if ($Control.Cancel) { break }; Start-Sleep -Milliseconds 25 }
        if ($Control.Cancel) { break }
        try {
            $r=Invoke-PWHttp -Url $url -ScopeUrl $ScopeUrl -Headers $Headers -Exclude $Exclude -TimeoutSeconds $TimeoutSeconds -Control $Control -CookieContainer $CookieContainer
            $rows.Add([pscustomobject]@{ Value=$payload; HTTP=$r.Status; Ms=$r.HeaderMs; Bytes=$r.BytesRead; Truncated=$r.Truncated; Reflected=($payload.Length -gt 0 -and $r.Body.Contains($payload)); Error='' })
            $history.Add([pscustomobject]@{ ZeitpunktUtc=[DateTime]::UtcNow.ToString('o'); Methode='GET'; Url=$r.Url; Status=$r.Status; DauerMs=$r.HeaderMs; Typ='Parameter test'; Fehler='' })
            foreach ($f in @(Get-PWPassiveFindings $r)) { $findings.Add($f) }
        } catch {
            if (-not $Control.Cancel) {
                $rows.Add([pscustomobject]@{ Value=$payload; HTTP=0; Ms=0; Bytes=0; Truncated=$false; Reflected=$false; Error=$_.Exception.Message })
                $history.Add([pscustomobject]@{ ZeitpunktUtc=[DateTime]::UtcNow.ToString('o'); Methode='GET'; Url=$url; Status=0; DauerMs=0; Typ='Parameter test'; Fehler=$_.Exception.Message })
            }
        }
    }
    [pscustomobject]@{ Rows=$rows.ToArray(); History=$history.ToArray(); Findings=$findings.ToArray(); Cancelled=[bool]$Control.Cancel }
}

function Import-PWProject {
    param([Parameter(Mandatory)][string]$Path)
    if ((Get-Item -LiteralPath $Path).Length -gt 20MB) { throw 'Project file is larger than 20 MB.' }
    $p=Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    foreach ($field in @('SchemaVersion','Tool','Version','Name','ScopeUrl','CreatedUtc','Findings','History','Checklist','Runs','Notes','Settings')) {
        if ($p.PSObject.Properties.Name -notcontains $field) { throw "Project field missing: $field" }
    }
    if ($p.SchemaVersion -ne 2 -or $p.Tool -ne 'PowerWEB') { throw 'Unsupported project format.' }
    foreach ($field in @('MaxPages','MaxDepth','DelayMs','TimeoutSeconds','Active','Seeds','Excludes')) {
        if ($null -eq $p.Settings -or $p.Settings.PSObject.Properties.Name -notcontains $field) { throw 'Incomplete project settings.' }
    }
    foreach ($group in @(@('Findings',@('Id','Risiko','Titel','Url','Status','Quelle','Nachweis','Empfehlung')),@('History',@('ZeitpunktUtc','Methode','Url','Status','DauerMs','Typ','Fehler')),@('Checklist',@('Bereich','Status','Anleitung','Notizen')))) {
        foreach ($row in @($p.($group[0]))) {
            foreach ($field in $group[1]) { if ($null -eq $row -or $row.PSObject.Properties.Name -notcontains $field) { throw 'Project contains incomplete entries.' } }
        }
    }
    return $p
}

function Export-PWProjectReport {
    param([Parameter(Mandatory)]$Project,[Parameter(Mandatory)][string]$Path,[ValidateSet('HTML','JSON','CSV')][string]$Format='HTML')
    if ($Format -eq 'JSON') { Save-PWProject $Project $Path; return }
    if ($Format -eq 'CSV') {
        # Prevent spreadsheet formula execution on opening attacker-controlled values.
        # ConvertTo-Csv uses the first object's properties: build the union first.
        $columns=[Collections.Generic.List[string]]::new()
        foreach ($f in $Project.Findings) { foreach ($prop in $f.PSObject.Properties) { if (-not $columns.Contains($prop.Name)) { $columns.Add($prop.Name) } } }
        $safe=foreach ($f in $Project.Findings) {
            $row=[ordered]@{}
            foreach ($column in $columns) {
                $prop=$f.PSObject.Properties[$column]
                if ($null -eq $prop) { $row[$column]=''; continue }
                $value=if ($null -ne $prop.Value -and $prop.Value -isnot [string] -and $prop.Value -isnot [ValueType]) { $prop.Value | ConvertTo-Json -Depth 10 -Compress } else { [string]$prop.Value }
                if ($value -match '^[\s]*[=+@-]|^[\t\r\n]') { $value="'"+$value }
                $row[$prop.Name]=$value
            }
            [pscustomobject]$row
        }
        $csv=if (@($safe).Count) { @($safe | ConvertTo-Csv -NoTypeInformation) -join "`r`n" } else { '"Id","Risiko","Titel","Url","Status","Quelle","Nachweis","Empfehlung"' }
        [IO.File]::WriteAllText($Path,$csv,[Text.UTF8Encoding]::new($true)); return
    }
    function E($Value) { [Net.WebUtility]::HtmlEncode([string]$Value) }
    $findings=foreach ($f in $Project.Findings) {
        $proof=''
        if ($f.PSObject.Properties.Name -contains 'Belege') { $proof='<details><summary>Control requests and response evidence</summary><pre>'+(E ($f.Belege | ConvertTo-Json -Depth 10))+'</pre></details>' }
        '<article><h3>{0} · {1}</h3><p>{2} | {3} | {4}</p><p><b>Evidence:</b> {5}</p><p><b>Recommendation:</b> {6}</p>{7}</article>' -f (E $f.Risiko),(E $f.Titel),(E $f.Url),(E $f.Status),(E $f.Quelle),(E $f.Nachweis),(E $f.Empfehlung),$proof
    }
    $checklist=foreach ($c in $Project.Checklist) { '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f (E $c.Bereich),(E $c.Status),(E $c.Anleitung),(E $c.Notizen) }
    $history=foreach ($r in $Project.History) { '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f (E $r.Methode),(E $r.Url),(E $r.Status),(E $r.Typ),(E $r.Fehler) }
    $runs=foreach ($r in $Project.Runs) { '<pre>{0}</pre>' -f (E ($r | ConvertTo-Json -Depth 10)) }
    $content=@"
<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>PowerWEB pentest report</title>
<style>body{font:15px system-ui;max-width:1100px;margin:40px auto;padding:0 24px;color:#16263b;background:#f3f6fa}h1{color:#1267bd}article,pre{background:white;padding:18px;border:1px solid #d7e1ef;border-radius:8px}table{border-collapse:collapse;width:100%;background:white}td,th{text-align:left;border:1px solid #d7e1ef;padding:10px;vertical-align:top}p,td,pre{white-space:pre-wrap;overflow-wrap:anywhere}@media print{body{background:white}article{break-inside:avoid}}</style>
<h1>PowerWEB · $(E $Project.Name)</h1><p>Target scope: $(E $Project.ScopeUrl)<br>Project created: $(E $Project.CreatedUtc)</p>
<p>Automatic hints must be confirmed on their merits. Open or untested checks are not a security proof. This report documents the scope actually executed.</p>
<h2>Engagement and notes</h2><p>$(E $Project.Notes)</p><h2>Findings ($(@($Project.Findings).Count))</h2>$($findings -join "`n")
<h2>Manual coverage</h2><table><tr><th>Area</th><th>Status</th><th>Task</th><th>Evidence / notes</th></tr>$($checklist -join "`n")</table>
<h2>Scan scope and limits</h2>$($runs -join "`n")<h2>Request history</h2><table><tr><th>Method</th><th>URL</th><th>HTTP</th><th>Test</th><th>Error</th></tr>$($history -join "`n")</table></html>
"@
    [IO.File]::WriteAllText($Path,$content,[Text.UTF8Encoding]::new($false))
}

Export-ModuleMember -Function Test-PWScope,ConvertFrom-PWHeaderText,Invoke-PWHttp,Get-PWPassiveFindings,Get-PWLinks,New-PWFinding,New-PWProject,Invoke-PWAudit,Invoke-PWFuzz,Save-PWProject,Import-PWProject,Export-PWProjectReport
