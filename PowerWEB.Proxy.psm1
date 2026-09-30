# SPDX-License-Identifier: MIT
# Independently written forward proxy for PowerWEB. Intercepts HTTP, allows
# modifying request and response headers/body (rules or manual intercept) and
# forwards. HTTPS is tunnelled by default; with MITM enabled it is decrypted using
# a locally generated CA so headers can be modified too. Use only within scope.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'PowerWEB.Audit.psm1')

# Connection-managed / hop-by-hop headers the proxy does not forward.
$script:PWHopByHop=@('connection','proxy-connection','keep-alive','transfer-encoding','te','trailer','upgrade','proxy-authorization','proxy-authenticate')

function New-PWProxyState {
    param(
        [int]$Port=8081,[string]$ScopeUrl='',[string[]]$Exclude=@(),
        [string]$RulesText='',[string]$ResponseRulesText='',
        [bool]$InterceptOn=$false,[bool]$InterceptResponses=$false,
        [bool]$InterceptScopeOnly=$false,[bool]$InterceptSkipStatic=$false,
        [string[]]$InterceptMethods=@(),[string]$InterceptUrlContains='',[string]$InterceptUrlExcludes='',
        [bool]$MitmOn=$false,[Security.Cryptography.X509Certificates.X509Certificate2]$RootCa=$null)
    $s=[hashtable]::Synchronized(@{})
    $s.Port=$Port; $s.ScopeUrl=$ScopeUrl; $s.Exclude=$Exclude
    $s.Rules=@(ConvertFrom-PWProxyRules $RulesText)
    $s.ResponseRules=@(ConvertFrom-PWProxyRules $ResponseRulesText)
    $s.InterceptOn=$InterceptOn; $s.InterceptResponses=$InterceptResponses
    # Interception conditions: which requests are actually held (Burp-style). All
    # empty/false means "hold every request" when interception is on.
    $s.InterceptScopeOnly=$InterceptScopeOnly; $s.InterceptSkipStatic=$InterceptSkipStatic
    $s.InterceptMethods=@($InterceptMethods); $s.InterceptUrlContains=$InterceptUrlContains; $s.InterceptUrlExcludes=$InterceptUrlExcludes
    $s.MitmOn=$MitmOn; $s.RootCa=$RootCa; $s.LeafCache=[hashtable]::Synchronized(@{})
    $s.Stop=$false; $s.Listening=$false; $s.Error=''; $s.Message=''; $s.LastBlock=''; $s.Count=0
    $s.Pending=[Collections.Queue]::Synchronized([Collections.Queue]::new())
    $s.History=[Collections.ArrayList]::Synchronized([Collections.ArrayList]::new())
    return $s
}

function ConvertFrom-PWProxyRules {
    # One rule per line:
    #   set  Name: value      -> set/replace a header
    #   add  Name: value      -> add a header
    #   remove Name           -> remove a header
    #   replace /regex/repl/  -> regex on each header line "Name: value" (not the request line)
    #   body /regex/repl/     -> regex on the message body (text)
    # Lines starting with # are comments. Invalid rules fail visibly.
    param([AllowEmptyString()][string]$Text='')
    $rules=[Collections.Generic.List[object]]::new()
    $lineNumber=0
    foreach ($raw in ($Text -split '\r?\n')) {
        $lineNumber++
        $line=$raw.Trim(); if (-not $line -or $line.StartsWith('#')) { continue }
        $sp=$line.IndexOf(' '); if ($sp -lt 1) { throw "Invalid proxy rule on line $lineNumber." }
        $op=$line.Substring(0,$sp).ToLowerInvariant(); $rest=$line.Substring($sp+1).Trim()
        if($op -in @('set','add','remove')){
            $name=if($op -eq 'remove'){$rest}else{($rest -split ':',2)[0].Trim()}
            if($name -notmatch '^[A-Za-z0-9!#$%&''*+.^_`|~-]+$' -or $name.ToLowerInvariant() -in $script:PWHopByHop -or $name -in @('Host','Content-Length','Content-Encoding')){throw "Invalid or connection-managed header in rule $lineNumber."}
            if($op -in @('set','add') -and ($rest.IndexOf(':') -lt 1 -or $rest -match '[\r\n]')){throw "Invalid header value in rule $lineNumber."}
        }
        switch ($op) {
            'set'    { $c=$rest.IndexOf(':'); if ($c -ge 1) { $rules.Add([pscustomobject]@{Op='set';Name=$rest.Substring(0,$c).Trim();Value=$rest.Substring($c+1).Trim()}) } }
            'add'    { $c=$rest.IndexOf(':'); if ($c -ge 1) { $rules.Add([pscustomobject]@{Op='add';Name=$rest.Substring(0,$c).Trim();Value=$rest.Substring($c+1).Trim()}) } }
            'remove' { $rules.Add([pscustomobject]@{Op='remove';Name=$rest.Trim();Value=''}) }
            {$_ -eq 'replace' -or $_ -eq 'body'} {
                if ($rest.Length -ge 3 -and $rest[0] -eq '/') {
                    $end=$rest.LastIndexOf('/'); $mid=$rest.IndexOf('/',1)
                    if ($mid -gt 1 -and $end -gt $mid) {
                        $pat=$rest.Substring(1,$mid-1); $rep=$rest.Substring($mid+1,$end-$mid-1)
                        try { [void][regex]::new($pat,[Text.RegularExpressions.RegexOptions]::None,[TimeSpan]::FromMilliseconds(200)); $rules.Add([pscustomobject]@{Op=$op;Name=$pat;Value=$rep}) } catch { throw "Invalid regex in rule $lineNumber." }
                    }
                }
            }
            default { throw "Unknown proxy rule on line $lineNumber." }
        }
        if($op -in @('replace','body') -and -not ($rest.Length -ge 3 -and $rest[0] -eq '/' -and $rest.IndexOf('/',1) -gt 1 -and $rest.LastIndexOf('/') -gt $rest.IndexOf('/',1))){throw "Invalid proxy rule on line $lineNumber."}
    }
    return $rules.ToArray()
}

# --- local CA and per-host leaf certificates for HTTPS MITM ---
function New-PWRootCa {
    $rsa=[Security.Cryptography.RSA]::Create(2048)
    $dn=[Security.Cryptography.X509Certificates.X500DistinguishedName]::new('CN=PowerWEB Proxy CA, O=PowerWEB')
    $req=[Security.Cryptography.X509Certificates.CertificateRequest]::new($dn,$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $req.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true,$false,0,$true))
    $req.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(([Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign),$true))
    $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1),[DateTimeOffset]::UtcNow.AddYears(5))
}
function Get-PWCaDir {
    $dir=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'PowerWEB'
    if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    return $dir
}
function Get-PWCaCertPath { return (Join-Path (Get-PWCaDir) 'powerweb-ca.crt') }
function Get-PWRootCa {
    # Load a persisted CA (so the user imports it once) or create and persist one.
    $dir=Get-PWCaDir; $pfx=Join-Path $dir 'powerweb-ca.pfx'; $crt=Join-Path $dir 'powerweb-ca.crt'
    if (Test-Path -LiteralPath $pfx) {
        try { return [Security.Cryptography.X509Certificates.X509Certificate2]::new($pfx,'PowerWEB',([Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)) } catch { throw 'Existing proxy CA cannot be loaded. Inspect the certificate files before retrying.' }
    }
    $ca=New-PWRootCa
    try {
        [IO.File]::WriteAllBytes($pfx,$ca.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx,'PowerWEB'))
        $b64=[Convert]::ToBase64String($ca.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert),[Base64FormattingOptions]::InsertLineBreaks)
        [IO.File]::WriteAllText($crt,"-----BEGIN CERTIFICATE-----`r`n$b64`r`n-----END CERTIFICATE-----`r`n")
    } catch { throw 'Could not save the proxy CA and certificate. Check local profile access.' }
    return $ca
}
function Get-PWCaTrustStatus {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Ca)
    if ($null -eq $Ca) { $Ca=Get-PWRootCa }
    $store=[Security.Cryptography.X509Certificates.X509Store]::new([Security.Cryptography.X509Certificates.StoreName]::Root,[Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        $matches=$store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$Ca.Thumbprint,$false)
        $sha=[Security.Cryptography.SHA256]::Create()
        try { $sha256=[BitConverter]::ToString($sha.ComputeHash($Ca.RawData)).Replace('-','') } finally { $sha.Dispose() }
        [pscustomobject]@{ Installed=($matches.Count -gt 0); Thumbprint=$Ca.Thumbprint; Sha256=$sha256; Subject=$Ca.Subject }
    } finally { $store.Close() }
}
function Add-PWCaTrust {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Ca)
    if ($null -eq $Ca) { $Ca=Get-PWRootCa }
    if ($Ca.Subject -notmatch '(^|,\s*)CN=PowerWEB Proxy CA(,|$)') { throw 'Certificate is not the PowerWEB proxy CA.' }
    $publicCert=[Security.Cryptography.X509Certificates.X509Certificate2]::new($Ca.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    $store=[Security.Cryptography.X509Certificates.X509Store]::new([Security.Cryptography.X509Certificates.StoreName]::Root,[Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        if ($store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$publicCert.Thumbprint,$false).Count -eq 0) { $store.Add($publicCert) }
    } finally { $store.Close(); $publicCert.Dispose() }
    return (Get-PWCaTrustStatus $Ca)
}
function Remove-PWCaTrust {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Ca)
    if ($null -eq $Ca) { $Ca=Get-PWRootCa }
    $store=[Security.Cryptography.X509Certificates.X509Store]::new([Security.Cryptography.X509Certificates.StoreName]::Root,[Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $matches=$store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$Ca.Thumbprint,$false)
        foreach ($match in $matches) { if ($match.Subject -match '(^|,\s*)CN=PowerWEB Proxy CA(,|$)') { $store.Remove($match) } }
    } finally { $store.Close() }
    return (Get-PWCaTrustStatus $Ca)
}
function New-PWLeafCert {
    param([string]$HostName,$Ca)
    $rsa=[Security.Cryptography.RSA]::Create(2048)
    $dn=[Security.Cryptography.X509Certificates.X500DistinguishedName]::new("CN=$HostName")
    $req=[Security.Cryptography.X509Certificates.CertificateRequest]::new($dn,$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $req.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false,$false,0,$false))
    $eku=[Security.Cryptography.OidCollection]::new(); [void]$eku.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
    $req.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku,$false))
    $san=[Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $ip=$null
    if ([Net.IPAddress]::TryParse($HostName,[ref]$ip)) { $san.AddIpAddress($ip) } else { $san.AddDnsName($HostName) }
    $req.CertificateExtensions.Add($san.Build())
    $serial=New-Object byte[] 16; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($serial)
    $signed=$req.Create($Ca,[DateTimeOffset]::UtcNow.AddDays(-1),[DateTimeOffset]::UtcNow.AddYears(2),$serial)
    $withKey=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($signed,$rsa)
    # Schannel cannot use EphemeralKeySet for an SslStream server certificate.
    # Import into the current user's key store so AuthenticateAsServer can use it.
    try {
        return [Security.Cryptography.X509Certificates.X509Certificate2]::new($withKey.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx),'',([Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet))
    } catch { throw 'Could not import the HTTPS proxy certificate into the Windows user key store. Check profile/key-store access: '+$_.Exception.Message }
}
function Get-PWLeaf {
    param($State,[string]$HostName)
    if ($State.LeafCache.ContainsKey($HostName)) { return $State.LeafCache[$HostName] }
    $leaf=New-PWLeafCert $HostName $State.RootCa
    $State.LeafCache[$HostName]=$leaf
    return $leaf
}

function Read-PWLine {
    param([IO.Stream]$Stream)
    $bytes=[Collections.Generic.List[byte]]::new()
    while ($true) {
        if ($bytes.Count -ge 16384) { throw 'HTTP line exceeds 16 KiB.' }
        $b=$Stream.ReadByte()
        if ($b -lt 0) { if ($bytes.Count -eq 0) { return $null } else { break } }
        if ($b -eq 10) { break }
        if ($b -ne 13) { $bytes.Add([byte]$b) }
    }
    return [Text.Encoding]::ASCII.GetString($bytes.ToArray())
}

function Read-PWHead {
    param([IO.Stream]$Stream)
    $requestLine=Read-PWLine $Stream
    if ($null -eq $requestLine -or -not $requestLine.Trim()) { return $null }
    $headers=[Collections.Generic.List[object]]::new()
    while ($true) {
        if ($headers.Count -ge 100) { throw 'Too many HTTP headers.' }
        $line=Read-PWLine $Stream
        if ($null -eq $line -or $line -eq '') { break }
        $c=$line.IndexOf(':'); if ($c -lt 1) { continue }
        $headers.Add([pscustomobject]@{ Name=$line.Substring(0,$c).Trim(); Value=$line.Substring($c+1).Trim() })
    }
    $parts=$requestLine -split ' ',3
    [pscustomobject]@{ Method=$parts[0]; Target=$(if ($parts.Count -gt 1){$parts[1]}else{''}); Version=$(if ($parts.Count -gt 2){$parts[2]}else{'HTTP/1.1'}); Headers=$headers }
}

function Get-PWHeader { param($Head,[string]$Name) foreach ($h in $Head.Headers) { if ($h.Name -ieq $Name) { return $h.Value } } return $null }

function ConvertTo-PWHeadText {
    param($Head)
    $sb=[Text.StringBuilder]::new()
    [void]$sb.Append(('{0} {1} {2}' -f $Head.Method,$Head.Target,$Head.Version)); [void]$sb.Append("`r`n")
    foreach ($h in $Head.Headers) { [void]$sb.Append(('{0}: {1}' -f $h.Name,$h.Value)); [void]$sb.Append("`r`n") }
    [void]$sb.Append("`r`n")
    $sb.ToString()
}

function ConvertFrom-PWHeadText {
    param([string]$Text)
    $lines=$Text -split '\r?\n'
    $requestLine=$lines[0]
    $headers=[Collections.Generic.List[object]]::new()
    $bodyStart=$lines.Count
    for ($i=1; $i -lt $lines.Count; $i++) {
        $line=$lines[$i]; if (-not $line.Trim()) { $bodyStart=$i+1; break }
        $c=$line.IndexOf(':'); if ($c -lt 1) { continue }
        $headers.Add([pscustomobject]@{ Name=$line.Substring(0,$c).Trim(); Value=$line.Substring($c+1).Trim() })
    }
    $parts=$requestLine.Trim() -split ' ',3
    [pscustomobject]@{ Method=$parts[0]; Target=$(if ($parts.Count -gt 1){$parts[1]}else{''}); Version=$(if ($parts.Count -gt 2){$parts[2]}else{'HTTP/1.1'}); Headers=$headers; Body=$(if($bodyStart -lt $lines.Count){$lines[$bodyStart..($lines.Count-1)] -join "`n"}else{''}) }
}

function ConvertTo-PWResponseText {
    param($Resp)
    $ct=''; foreach ($h in $Resp.Headers) { if ($h.Name -ieq 'Content-Type') { $ct=$h.Value } }
    $sb=[Text.StringBuilder]::new()
    [void]$sb.Append(('HTTP/1.1 {0} {1}' -f $Resp.Status,$Resp.Description)); [void]$sb.Append("`r`n")
    foreach ($h in $Resp.Headers) { [void]$sb.Append(('{0}: {1}' -f $h.Name,$h.Value)); [void]$sb.Append("`r`n") }
    [void]$sb.Append("`r`n")
    if ($ct -match '(?i)text/|json|xml|javascript|x-www-form-urlencoded' -and $null -ne $Resp.Body -and $Resp.Body.Length) {
        try { [void]$sb.Append([Text.Encoding]::UTF8.GetString($Resp.Body)) } catch { }
    }
    $sb.ToString()
}

function ConvertFrom-PWResponseText {
    param([string]$Text)
    $idx=$Text.IndexOf("`r`n`r`n"); if ($idx -lt 0) { $idx=$Text.IndexOf("`n`n") }
    $headPart=if ($idx -ge 0) { $Text.Substring(0,$idx) } else { $Text }
    $bodyPart=if ($idx -ge 0) { $Text.Substring($idx+$(if($Text.Substring($idx).StartsWith("`r`n")){4}else{2})) } else { '' }
    $lines=$headPart -split '\r?\n'
    $m=[regex]::Match($lines[0],'^\S+\s+(\d{3})\s*(.*)$')
    if(-not $m.Success){throw 'Invalid edited response status line.'}
    $status=[int]$m.Groups[1].Value
    $desc=$m.Groups[2].Value
    $headers=[Collections.Generic.List[object]]::new()
    for ($i=1; $i -lt $lines.Count; $i++) { $l=$lines[$i]; if (-not $l.Trim()) { continue }; $c=$l.IndexOf(':'); if ($c -lt 1) { continue }; $headers.Add([pscustomobject]@{Name=$l.Substring(0,$c).Trim();Value=$l.Substring($c+1).Trim()}) }
    [pscustomobject]@{ Status=$status; Description=$desc; Headers=$headers; Body=[Text.Encoding]::UTF8.GetBytes($bodyPart) }
}

function Invoke-PWProxyRules {
    # Applies header ops (set/add/remove/replace) to a Head-like object's Headers.
    param($Head,[object[]]$Rules)
    $list=[Collections.Generic.List[object]]::new()
    foreach ($h in $Head.Headers) { $list.Add([pscustomobject]@{Name=$h.Name;Value=$h.Value}) }
    foreach ($rule in $Rules) {
        switch ($rule.Op) {
            'set' {
                $found=$false
                foreach ($h in $list) { if ($h.Name -ieq $rule.Name) { $h.Value=$rule.Value; $found=$true } }
                if (-not $found) { $list.Add([pscustomobject]@{Name=$rule.Name;Value=$rule.Value}) }
            }
            'add' { $list.Add([pscustomobject]@{Name=$rule.Name;Value=$rule.Value}) }
            'remove' { $keep=[Collections.Generic.List[object]]::new(); foreach ($h in $list) { if ($h.Name -inotlike $rule.Name) { $keep.Add($h) } }; $list=$keep }
            'replace' {
                foreach ($h in $list) {
                    try { $combined=[regex]::Replace(('{0}: {1}' -f $h.Name,$h.Value),$rule.Name,$rule.Value,[Text.RegularExpressions.RegexOptions]::None,[TimeSpan]::FromMilliseconds(200))
                        $c=$combined.IndexOf(':'); if ($c -ge 1) { $h.Name=$combined.Substring(0,$c).Trim(); $h.Value=$combined.Substring($c+1).Trim() }
                    } catch { }
                }
            }
        }
    }
    $Head.Headers=$list
    return $Head
}

function Invoke-PWBodyRulesBytes {
    param([byte[]]$Body,[object[]]$Rules)
    $ops=@($Rules | Where-Object { $_.Op -eq 'body' })
    if (-not $ops.Count -or $null -eq $Body -or -not $Body.Length) { return $Body }
    try { $t=[Text.Encoding]::UTF8.GetString($Body); foreach ($r in $ops) { try { $t=[regex]::Replace($t,$r.Name,$r.Value,[Text.RegularExpressions.RegexOptions]::None,[TimeSpan]::FromMilliseconds(200)) } catch { } }; return [Text.Encoding]::UTF8.GetBytes($t) } catch { return $Body }
}

function Invoke-PWResponseRules {
    param($Resp,[object[]]$Rules)
    $wrap=Invoke-PWProxyRules ([pscustomobject]@{ Headers=$Resp.Headers }) $Rules
    $body=Invoke-PWBodyRulesBytes $Resp.Body $Rules
    [pscustomobject]@{ Status=$Resp.Status; Description=$Resp.Description; Headers=$wrap.Headers; Body=$body }
}

function Send-PWProxyUpstream {
    param([string]$Method,[string]$Url,$Headers,[byte[]]$Body,[int]$TimeoutSeconds=30)
    $req=[Net.HttpWebRequest]::Create($Url)
    $req.Method=$Method; $req.AllowAutoRedirect=$false; $req.KeepAlive=$false
    $req.AutomaticDecompression=[Net.DecompressionMethods]::GZip -bor [Net.DecompressionMethods]::Deflate
    $req.Timeout=$TimeoutSeconds*1000; $req.ReadWriteTimeout=$TimeoutSeconds*1000
    $req.ServicePoint.Expect100Continue=$false
    foreach ($h in $Headers) {
        $lower=$h.Name.ToLowerInvariant()
        if ($lower -in $script:PWHopByHop -or $lower -in @('host','content-length','accept-encoding','date','expect')) { continue }
        try {
            switch ($lower) {
                'content-type' { $req.ContentType=$h.Value }
                'accept'       { $req.Accept=$h.Value }
                'user-agent'   { $req.UserAgent=$h.Value }
                'referer'      { $req.Referer=$h.Value }
                'if-modified-since' { $req.IfModifiedSince=[DateTime]::Parse($h.Value) }
                'range'        { }
                default        { $req.Headers[$h.Name]=$h.Value }
            }
        } catch { }
    }
    if ($null -ne $Body -and $Body.Length -gt 0 -and $Method -notin @('GET','HEAD')) {
        $req.ContentLength=$Body.Length
        $rs=$req.GetRequestStream(); try { $rs.Write($Body,0,$Body.Length) } finally { $rs.Dispose() }
    }
    $resp=$null
    try { $resp=[Net.HttpWebResponse]$req.GetResponse() }
    catch [Net.WebException] { if ($null -eq $_.Exception.Response) { throw }; $resp=[Net.HttpWebResponse]$_.Exception.Response }
    try {
        $ms=[IO.MemoryStream]::new()
        if ($Method -ne 'HEAD') { $rstream=$resp.GetResponseStream(); $buf=New-Object byte[] 8192; while (($n=$rstream.Read($buf,0,$buf.Length)) -gt 0) { if ($ms.Length+$n -gt 10485760) { throw 'Proxy response exceeds 10 MiB limit.' }; $ms.Write($buf,0,$n) } }
        $respHeaders=[Collections.Generic.List[object]]::new()
        foreach ($key in $resp.Headers.AllKeys) {
            if ($key.ToLowerInvariant() -in $script:PWHopByHop -or $key -ieq 'content-length') { continue }
            foreach ($val in $resp.Headers.GetValues($key)) { $respHeaders.Add([pscustomobject]@{Name=$key;Value=$val}) }
        }
        [pscustomobject]@{ Status=[int]$resp.StatusCode; Description=[string]$resp.StatusDescription; Headers=$respHeaders; Body=$ms.ToArray() }
    } finally { if ($resp) { $resp.Close() } }
}

function Write-PWClientResponse {
    param([IO.Stream]$Stream,[int]$Status,[string]$Description,$Headers,[byte[]]$Body)
    $sb=[Text.StringBuilder]::new()
    [void]$sb.Append(('HTTP/1.1 {0} {1}' -f $Status,$Description)); [void]$sb.Append("`r`n")
    foreach ($h in $Headers) {
        if ($h.Name -notmatch '^[A-Za-z0-9!#$%&''*+.^_`|~-]+$' -or [string]$h.Value -match '[\r\n]' -or $h.Name.ToLowerInvariant() -in $script:PWHopByHop -or $h.Name -ieq 'Content-Length') { throw 'Invalid or connection-managed response header.' }
        [void]$sb.Append(('{0}: {1}' -f $h.Name,$h.Value)); [void]$sb.Append("`r`n")
    }
    $len=$(if ($null -ne $Body) { $Body.Length } else { 0 })
    [void]$sb.Append(('Content-Length: {0}' -f $len)); [void]$sb.Append("`r`n")
    [void]$sb.Append("Connection: close`r`n`r`n")
    $headBytes=[Text.Encoding]::ASCII.GetBytes($sb.ToString())
    $Stream.Write($headBytes,0,$headBytes.Length)
    if ($len -gt 0) { $Stream.Write($Body,0,$Body.Length) }
    $Stream.Flush()
}

function Write-PWSimpleResponse {
    param([IO.Stream]$Stream,[int]$Status,[string]$Description,[string]$Text='')
    $body=[Text.Encoding]::UTF8.GetBytes($Text)
    Write-PWClientResponse $Stream $Status $Description @([pscustomobject]@{Name='Content-Type';Value='text/plain; charset=utf-8'}) $body
}

function Invoke-PWTunnel {
    # HTTPS CONNECT: transparent tunnel without inspection.
    param([Net.Sockets.TcpClient]$Client,[string]$HostName,[int]$TargetPort,$State)
    $upstream=[Net.Sockets.TcpClient]::new()
    try {
        $upstream.Connect($HostName,$TargetPort)
        $cs=$Client.GetStream(); $us=$upstream.GetStream()
        $ok=[Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 Connection Established`r`n`r`n")
        $cs.Write($ok,0,$ok.Length); $cs.Flush()
        $t1=$cs.CopyToAsync($us); $t2=$us.CopyToAsync($cs)
        while (-not ($t1.IsCompleted -and $t2.IsCompleted)) { if ($State.Stop) { break }; [Threading.Tasks.Task]::WaitAny(@($t1,$t2),200) | Out-Null }
    } catch { } finally { $upstream.Close() }
}

function Add-PWProxyHistory {
    param($State,[string]$Method,[string]$Url,[int]$Status,[int]$Bytes,[bool]$InScope,[bool]$Modified,$Head,[byte[]]$Body,$Response=$null)
    $preview=@(); foreach ($h in $Head.Headers) { $v=if ($h.Name -imatch 'authorization|cookie|proxy-authorization') { '[hidden]' } else { $h.Value }; $preview+=('{0}: {1}' -f $h.Name,$v) }
    $item=[pscustomobject]@{
        Zeit=[DateTime]::Now.ToString('HH:mm:ss'); Methode=$Method; Url=$Url; HTTP=$Status; Bytes=$Bytes
        ImScope=$InScope; Veraendert=$Modified
        RawMethod=$Method; RawTarget=$Url; RawHeaders=($preview -join "`r`n")
        FullHeaders=$Head.Headers; BodyText=$(if ($null -ne $Body -and $Body.Length -gt 0){ try { [Text.Encoding]::UTF8.GetString($Body) } catch { '' } } else { '' })
        ResponseText=$(if($Response){$shown=ConvertTo-PWResponseText $Response;$shown.Substring(0,[Math]::Min($shown.Length,4096))}else{''})
    }
    [void]$State.History.Add($item)
    while ($State.History.Count -gt 500) { $State.History.RemoveAt(0) }
}

function Test-PWShouldIntercept {
    # Decide whether a single request is held for manual review (Burp-style
    # interception conditions). Interception being ON is checked by the caller;
    # here we only apply the filters. With no filters set, every request is held.
    param($State,[string]$Method,[string]$Url,[bool]$InScope)
    if ($State.InterceptScopeOnly -and -not $InScope) { return $false }
    if ($State.InterceptSkipStatic) {
        $path=$Url; try { $path=([Uri]$Url).AbsolutePath } catch {}
        if ($path -match '(?i)\.(js|mjs|css|png|jpe?g|gif|svg|ico|webp|bmp|woff2?|ttf|eot|otf|map|mp4|webm|mp3|wav|wasm|pdf)(\?|#|$)') { return $false }
    }
    $methods=@(@($State.InterceptMethods) | Where-Object { $_ })
    if ($methods.Count) {
        $m=$Method.ToUpperInvariant()
        if ($m -notin @($methods | ForEach-Object { $_.ToUpperInvariant() })) { return $false }
    }
    if ($State.InterceptUrlContains -and $Url.IndexOf([string]$State.InterceptUrlContains,[StringComparison]::OrdinalIgnoreCase) -lt 0) { return $false }
    if ($State.InterceptUrlExcludes) {
        foreach ($ex in ([string]$State.InterceptUrlExcludes -split '\r?\n|,' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
            if ($Url.IndexOf($ex,[StringComparison]::OrdinalIgnoreCase) -ge 0) { return $false }
        }
    }
    return $true
}

function Wait-PWIntercept {
    # Enqueue an intercept item and block until the UI forwards or drops it.
    param($State,[string]$Kind,[string]$Raw,[string]$Url)
    $item=[hashtable]::Synchronized(@{ Kind=$Kind; Raw=$Raw; Url=$Url; Done=$false; Decision=''; Edited='' })
    $State.Pending.Enqueue($item)
    while (-not $item.Done -and -not $State.Stop) { Start-Sleep -Milliseconds 40 }
    return $item
}

function Invoke-PWServeRequest {
    # Shared request/response handling for the plain-HTTP and MITM paths.
    param([IO.Stream]$Stream,$Head,[string]$Url,[byte[]]$Body,$State,[bool]$InScope)
    $modified=$false
    if (-not $InScope) { Write-PWSimpleResponse $Stream 403 'Forbidden' 'Target outside the configured scope or excluded.'; return }
    $applyEdits = $true
    if ($applyEdits -and @($State.Rules).Count) { $Head=Invoke-PWProxyRules $Head @($State.Rules); $Body=Invoke-PWBodyRulesBytes $Body @($State.Rules); $modified=$true }

    if ($State.InterceptOn -and $InScope -and (Test-PWShouldIntercept $State $Head.Method $Url $InScope)) {
        $disp=[pscustomobject]@{ Method=$Head.Method; Target=$Url; Version=$Head.Version; Headers=$Head.Headers }
        $editableBody=if($Body -and (Get-PWHeader $Head 'Content-Type') -match '(?i)text/|json|xml|x-www-form-urlencoded'){[Text.Encoding]::UTF8.GetString($Body)}else{''}
        $item=Wait-PWIntercept $State 'request' ((ConvertTo-PWHeadText $disp)+$editableBody) $Url
        if ($State.Stop) { try { Write-PWSimpleResponse $Stream 504 'Gateway Timeout' 'Proxy stopped.' } catch {}; return }
        if ($item.Decision -eq 'drop') { Write-PWSimpleResponse $Stream 504 'Dropped' 'Request dropped by the tester.'; return }
        if ($item.Edited -and $item.Edited -ne $item.Raw) { $Head=ConvertFrom-PWHeadText $item.Edited; $Url=$Head.Target; if($editableBody -ne $Head.Body){$Body=[Text.Encoding]::UTF8.GetBytes($Head.Body)}; $modified=$true }
    }

    if (-not (Test-PWScope $Url $State.ScopeUrl $State.Exclude)) { Write-PWSimpleResponse $Stream 403 'Forbidden' 'Edited request left the configured scope.'; return }
    if ($Head.Method -notin @('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS')) { Write-PWSimpleResponse $Stream 400 'Bad Request' 'Unsupported HTTP method.'; return }
    foreach ($h in $Head.Headers) { if ($h.Name -notmatch '^[A-Za-z0-9!#$%&''*+.^_`|~-]+$' -or [string]$h.Value -match '[\r\n]') { Write-PWSimpleResponse $Stream 400 'Bad Request' 'Invalid edited header.'; return } }

    try {
        $resp=Send-PWProxyUpstream $Head.Method $Url $Head.Headers $Body
    } catch {
        try { Write-PWSimpleResponse $Stream 502 'Bad Gateway' ('Upstream request failed: '+$_.Exception.Message) } catch {}
        Add-PWProxyHistory $State $Head.Method $Url 0 0 $InScope $modified $Head $Body
        return
    }

    if ($applyEdits -and @($State.ResponseRules).Count) { $resp=Invoke-PWResponseRules $resp @($State.ResponseRules); $modified=$true }

    if ($State.InterceptResponses -and $InScope -and (Test-PWShouldIntercept $State $Head.Method $Url $InScope)) {
        $item=Wait-PWIntercept $State 'response' (ConvertTo-PWResponseText $resp) $Url
        if ($State.Stop) { return }
        if ($item.Decision -eq 'drop') { try { Write-PWSimpleResponse $Stream 504 'Dropped' 'Response dropped by the tester.' } catch {}; Add-PWProxyHistory $State $Head.Method $Url 0 0 $InScope $true $Head $Body; return }
        if ($item.Edited -and $item.Edited -ne $item.Raw) { $resp=ConvertFrom-PWResponseText $item.Edited; $modified=$true }
    }

    try { Write-PWClientResponse $Stream $resp.Status $resp.Description $resp.Headers $resp.Body }
    catch { Write-PWSimpleResponse $Stream 502 'Bad Gateway' 'Invalid response after editing.'; return }
    Add-PWProxyHistory $State $Head.Method $Url $resp.Status $resp.Body.Length $InScope $modified $Head $Body $resp
}

function Invoke-PWMitm {
    # HTTPS CONNECT with decryption: present a leaf certificate, then serve plaintext
    # requests over the TLS tunnel like the HTTP path. Requires a trusted local CA.
    param([Net.Sockets.TcpClient]$Client,[string]$HostName,[int]$TargetPort,$State)
    $tunnelEstablished=$false
    try {
        $leaf=Get-PWLeaf $State $HostName
        $cs=$Client.GetStream()
        $ok=[Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 Connection Established`r`n`r`n"); $cs.Write($ok,0,$ok.Length); $cs.Flush()
        $tunnelEstablished=$true
        $ssl=[Net.Security.SslStream]::new($cs,$false)
        $ssl.AuthenticateAsServer($leaf,$false,[Security.Authentication.SslProtocols]::Tls12,$false)
        while (-not $State.Stop) {
            $head=Read-PWHead $ssl
            if ($null -eq $head) { break }
            $portPart=if ($TargetPort -ne 443) { ':'+$TargetPort } else { '' }
            $url='https://'+$HostName+$portPart+$head.Target
            if (Get-PWHeader $head 'Transfer-Encoding') { Write-PWSimpleResponse $ssl 501 'Not Implemented' 'Chunked request bodies are not supported.'; break }
            $body=$null; $clen=Get-PWHeader $head 'Content-Length'; $total=0
            if ($clen -and (-not [int]::TryParse($clen,[ref]$total) -or $total -lt 0 -or $total -gt 20971520)) { Write-PWSimpleResponse $ssl 413 'Payload Too Large' 'Invalid or oversized request body.'; break }
            if ($total -gt 0) {
                $body=New-Object byte[] $total; $read=0
                while ($read -lt $total) { $n=$ssl.Read($body,$read,$total-$read); if ($n -le 0) { break }; $read+=$n }
                if ($read -ne $total) { Write-PWSimpleResponse $ssl 400 'Bad Request' 'Incomplete request body.'; break }
            }
            $inScope=[bool](Test-PWScope $url $State.ScopeUrl $State.Exclude)
            Invoke-PWServeRequest $ssl $head $url $body $State $inScope
            # Responses force Connection: close, so end the TLS session after one exchange.
            break
        }
        try { $ssl.Dispose() } catch { }
    } catch {
        $State.Error='HTTPS interception: '+$_.Exception.Message
        if (-not $tunnelEstablished) { try { Write-PWSimpleResponse $Client.GetStream() 502 'Bad Gateway' 'HTTPS proxy certificate could not be prepared. Check PowerWEB status.' } catch {} }
    }
}

function Invoke-PWProxyConnection {
    [CmdletBinding()]
    param([Net.Sockets.TcpClient]$Client,$State)
    try {
        $Client.ReceiveTimeout=30000; $Client.SendTimeout=30000
        $stream=$Client.GetStream()
        $head=Read-PWHead $stream
        if ($null -eq $head) { return }
        $State.Count++

        if ($head.Method -eq 'CONNECT') {
            $connUri=$null
            if (-not [Uri]::TryCreate(('https://'+$head.Target),[UriKind]::Absolute,[ref]$connUri) -or $connUri.Scheme -ne 'https' -or $connUri.AbsolutePath -ne '/' -or $connUri.Query -or $connUri.Fragment -or $connUri.UserInfo) { Write-PWSimpleResponse $stream 400 'Bad Request' 'Invalid CONNECT authority.'; return }
            $h=$connUri.Host; $p=$connUri.Port
            $connUrl=$connUri.GetLeftPart([UriPartial]::Authority)+'/'
            # Scope is optional: with no scope the proxy tunnels/decrypts every
            # host. With a scope set, a CONNECT to a different origin is blocked.
            if ($State.ScopeUrl) {
                $scopeUri=[Uri]$State.ScopeUrl
                $targetOrigin=([Uri]$connUrl).GetLeftPart([UriPartial]::Authority)
                if ($scopeUri.GetLeftPart([UriPartial]::Authority) -ine $targetOrigin) {
                    $State.LastBlock=('Blocked HTTPS {0}: outside scope origin {1}.' -f $head.Target,$scopeUri.GetLeftPart([UriPartial]::Authority))
                    try { Write-PWSimpleResponse $stream 403 'Forbidden' 'CONNECT outside configured origin.' } catch {}
                    return
                }
            }
            if ($State.MitmOn -and $null -ne $State.RootCa) {
                Invoke-PWMitm $Client $h $p $State
            } else {
                if ($State.ScopeUrl -and (([Uri]$State.ScopeUrl).AbsolutePath -ne '/' -or @($State.Exclude).Count -gt 0)) {
                    $State.LastBlock=('Blocked HTTPS {0}: enable Decrypt HTTPS to enforce path scope and exclusions.' -f $head.Target)
                    try { Write-PWSimpleResponse $stream 403 'Forbidden' 'HTTPS path scope or exclusions require decryption to inspect paths.' } catch {}
                    return
                }
                Add-PWProxyHistory $State 'CONNECT' ('https://'+$head.Target) 0 0 $true $false $head $null
                Invoke-PWTunnel $Client $h $p $State
            }
            return
        }

        $url=$head.Target
        if ($url -notmatch '^https?://') { Write-PWSimpleResponse $stream 400 'Bad Request' 'PowerWEB proxy expects absolute URLs (forward proxy).'; return }
        if (Get-PWHeader $head 'Transfer-Encoding') { Write-PWSimpleResponse $stream 501 'Not Implemented' 'Chunked request bodies are not supported.'; return }

        $body=$null; $clen=Get-PWHeader $head 'Content-Length'; $total=0
        if ($clen -and (-not [int]::TryParse($clen,[ref]$total) -or $total -lt 0 -or $total -gt 20971520)) { Write-PWSimpleResponse $stream 413 'Payload Too Large' 'Invalid or oversized request body.'; return }
        if ($total -gt 0) {
            $body=New-Object byte[] $total; $read=0
            while ($read -lt $total) { $n=$stream.Read($body,$read,$total-$read); if ($n -le 0) { break }; $read+=$n }
            if ($read -ne $total) { Write-PWSimpleResponse $stream 400 'Bad Request' 'Incomplete request body.'; return }
        }
        $inScope=[bool](Test-PWScope $url $State.ScopeUrl $State.Exclude)
        Invoke-PWServeRequest $stream $head $url $body $State $inScope
    } catch { $State.Error='Proxy connection: '+$_.Exception.Message } finally { try { $Client.Close() } catch {} }
}

function Start-PWProxyServer {
    [CmdletBinding()]
    param($State,[string]$ModulePath)
    if ($State.MitmOn -and $null -eq $State.RootCa) { try { $State.RootCa=Get-PWRootCa } catch { $State.Error='Proxy CA: '+$_.Exception.Message; return } }
    $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,$State.Port)
    try { $listener.Start() } catch { $State.Error='Listener: '+$_.Exception.Message; $State.Listening=$false; return }
    $State.Listening=$true; $State.Message=('Proxy running on 127.0.0.1:{0}' -f $State.Port)
    $iss=[Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    try { $iss.ImportPSModule(@($ModulePath)) } catch {}
    $pool=[RunspaceFactory]::CreateRunspacePool($iss); $pool.SetMinRunspaces(1); [void]$pool.SetMaxRunspaces(32); $pool.Open()
    $handlerCode='param($client,$state,$module) if (-not (Get-Command Invoke-PWProxyConnection -ErrorAction SilentlyContinue)) { Import-Module $module -Force }; Invoke-PWProxyConnection -Client $client -State $state'
    $active=[Collections.Generic.List[object]]::new()
    try {
        while (-not $State.Stop) {
            if ($listener.Pending()) {
                $client=$listener.AcceptTcpClient()
                $ps=[PowerShell]::Create(); $ps.RunspacePool=$pool
                [void]$ps.AddScript($handlerCode).AddArgument($client).AddArgument($State).AddArgument($ModulePath)
                $active.Add(@{ PS=$ps; Handle=$ps.BeginInvoke() })
            } else { Start-Sleep -Milliseconds 15 }
            for ($i=$active.Count-1; $i -ge 0; $i--) { if ($active[$i].Handle.IsCompleted) { try { $active[$i].PS.EndInvoke($active[$i].Handle) } catch {}; $active[$i].PS.Dispose(); $active.RemoveAt($i) } }
        }
    } finally {
        try { $listener.Stop() } catch {}
        foreach ($a in $active) { try { $a.PS.Stop() } catch {}; try { $a.PS.Dispose() } catch {} }
        try { $pool.Close() } catch {}
        foreach ($leaf in @($State.LeafCache.Values)) { try { $leaf.Dispose() } catch {} }
        $State.LeafCache.Clear()
        $State.Listening=$false; $State.Message='Proxy stopped.'
    }
}

Export-ModuleMember -Function New-PWProxyState,ConvertFrom-PWProxyRules,New-PWRootCa,Get-PWRootCa,Get-PWCaTrustStatus,Add-PWCaTrust,Remove-PWCaTrust,Get-PWCaCertPath,New-PWLeafCert,Get-PWLeaf,Read-PWHead,Get-PWHeader,ConvertTo-PWHeadText,ConvertFrom-PWHeadText,ConvertTo-PWResponseText,ConvertFrom-PWResponseText,Invoke-PWProxyRules,Invoke-PWResponseRules,Invoke-PWBodyRulesBytes,Send-PWProxyUpstream,Invoke-PWServeRequest,Invoke-PWMitm,Invoke-PWProxyConnection,Start-PWProxyServer
