# SPDX-License-Identifier: MIT
# UI-side helpers for PowerWEB: sitemap tree, HAR import and cURL conversion.
# Pure data transforms; the WPF layer renders/consumes their output.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Get-PWSitemap {
    # Builds a host -> path tree from a flat list of URLs. Returns an array of root
    # nodes; each node is @{ Name; Url; Children=@(...) }. Intermediate path nodes
    # carry the directory URL; a query is added as a child leaf named "?...".
    param([string[]]$Urls)
    $roots=[ordered]@{}
    function Get-Child($map,[string]$name,[string]$url) {
        if (-not $map.Contains($name)) { $map[$name]=@{ Name=$name; Url=$url; ChildMap=[ordered]@{} } }
        elseif ($url -and -not $map[$name].Url) { $map[$name].Url=$url }
        return $map[$name]
    }
    foreach ($u in $Urls) {
        if (-not $u) { continue }
        $uri=$null; if (-not [Uri]::TryCreate([string]$u,[UriKind]::Absolute,[ref]$uri)) { continue }
        if ($uri.Scheme -notin @('http','https')) { continue }
        $origin=$uri.GetLeftPart([UriPartial]::Authority)
        $node=Get-Child $roots $origin ($origin+'/')
        $acc=$origin
        foreach ($seg in ($uri.AbsolutePath.Trim('/') -split '/')) {
            if (-not $seg) { continue }
            $acc=$acc+'/'+$seg
            $node=Get-Child $node.ChildMap $seg $acc
        }
        if ($uri.Query.Length -gt 1) { [void](Get-Child $node.ChildMap $uri.Query ($uri.AbsoluteUri)) }
    }
    function Convert-Node($n) {
        $children=@(); foreach ($k in $n.ChildMap.Keys) { $children+=(Convert-Node $n.ChildMap[$k]) }
        [pscustomobject]@{ Name=$n.Name; Url=$n.Url; Children=$children }
    }
    $out=@(); foreach ($k in $roots.Keys) { $out+=(Convert-Node $roots[$k]) }
    return $out
}

function Import-PWHar {
    # Parses a .har file into history rows and repeater-ready requests.
    param([Parameter(Mandatory)][string]$Path,[int]$MaxRequests=200)
    if ((Get-Item -LiteralPath $Path).Length -gt 50MB) { throw 'HAR file is larger than 50 MB.' }
    $har=Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    function Has($o,[string]$n) { return ($null -ne $o -and ($o.PSObject.Properties.Name -contains $n)) }
    if (-not (Has $har 'log') -or -not (Has $har.log 'entries')) { throw 'Not a valid HAR file (log.entries missing).' }
    $skip=@('host','content-length','connection','proxy-connection','keep-alive','transfer-encoding','cookie')
    $history=[Collections.Generic.List[object]]::new(); $requests=[Collections.Generic.List[object]]::new()
    foreach ($e in $har.log.entries) {
        if (-not (Has $e 'request')) { continue }
        $req=$e.request; if (-not (Has $req 'url')) { continue }
        $url=[string]$req.url; if ($url -notmatch '^https?://') { continue }
        $method='GET'; if ((Has $req 'method') -and $req.method) { $method=[string]$req.method }
        $status=0; if ((Has $e 'response') -and (Has $e.response 'status')) { $status=[int]$e.response.status }
        $ms=0; if ((Has $e 'time') -and $null -ne $e.time) { try { $ms=[int][Math]::Round([double]$e.time) } catch { } }
        $history.Add([pscustomobject]@{ ZeitpunktUtc=[DateTime]::UtcNow.ToString('o'); Methode=$method; Url=$url; Status=$status; DauerMs=$ms; Typ='HAR'; Fehler='' })
        if ($requests.Count -lt $MaxRequests) {
            $hlines=@()
            if ((Has $req 'headers') -and $req.headers) { foreach ($h in $req.headers) { if (-not (Has $h 'name')) { continue }; $name=[string]$h.name; if (-not $name -or $name.StartsWith(':')) { continue }; if ($name.ToLowerInvariant() -in $skip) { continue }; $val=if (Has $h 'value') { [string]$h.value } else { '' }; $hlines+=('{0}: {1}' -f $name,$val) } }
            $body=''; if ((Has $req 'postData') -and (Has $req.postData 'text') -and $null -ne $req.postData.text) { $body=[string]$req.postData.text }
            $requests.Add(@{ Method=$method; Url=$url; Headers=($hlines -join "`r`n"); Body=$body })
        }
    }
    [pscustomobject]@{ History=$history.ToArray(); Requests=$requests.ToArray() }
}

function ConvertTo-PWCurl {
    # Builds a single-line curl command. Values are double-quoted with " escaped.
    param([string]$Method='GET',[Parameter(Mandatory)][string]$Url,[string]$HeadersText='',[string]$Body='')
    function Q([string]$s) { '"'+([string]$s -replace '"','\"')+'"' }
    $parts=[Collections.Generic.List[string]]::new(); [void]$parts.Add('curl'); [void]$parts.Add('-i')
    if ($Method -and $Method -ne 'GET') { [void]$parts.Add('-X'); [void]$parts.Add($Method) }
    foreach ($line in ($HeadersText -split '\r?\n')) { if ($line.Trim()) { [void]$parts.Add('-H'); [void]$parts.Add((Q $line.Trim())) } }
    if ($Body) { [void]$parts.Add('--data-raw'); [void]$parts.Add((Q $Body)) }
    [void]$parts.Add((Q $Url))
    return ($parts -join ' ')
}

function ConvertFrom-PWCurl {
    # Parses a curl command into method/url/headers/body. Handles the common flags.
    param([Parameter(Mandatory)][string]$Text)
    $t=$Text -replace '(\\|\^|`)\r?\n',' '
    $toks=[Collections.Generic.List[string]]::new(); $cur=[Text.StringBuilder]::new(); $q=$null; $has=$false
    for ($i=0; $i -lt $t.Length; $i++) {
        $c=$t[$i]
        if ($q) {
            if ($c -eq '\' -and $q -eq '"' -and $i+1 -lt $t.Length -and $t[$i+1] -eq '"') { [void]$cur.Append('"'); $i++ }
            elseif ($c -eq $q) { $q=$null } else { [void]$cur.Append($c) }
        }
        elseif ($c -eq '"' -or $c -eq "'") { $q=$c; $has=$true }
        elseif ($c -eq ' ' -or $c -eq "`t" -or $c -eq "`r" -or $c -eq "`n") { if ($has -or $cur.Length) { $toks.Add($cur.ToString()); [void]$cur.Clear(); $has=$false } }
        else { [void]$cur.Append($c) }
    }
    if ($has -or $cur.Length) { $toks.Add($cur.ToString()) }

    $method=''; $url=''; $headers=[Collections.Generic.List[string]]::new(); $body=''
    for ($i=0; $i -lt $toks.Count; $i++) {
        $tok=$toks[$i]
        if ($tok -eq 'curl') { continue }
        elseif ($tok -eq '-X' -or $tok -eq '--request') { if ($i+1 -lt $toks.Count) { $i++; $method=$toks[$i] } }
        elseif ($tok -eq '-H' -or $tok -eq '--header') { if ($i+1 -lt $toks.Count) { $i++; $headers.Add($toks[$i]) } }
        elseif ($tok -eq '-A' -or $tok -eq '--user-agent') { if ($i+1 -lt $toks.Count) { $i++; $headers.Add('User-Agent: '+$toks[$i]) } }
        elseif ($tok -eq '-e' -or $tok -eq '--referer') { if ($i+1 -lt $toks.Count) { $i++; $headers.Add('Referer: '+$toks[$i]) } }
        elseif ($tok -eq '-b' -or $tok -eq '--cookie') { if ($i+1 -lt $toks.Count) { $i++; $headers.Add('Cookie: '+$toks[$i]) } }
        elseif ($tok -in @('-d','--data','--data-raw','--data-binary','--data-ascii','--data-urlencode')) { if ($i+1 -lt $toks.Count) { $i++; if ($body) { $body+='&' }; $body+=$toks[$i]; if (-not $method) { $method='POST' } } }
        elseif ($tok -eq '--url') { if ($i+1 -lt $toks.Count) { $i++; $url=$toks[$i] } }
        elseif ($tok -match '^https?://') { if (-not $url) { $url=$tok } }
    }
    if (-not $method) { $method='GET' }
    return @{ Method=$method; Url=$url; Headers=($headers -join "`r`n"); Body=$body }
}

Export-ModuleMember -Function Get-PWSitemap,Import-PWHar,ConvertTo-PWCurl,ConvertFrom-PWCurl
