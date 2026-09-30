# SPDX-License-Identifier: MIT
# Native, independently authored HTTP scanner; no external scan engine/runtime.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'PowerWEB.Audit.psm1')

function Protect-PWText {
    param([AllowEmptyString()][string]$Text,[string[]]$Secrets=@())
    $result=$Text
    foreach ($secret in ($Secrets | Sort-Object Length -Descending)) { if ($secret -and $secret.Length -ge 4) { $result=$result.Replace($secret,'[REDACTED]').Replace([Uri]::EscapeDataString($secret),'[REDACTED]') } }
    $result=[regex]::Replace($result,'(?i)((?:password|passwd|access_token|refresh_token|token|api_key|apikey|secret|sessionid|session|authorization)\s*["'']?\s*[:=]\s*["'']?)[^"''\s<>&;,]+','$1[REDACTED]')
    return $result
}
function Protect-PWUrl {
    param([string]$Url,[string[]]$Secrets=@())
    $u=[UriBuilder]::new($Url)
    if ($u.Query.Length -gt 1) {
        $parts=foreach ($part in $u.Query.TrimStart('?').Split('&')) {
            $pair=$part -split '=',2
            if ([Uri]::UnescapeDataString($pair[0]) -match '(?i)pass|token|secret|auth|session|key|signature') { $pair[0]+'=%5BREDACTED%5D' } else { $part }
        }
        $u.Query=$parts -join '&'
    }
    return (Protect-PWText $u.Uri.AbsoluteUri $Secrets)
}
# Reuse a single hasher instead of allocating/disposing one per call. ComputeHash
# resets internal state on each call; scans run single-threaded per runspace.
$script:PWSha256=[Security.Cryptography.SHA256]::Create()
function Get-PWBodyDigest {
    param([string]$Body)
    return ([BitConverter]::ToString($script:PWSha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($Body)))).Replace('-','').ToLowerInvariant()
}
function Get-PWQueryParameters {
    param([string]$Url)
    $u=[Uri]$Url
    if ($u.Query.Length -lt 2) { return }
    $index=0
    foreach ($part in $u.Query.Substring(1).Split('&')) {
        $pair=$part -split '=',2
        [pscustomobject]@{ Index=$index; Name=[Uri]::UnescapeDataString($pair[0].Replace('+',' ')); Value=$(if($pair.Count -gt 1){[Uri]::UnescapeDataString($pair[1].Replace('+',' '))}else{''}) }
        $index++
    }
}
function Set-PWQueryValue {
    param([string]$Url,[int]$Index,[string]$Value)
    $u=[UriBuilder]::new($Url); $parts=$u.Query.TrimStart('?').Split('&')
    $key=($parts[$Index] -split '=',2)[0]; $parts[$Index]=$key+'='+[Uri]::EscapeDataString($Value); $u.Query=$parts -join '&'
    return $u.Uri.AbsoluteUri
}
function New-PWResponseEvidence {
    param($Response,[string]$Label,[string]$Needle='',[string[]]$Secrets=@())
    $snippet=''
    if ($Needle) {
        $pos=$Response.Body.IndexOf($Needle,[StringComparison]::Ordinal)
        if ($pos -ge 0) { $from=[Math]::Max(0,$pos-60); $snippet=$Response.Body.Substring($from,[Math]::Min(300,$Response.Body.Length-$from)) }
    }
    $selected=[ordered]@{}
    foreach ($header in @('Content-Type','Location','Access-Control-Allow-Origin','Access-Control-Allow-Credentials','X-PowerWEB-Probe')) {
        if ($Response.Headers[$header]) { $selected[$header]=Protect-PWText ([string]$Response.Headers[$header]) $Secrets }
    }
    [pscustomobject]@{ Label=$Label; ZeitpunktUtc=[DateTime]::UtcNow.ToString('o'); Methode=$Response.Method; Url=(Protect-PWUrl $Response.Url $Secrets); HttpStatus=$Response.Status; HeaderMs=$Response.HeaderMs; GeleseneBytes=$Response.BytesRead; Gekuerzt=$Response.Truncated; TextSHA256=(Get-PWBodyDigest $Response.Body); AntwortHeader=[pscustomobject]$selected; Ausschnitt=(Protect-PWText $snippet $Secrets) }
}
function Get-PWNativeRules {
    @(
        [pscustomobject]@{Id='PW-SQL-ERROR';Name='New SQL error message';Nachweis='Baseline response, quote test, escape control';Grenze='Suspicion, no confirmed database access'},
        [pscustomobject]@{Id='PW-SQL-BOOL';Name='Boolean SQL response pattern';Nachweis='Stable baseline, repeated true/false pairs';Grenze='Numeric parameters only, manual confirmation required'},
        [pscustomobject]@{Id='PW-TEMPLATE';Name='Template-Auswertung';Nachweis='Two different calculations with unique markers';Grenze='Only two expression syntaxes; no code execution tested'},
        [pscustomobject]@{Id='PW-HTML';Name='Unencoded HTML reflection';Nachweis='Inert HTML element in the response text';Grenze='No XSS or DOM evidence'},
        [pscustomobject]@{Id='PW-REDIRECT';Name='External redirect';Nachweis='Two different random .invalid targets';Grenze='Targets are not requested'},
        [pscustomobject]@{Id='PW-CRLF';Name='Response header injection';Nachweis='Two unique markers as real response headers';Grenze='No further response-splitting exploitation'},
        [pscustomobject]@{Id='PW-CORS';Name='CORS with foreign origins';Nachweis='Two origin response pairs with Credentials=true';Grenze='No evidence of readable confidential data in the browser'}
    )
}

function Invoke-PWNativeScan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ScopeUrl,[string[]]$SeedUrls=@(),[hashtable]$Headers=@{},[Net.CookieContainer]$CookieContainer,
        [string[]]$Exclude=@('logout','signout','delete','remove','unsubscribe'),
        [ValidateRange(1,50)][int]$MaxPages=10,[ValidateRange(0,10)][int]$MaxDepth=2,
        [ValidateRange(1,1000)][int]$MaxRequests=150,[ValidateRange(1,10)][int]$MaxParameters=3,
        [ValidateRange(1,60)][int]$MaxMinutes=10,[ValidateRange(0,10000)][int]$DelayMs=200,[ValidateRange(1,60)][int]$TimeoutSeconds=15,
        [string[]]$Rules=@('PW-SQL-ERROR','PW-SQL-BOOL','PW-TEMPLATE','PW-HTML','PW-REDIRECT','PW-CRLF','PW-CORS'),[hashtable]$Control)
    $knownRules=@(Get-PWNativeRules | ForEach-Object Id)
    foreach ($rule in $Rules) { if ($rule -notin $knownRules) { throw "Unknown scan rule: $rule" } }
    if (-not (Test-PWScope $ScopeUrl $ScopeUrl $Exclude)) { throw 'Invalid or excluded scope.' }
    if (-not $Control) { $Control=[hashtable]::Synchronized(@{Cancel=$false;Request=$null;Message=''}) }
    if ($null -eq $CookieContainer) { $CookieContainer=[Net.CookieContainer]::new() }
    $start=[DateTime]::UtcNow; $deadline=$start.AddMinutes($MaxMinutes)
    $stats=@{ Requests=0; Errors=0; Pages=0; Limited=$false; PartialResponses=0 }
    $findings=[Collections.Generic.List[object]]::new(); $history=[Collections.Generic.List[object]]::new(); $tests=[Collections.Generic.List[object]]::new()
    $secrets=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($key in $Headers.Keys) {
        if ($key -match '(?i)authorization|cookie|token|secret|key') {
            [void]$secrets.Add([string]$Headers[$key]); [void]$secrets.Add(([string]$Headers[$key] -replace '^(?i)Bearer\s+',''))
            if ($key -ieq 'Cookie') { foreach($c in ([string]$Headers[$key] -split ';')) { $p=$c -split '=',2; if($p.Count -eq 2){[void]$secrets.Add($p[1].Trim())} } }
        }
    }
    $queue=[Collections.Generic.Queue[object]]::new(); $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($seed in (@($ScopeUrl)+$SeedUrls)) {
        if (-not (Test-PWScope $seed $ScopeUrl $Exclude)) { throw "Start URL outside scope: $seed" }
        $u=[UriBuilder]::new($seed);$u.Fragment='';if($seen.Add($u.Uri.AbsoluteUri)){$queue.Enqueue([pscustomobject]@{Url=$u.Uri.AbsoluteUri;Depth=0})}
    }
    function Send-Probe([string]$Url,[string]$Label,[hashtable]$RequestHeaders=$Headers) {
        if ($Control.Cancel -or $stats.Requests -ge $MaxRequests -or [DateTime]::UtcNow -ge $deadline) { $stats.Limited=$true; return $null }
        if (-not (Test-PWScope $Url $ScopeUrl $Exclude)) { return $null }
        foreach($parameter in @(Get-PWQueryParameters $Url)){if($parameter.Name -match '(?i)pass|token|secret|auth|session|key|signature'){[void]$secrets.Add($parameter.Value)}}
        $pauseUntil=[DateTime]::UtcNow.AddMilliseconds($DelayMs)
        while([DateTime]::UtcNow -lt $pauseUntil){if($Control.Cancel){return $null};Start-Sleep -Milliseconds 25}
        if($Control.Cancel -or [DateTime]::UtcNow -ge $deadline){$stats.Limited=$true;return $null}
        $stats.Requests++; $Control.Message="Native engine $($stats.Requests)/${MaxRequests}: $Label"
        try {
            $r=Invoke-PWHttp -Url $Url -ScopeUrl $ScopeUrl -Headers $RequestHeaders -CookieContainer $CookieContainer -Exclude $Exclude -TimeoutSeconds $TimeoutSeconds -Control $Control
            if ($r.Truncated -or -not $r.BodyRead) { $stats.PartialResponses++ }
            foreach($cookie in $r.Cookies){$p=($cookie -split ';',2)[0] -split '=',2;if($p.Count -eq 2){[void]$secrets.Add($p[1])}}
            foreach($cookie in $CookieContainer.GetCookies([Uri]$Url)){[void]$secrets.Add($cookie.Value)}
            $history.Add([pscustomobject]@{ZeitpunktUtc=[DateTime]::UtcNow.ToString('o');Methode='GET';Url=(Protect-PWUrl $r.Url @($secrets));Status=$r.Status;DauerMs=$r.HeaderMs;Typ=$Label;Fehler=''})
            return $r
        } catch {
            if(-not $Control.Cancel){$stats.Errors++;$history.Add([pscustomobject]@{ZeitpunktUtc=[DateTime]::UtcNow.ToString('o');Methode='GET';Url=(Protect-PWUrl $Url @($secrets));Status=0;DauerMs=0;Typ=$Label;Fehler=(Protect-PWText $_.Exception.Message @($secrets))})}
            return $null
        }
    }
    function Record-Test([string]$Rule,[string]$Url,[string]$Parameter,[string]$Result) {
        $tests.Add([pscustomobject]@{Regel=$Rule;Url=(Protect-PWUrl $Url @($secrets));Parameter=$Parameter;Ergebnis=$Result})
    }
    function Add-NativeFinding([string]$Rule,[string]$Title,[string]$Risk,[string]$Url,[string]$Parameter,[string]$Confidence,[string]$Explanation,[string]$Fix,[object[]]$Evidence) {
        $safeUrl=Protect-PWUrl $Url @($secrets)
        $proof=@($Evidence | Where-Object { $null -ne $_ })
        $text="Regel: $Rule`nParameter: $Parameter`nNachweissicherheit: $Confidence`n$Explanation`n"+(@($proof|ForEach-Object { "$($_.Label): HTTP $($_.HttpStatus), SHA256 $($_.TextSHA256), $($_.Url)" }) -join "`n")
        $f=New-PWFinding -Title $Title -Risk $Risk -Url $safeUrl -Evidence (Protect-PWText $text @($secrets)) -Fix $Fix -Source 'Native engine'
        $f | Add-Member -NotePropertyName RegelId -NotePropertyValue $Rule
        $f | Add-Member -NotePropertyName Sicherheit -NotePropertyValue $Confidence
        $f | Add-Member -NotePropertyName Belege -NotePropertyValue $proof
        $findings.Add($f);Record-Test $Rule $Url $Parameter 'Finding'
    }
    function Evidence($Response,[string]$Label,[string]$Needle='') { New-PWResponseEvidence $Response $Label $Needle @($secrets) }
    $sqlRx='(?i)You have an error in your SQL syntax|Unclosed quotation mark after the character string|unterminated quoted string|ORA-01756|SQLite(?:Exception|3?::SQLException).*?(?:syntax|unrecognized token)|SQLSTATE\[42000\]'
    while($queue.Count -gt 0 -and $stats.Pages -lt $MaxPages -and -not $Control.Cancel -and -not $stats.Limited){
        $item=$queue.Dequeue();$stats.Pages++
        $base=Send-Probe $item.Url 'Base'
        if(-not $base){continue}
        foreach($f in @(Get-PWPassiveFindings $base)){$f.Url=Protect-PWUrl $f.Url @($secrets);$f.Nachweis=Protect-PWText $f.Nachweis @($secrets);$findings.Add($f)}
        foreach($link in @(Get-PWLinks $base)){if($item.Depth -lt $MaxDepth -and $seen.Count -lt 2000 -and (Test-PWScope $link $ScopeUrl $Exclude) -and $seen.Add($link)){$queue.Enqueue([pscustomobject]@{Url=$link;Depth=$item.Depth+1})}}
        if('PW-CORS' -in $Rules){
            $cors=@();$origins=@()
            for($i=0;$i -lt 2;$i++){$origin='https://pw-'+[Guid]::NewGuid().ToString('N')+'.invalid';$origins+=$origin;$h=$Headers.Clone();$h.Origin=$origin;$cors+=,(Send-Probe $item.Url 'PW-CORS' $h)}
            if($cors[0] -and $cors[1]){
                if($cors[0].Headers['Access-Control-Allow-Origin'] -ceq $origins[0] -and $cors[1].Headers['Access-Control-Allow-Origin'] -ceq $origins[1] -and $cors[0].Headers['Access-Control-Allow-Credentials'] -ceq 'true' -and $cors[1].Headers['Access-Control-Allow-Credentials'] -ceq 'true'){
                    Add-NativeFinding 'PW-CORS' 'Arbitrary test origins accepted with credentials' 'Mittel' $item.Url 'Origin' 'High (header behaviour)' 'Two foreign origins were echoed exactly. Access to confidential data in the browser not tested.' 'Review the origin allowlist and the resource sensitivity.' @((Evidence $base 'Base'),(Evidence $cors[0] 'Origin A'),(Evidence $cors[1] 'Origin B'))
                }else{Record-Test 'PW-CORS' $item.Url 'Origin' 'No evidence'}
            }else{Record-Test 'PW-CORS' $item.Url 'Origin' 'Incomplete'}
        }
        $parameters=@(Get-PWQueryParameters $item.Url)
        $selected=@($parameters | Where-Object {$_.Name -notmatch '(?i)pass|token|secret|auth|session|key|signature'} | Select-Object -First $MaxParameters)
        $selectedIndexes=@($selected|ForEach-Object Index)
        foreach($p in $parameters){if($p.Index -notin $selectedIndexes){Record-Test 'Parameter scope' $item.Url $p.Name 'Skipped (sensitive name or parameter limit)'}}
        foreach($p in $selected){
            foreach($rule in @($Rules|Where-Object {$_ -ne 'PW-CORS'})){
                if($Control.Cancel -or $stats.Limited){Record-Test $rule $item.Url $p.Name 'Incomplete';continue}
                $before=$findings.Count;$completed=$true;$recorded=$false
                $partialBefore=$stats.PartialResponses
                $bodyRule=$rule -in @('PW-SQL-ERROR','PW-SQL-BOOL','PW-TEMPLATE','PW-HTML')
                if ($bodyRule -and ($base.Truncated -or -not $base.BodyRead)) {
                    Record-Test $rule $item.Url $p.Name 'Skipped (base truncated or no text read)'
                    continue
                }
                switch($rule){
                    'PW-SQL-ERROR'{
                        if($base.Body -match $sqlRx){Record-Test $rule $item.Url $p.Name 'Skipped (error already in base)';$recorded=$true;continue}
                        $q=Send-Probe (Set-PWQueryValue $item.Url $p.Index ($p.Value+"'")) $rule
                        $c=Send-Probe (Set-PWQueryValue $item.Url $p.Index ($p.Value+"''")) $rule
                        if($q -and $c -and -not $q.Truncated -and -not $c.Truncated){
                            $m=[regex]::Match($q.Body,$sqlRx)
                            if($m.Success -and $c.Body -notmatch $sqlRx){Add-NativeFinding $rule 'Suspected SQL injection via error message' 'Hoch' $item.Url $p.Name 'Mittel' 'SQL error pattern only on the single-quote test; escape control without this pattern. No confirmed data access.' 'Use parameterised database queries and do not expose error details.' @((Evidence $base 'Base'),(Evidence $q 'Quote test' $m.Value),(Evidence $c 'Escape control'))}
                        }else{$completed=$false}
                    }
                    'PW-SQL-BOOL'{
                        if($p.Value -notmatch '^\d{1,12}$' -or $base.Truncated -or -not $base.Body){Record-Test $rule $item.Url $p.Name 'Skipped (no complete numeric base)';$recorded=$true;continue}
                        $repeat=Send-Probe $item.Url ($rule+' Base repeat')
                        if(-not $repeat){$completed=$false;break}
                        $digest=Get-PWBodyDigest $base.Body
                        if($repeat.Truncated -or $repeat.Status -ne $base.Status -or (Get-PWBodyDigest $repeat.Body) -ne $digest){Record-Test $rule $item.Url $p.Name 'Skipped (dynamic base)';$recorded=$true;continue}
                        $t1=Send-Probe (Set-PWQueryValue $item.Url $p.Index ($p.Value+' AND 731=731')) $rule
                        $f1=Send-Probe (Set-PWQueryValue $item.Url $p.Index ($p.Value+' AND 731=732')) $rule
                        $t2=Send-Probe (Set-PWQueryValue $item.Url $p.Index ($p.Value+' AND 947=947')) $rule
                        $f2=Send-Probe (Set-PWQueryValue $item.Url $p.Index ($p.Value+' AND 947=948')) $rule
                        if($t1 -and $f1 -and $t2 -and $f2){
                            $all=@($base,$t1,$f1,$t2,$f2)
                            if(@($all|Where-Object {$_.Truncated -or $_.Status -lt 200 -or $_.Status -ge 300}).Count -eq 0 -and (Get-PWBodyDigest $t1.Body) -eq $digest -and (Get-PWBodyDigest $t2.Body) -eq $digest -and (Get-PWBodyDigest $f1.Body) -eq (Get-PWBodyDigest $f2.Body) -and (Get-PWBodyDigest $f1.Body) -ne $digest){Add-NativeFinding $rule 'Suspected SQL injection via boolean response pattern' 'Hoch' $item.Url $p.Name 'Mittel' 'Repeated true conditions match the stable baseline; false conditions produce a different stable response. Alternative application logic remains possible.' 'Review the query and parameter binding in the backend; confirm the finding manually.' @((Evidence $base 'Base'),(Evidence $repeat 'Base repeat'),(Evidence $t1 'True A'),(Evidence $f1 'False A'),(Evidence $t2 'True B'),(Evidence $f2 'False B'))}
                        }else{$completed=$false}
                    }
                    'PW-TEMPLATE'{
                        foreach($syntax in @('mustache','dollar')){
                            $mark='PW'+[Guid]::NewGuid().ToString('N').Substring(0,10)
                            $a=if($syntax -eq 'mustache'){'{{37*41}}'}else{'${37*41}'};$b=if($syntax -eq 'mustache'){'{{43*47}}'}else{'${43*47}'}
                            $ra=Send-Probe (Set-PWQueryValue $item.Url $p.Index ($mark+$a+'END')) $rule
                            $rb=Send-Probe (Set-PWQueryValue $item.Url $p.Index ($mark+$b+'END')) $rule
                            if($ra -and $rb){if($ra.Body.Contains($mark+'1517END') -and $rb.Body.Contains($mark+'2021END')){Add-NativeFinding $rule 'Template evaluation observed in the response text' 'Hoch' $item.Url $p.Name 'High (evaluation)' "Two different arithmetic expressions were evaluated inside unique markers ($syntax). No further code execution tested." 'Treat user input as data, not as a template; rule out an intended calculation feature.' @((Evidence $base 'Base'),(Evidence $ra 'Calculation A' ($mark+'1517END')),(Evidence $rb 'Calculation B' ($mark+'2021END')))}}else{$completed=$false}
                        }
                    }
                    'PW-HTML'{
                        $mark='PW'+[Guid]::NewGuid().ToString('N').Substring(0,10);$payload='<pw-probe data-pw="'+$mark+'">'
                        $r=Send-Probe (Set-PWQueryValue $item.Url $p.Index $payload) $rule
                        if($r){if($r.Headers['Content-Type'] -match '(?i)text/html' -and $r.Body.Contains($payload)){Add-NativeFinding $rule 'Unencoded HTML reflection' 'Niedrig' $item.Url $p.Name 'Mittel' 'An inert HTML element appears unchanged in the response text. No DOM or XSS evidence.' 'Review the output context manually and use context-appropriate encoding.' @((Evidence $base 'Base'),(Evidence $r 'HTML marker' $payload))}}else{$completed=$false}
                    }
                    'PW-REDIRECT'{
                        $evidence=@();$hits=0
                        foreach($i in 1,2){$hostName='pw-'+[Guid]::NewGuid().ToString('N')+'.invalid';$payload='https://'+$hostName+'/probe';$r=Send-Probe (Set-PWQueryValue $item.Url $p.Index $payload) $rule
                            if($r){if($r.Status -ge 300 -and $r.Status -lt 400 -and $r.Headers['Location']){try{$dest=[Uri]::new([Uri]$item.Url,$r.Headers['Location']);if($dest.Host -eq $hostName){$hits++;$evidence+=,(Evidence $r "Redirect $i")}}catch{}}}else{$completed=$false}
                        }
                        if($hits -eq 2){Add-NativeFinding $rule 'Redirect to arbitrary external targets' 'Mittel' $item.Url $p.Name 'High (redirect)' 'Two random external hosts were accepted as the Location target. No target was requested.' 'Restrict redirect targets to allowed local paths or a fixed allowlist.' (@((Evidence $base 'Base'))+$evidence)}
                    }
                    'PW-CRLF'{
                        $evidence=@();$hits=0
                        foreach($i in 1,2){$mark='PW'+[Guid]::NewGuid().ToString('N');$r=Send-Probe (Set-PWQueryValue $item.Url $p.Index ($p.Value+"`r`nX-PowerWEB-Probe: "+$mark)) $rule
                            if($r){if($r.Headers['X-PowerWEB-Probe'] -ceq $mark){$hits++;$evidence+=,(Evidence $r "Header marker $i")}}else{$completed=$false}
                        }
                        if($hits -eq 2){Add-NativeFinding $rule 'Query value creates an extra response header' 'Hoch' $item.Url $p.Name 'High (header injection)' 'Two unique CRLF test markers appear as real X-PowerWEB-Probe headers.' 'Reject CR/LF in header values and use safe header APIs.' (@((Evidence $base 'Base'))+$evidence)}
                    }
                }
                if($bodyRule -and $stats.PartialResponses -gt $partialBefore){$completed=$false}
                if($findings.Count -eq $before -and -not $recorded){Record-Test $rule $item.Url $p.Name $(if($completed){'No evidence'}else{'Incomplete'})}
            }
        }
    }
    $status=if($Control.Cancel){'Cancelled'}elseif($stats.Limited -or ($queue.Count -gt 0 -and $stats.Pages -ge $MaxPages)){'Limit reached'}elseif($stats.Errors){'Completed with errors'}elseif(@($tests|Where-Object Ergebnis -eq 'Incomplete').Count){'Some checks incomplete'}else{'Finished'}
    [pscustomobject]@{Findings=$findings.ToArray();History=$history.ToArray();Tests=$tests.ToArray();Summary=[pscustomobject]@{Typ='Native engine';Version='4.0';StartUtc=$start.ToString('o');EndeUtc=[DateTime]::UtcNow.ToString('o');Scope=(Protect-PWUrl $ScopeUrl @($secrets));Status=$status;Seiten=$stats.Pages;Anfragen=$stats.Requests;Fehler=$stats.Errors;MaxAnfragen=$MaxRequests;MaxSeiten=$MaxPages;MaxParameter=$MaxParameters;MaxMinuten=$MaxMinutes;RestQueue=$queue.Count;Regeln=$Rules;Pruefungen=$tests.ToArray();Hinweis='GET query parameters and headers only; no stored/DOM-based XSS, upload, JSON body or business-logic tests. No evidence does not mean safe. Evidence masks known secrets; review before sharing.'}}
}

function Invoke-PWRoleComparison {
    [CmdletBinding()]
    param([string]$Url,[string]$ScopeUrl,[hashtable]$HeadersA=@{},[hashtable]$HeadersB=@{},[Net.CookieContainer]$CookiesA,[Net.CookieContainer]$CookiesB,[string[]]$Exclude=@(),[int]$TimeoutSeconds=15,[hashtable]$Control)
    $a=Invoke-PWHttp -Url $Url -ScopeUrl $ScopeUrl -Headers $HeadersA -CookieContainer $CookiesA -Exclude $Exclude -TimeoutSeconds $TimeoutSeconds -Control $Control
    $b=Invoke-PWHttp -Url $Url -ScopeUrl $ScopeUrl -Headers $HeadersB -CookieContainer $CookiesB -Exclude $Exclude -TimeoutSeconds $TimeoutSeconds -Control $Control
    $comparable=$a.BodyRead -and $b.BodyRead -and -not $a.Truncated -and -not $b.Truncated
    [pscustomobject]@{Url=(Protect-PWUrl $Url);StatusA=$a.Status;StatusB=$b.Status;TextVergleichbar=$comparable;TextGleich=$(if($comparable){(Get-PWBodyDigest $a.Body) -eq (Get-PWBodyDigest $b.Body)}else{$null});TextSHA256A=$(if($a.BodyRead){Get-PWBodyDigest $a.Body}else{$null});TextSHA256B=$(if($b.BodyRead){Get-PWBodyDigest $b.Body}else{$null});BytesA=$a.BytesRead;BytesB=$b.BytesRead;Gekuerzt=($a.Truncated -or $b.Truncated);Hinweis='Comparison hint, not automatic proof of an authorization flaw. TextGleich stays empty without two complete text responses. Assess roles and expected access manually.'}
}
# --- Intruder-artige Anfragemodifikation (mehrere Positionen, eigene Payload-Sets) ---
# Positionen werden mit Paaren aus dem Trennzeichen Paragraph markiert: TEXT steht
# zwischen zwei Markern, z. B. id=<S>1<S> (hier als <S> dargestellt). Der markierte
# Text ist der Basiswert und wird im Angriff ersetzt. Reihenfolge der Positionen:
# zuerst URL, dann Header, dann Body. Alles laeuft ueber Invoke-PWHttp und damit
# unter Scope-Pruefung, Header-Guards und den bestehenden Limits.
function Split-PWTemplate {
    param([string]$Template)
    # Marker aus [char]0x00A7 (Paragraphzeichen) bauen, damit der Quelltext reines
    # ASCII bleibt und die Modul-Datei encodingunabhaengig geladen wird.
    $sep=[string][char]0x00A7
    $rx=[regex]::new($sep+'([^'+$sep+']*)'+$sep)
    $literals=[Collections.Generic.List[string]]::new()
    $bases=[Collections.Generic.List[string]]::new()
    $last=0
    foreach ($m in $rx.Matches($Template)) {
        $literals.Add($Template.Substring($last,$m.Index-$last))
        $bases.Add($m.Groups[1].Value)
        $last=$m.Index+$m.Length
    }
    $literals.Add($Template.Substring($last))
    [pscustomobject]@{ Literals=$literals.ToArray(); Bases=$bases.ToArray(); Count=$bases.Count }
}
function Render-PWTemplate {
    param($Parsed,[object[]]$Values,[bool]$Encode)
    $sb=[Text.StringBuilder]::new()
    for ($i=0; $i -lt $Parsed.Count; $i++) {
        [void]$sb.Append($Parsed.Literals[$i])
        $v=[string]$Values[$i]
        [void]$sb.Append($(if ($Encode) { [Uri]::EscapeDataString($v) } else { $v }))
    }
    [void]$sb.Append($Parsed.Literals[$Parsed.Count])
    $sb.ToString()
}

# Optional grep on a response body: Match yields yes/no, Extract yields the first
# capture group (or whole match), capped in length. Used by intruder and data table.
function Get-PWGrep {
    param([string]$Body,[string]$Match,[string]$Extract)
    $m=''; $x=''
    if ($Match) { try { $m=if ([regex]::IsMatch($Body,$Match)) { 'yes' } else { 'no' } } catch { $m='rx?' } }
    if ($Extract) {
        try { $mm=[regex]::Match($Body,$Extract)
            if ($mm.Success) { $x=if ($mm.Groups.Count -gt 1 -and $mm.Groups[1].Success) { $mm.Groups[1].Value } else { $mm.Value } }
        } catch { $x='rx?' }
        if ($x.Length -gt 200) { $x=$x.Substring(0,200) }
    }
    [pscustomobject]@{ Match=$m; Extract=$x }
}

function Get-PWIntruderPreview {
    [CmdletBinding()]
    param([string]$UrlTemplate,[string]$HeadersTemplate='',[string]$BodyTemplate='',
        [ValidateSet('Sniper','BatteringRam','Pitchfork','ClusterBomb')][string]$Mode='Sniper',
        [object[]]$PayloadSets=@(),[ValidateRange(1,5000)][int]$MaxRequests=200)
    $marker=[string][char]0x00A7
    $positions=[Collections.Generic.List[object]]::new()
    foreach($part in @(@('URL',$UrlTemplate),@('Headers',$HeadersTemplate),@('Body',$BodyTemplate))){
        $parsed=Split-PWTemplate $part[1]
        if ([regex]::Matches($part[1],[regex]::Escape($marker)).Count -ne 2*$parsed.Count) { throw "Unpaired position marker in $($part[0])." }
        foreach($base in $parsed.Bases){$positions.Add([pscustomobject]@{Number=$positions.Count+1;Field=$part[0];Base=$base})}
    }
    if($positions.Count -lt 1 -or $positions.Count -gt 8){throw 'Mark between one and eight positions.'}
    $sets=@(foreach($set in $PayloadSets){,@($set)})
    foreach($set in $sets){if($set.Count -gt 1000){throw 'A payload set may contain at most 1000 values.'};foreach($value in $set){if(([string]$value).Length -gt 2048){throw 'A payload may contain at most 2048 characters.'}}}
    if($Mode -in @('Sniper','BatteringRam')){if($sets.Count -lt 1 -or $sets[0].Count -lt 1){throw 'Enter values in set 1.'}}
    else {
        if($sets.Count -lt $positions.Count){throw "This mode needs $($positions.Count) payload sets; the interface provides four."}
        for($i=0;$i -lt $positions.Count;$i++){if($sets[$i].Count -lt 1){throw "Enter values in set $($i+1)."}}
    }
    $estimated=[decimal]0
    switch($Mode){
        'Sniper' {$estimated=$positions.Count*$sets[0].Count}
        'BatteringRam' {$estimated=$sets[0].Count}
        'Pitchfork' {$estimated=($sets[0..($positions.Count-1)]|ForEach-Object Count|Measure-Object -Minimum).Minimum}
        'ClusterBomb' {$estimated=1;for($i=0;$i -lt $positions.Count;$i++){$estimated*=$sets[$i].Count}}
    }
    [pscustomobject]@{Positionen=$positions.ToArray();Gesamt=$estimated;Geplant=[int][Math]::Min($estimated,$MaxRequests);Begrenzt=$estimated -gt $MaxRequests;Modus=$Mode}
}

function Invoke-PWIntruder {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$ScopeUrl='',
        [Parameter(Mandatory)][string]$UrlTemplate,
        [ValidateSet('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS')][string]$Method='GET',
        [string]$HeadersTemplate='',[string]$BodyTemplate='',
        [ValidateSet('Sniper','BatteringRam','Pitchfork','ClusterBomb')][string]$Mode='Sniper',
        [object[]]$PayloadSets=@(),[hashtable]$Headers=@{},[string[]]$Exclude=@(),
        [ValidateRange(0,10000)][int]$DelayMs=250,[ValidateRange(1,60)][int]$TimeoutSeconds=15,
        [ValidateRange(1,5000)][int]$MaxRequests=200,[switch]$EncodeUrl,[switch]$AllowStateChanging,
        [string]$GrepMatch='',[string]$GrepExtract='',
        [Net.CookieContainer]$CookieContainer,[hashtable]$Control)
    if (-not $Control) { $Control=[hashtable]::Synchronized(@{Cancel=$false;Request=$null;Message=''}) }
    if ($Method -in @('POST','PUT','PATCH','DELETE') -and -not $AllowStateChanging) { throw 'Enable state-changing requests in the intruder first.' }
    if ($BodyTemplate -and $Method -in @('GET','HEAD')) { throw 'GET/HEAD are sent without a request body; change the method or clear the body.' }

    $urlP=Split-PWTemplate $UrlTemplate
    $hdrP=Split-PWTemplate $HeadersTemplate
    $bodyP=Split-PWTemplate $BodyTemplate
    $total=$urlP.Count+$hdrP.Count+$bodyP.Count
    $preview=Get-PWIntruderPreview -UrlTemplate $UrlTemplate -HeadersTemplate $HeadersTemplate -BodyTemplate $BodyTemplate -Mode $Mode -PayloadSets $PayloadSets -MaxRequests $MaxRequests
    if ($total -lt 1) { throw 'No position marked. Mark text with a pair of section signs, e.g. id=' + [char]0x00A7 + '1' + [char]0x00A7 + '.' }
    if ($total -gt 8) { throw 'At most 8 positions are supported.' }

    # Payload-Sets normalisieren und pruefen.
    $sets=@(); foreach ($s in $PayloadSets) { $sets+=,@($s) }
    foreach ($s in $sets) {
        if ($s.Count -gt 1000) { throw 'A payload set may hold at most 1000 values.' }
        foreach ($p in $s) { if ([string]$p -and ([string]$p).Length -gt 2048) { throw 'A payload may hold at most 2048 characters.' } }
    }
    if ($Mode -in @('Sniper','BatteringRam')) {
        if ($sets.Count -lt 1 -or -not $sets[0].Count) { throw 'Set 1 has no payloads.' }
    } else {
        if ($sets.Count -lt $total) { throw ("Mode {0} needs {1} payload set(s), one per position." -f $Mode,$total) }
        for ($p=0; $p -lt $total; $p++) { if (-not $sets[$p].Count) { throw ("Set {0} (position {0}) has no payloads." -f ($p+1)) } }
    }

    $baseGlobal=@($urlP.Bases)+@($hdrP.Bases)+@($bodyP.Bases)
    $gen=@{ Limited=$false }
    $plan=[Collections.Generic.List[object]]::new()
    function Add-Plan([object[]]$Values,[string[]]$Payloads,[int[]]$Positions) {
        if ($plan.Count -ge $MaxRequests) { $gen.Limited=$true; return }
        $plan.Add([pscustomobject]@{ Values=$Values; Payloads=$Payloads; Positions=$Positions })
    }
    switch ($Mode) {
        'Sniper' {
            $allPos=@(0..($total-1))
            foreach ($p in $allPos) {
                foreach ($pl in $sets[0]) {
                    $v=@($baseGlobal.Clone()); $v[$p]=$pl
                    Add-Plan $v @([string]$pl) @($p)
                    if ($gen.Limited) { break }
                }
                if ($gen.Limited) { break }
            }
        }
        'BatteringRam' {
            foreach ($pl in $sets[0]) {
                $v=@(); for ($i=0;$i -lt $total;$i++) { $v+=[string]$pl }
                Add-Plan $v @([string]$pl) @(0..($total-1))
                if ($gen.Limited) { break }
            }
        }
        'Pitchfork' {
            $min=($sets[0..($total-1)] | ForEach-Object { $_.Count } | Measure-Object -Minimum).Minimum
            for ($i=0;$i -lt $min;$i++) {
                $v=@(); $pls=@()
                for ($p=0;$p -lt $total;$p++) { $v+=[string]$sets[$p][$i]; $pls+=[string]$sets[$p][$i] }
                Add-Plan $v $pls @(0..($total-1))
                if ($gen.Limited) { break }
            }
        }
        'ClusterBomb' {
            $sizes=@(); for ($p=0;$p -lt $total;$p++) { $sizes+=$sets[$p].Count }
            $idx=New-Object 'int[]' $total
            while ($true) {
                $v=@(); $pls=@()
                for ($p=0;$p -lt $total;$p++) { $val=[string]$sets[$p][$idx[$p]]; $v+=$val; $pls+=$val }
                Add-Plan $v $pls @(0..($total-1))
                if ($gen.Limited) { break }
                $k=$total-1
                while ($k -ge 0) { $idx[$k]++; if ($idx[$k] -lt $sizes[$k]) { break }; $idx[$k]=0; $k-- }
                if ($k -lt 0) { break }
            }
        }
    }

    # Bekannte Anmelde-Geheimnisse fuer die Maskierung sammeln.
    $secrets=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($key in $Headers.Keys) {
        if ($key -match '(?i)authorization|cookie|token|secret|key') {
            [void]$secrets.Add([string]$Headers[$key]); [void]$secrets.Add(([string]$Headers[$key] -replace '^(?i)Bearer\s+',''))
            if ($key -ieq 'Cookie') { foreach ($c in ([string]$Headers[$key] -split ';')) { $pr=$c -split '=',2; if ($pr.Count -eq 2) { [void]$secrets.Add($pr[1].Trim()) } } }
        }
    }

    $rows=[Collections.Generic.List[object]]::new(); $history=[Collections.Generic.List[object]]::new()
    $start=[DateTime]::UtcNow; $sent=0
    foreach ($entry in $plan) {
        if ($Control.Cancel) { break }
        $until=[DateTime]::UtcNow.AddMilliseconds($DelayMs)
        while ([DateTime]::UtcNow -lt $until) { if ($Control.Cancel) { break }; Start-Sleep -Milliseconds 25 }
        if ($Control.Cancel) { break }
        $Control.Message=('Intruder {0}/{1}' -f ($rows.Count+1),$plan.Count)
        $vals=$entry.Values; $off=0
        $urlVals=@(); if ($urlP.Count) { $urlVals=@($vals[$off..($off+$urlP.Count-1)]) }; $off+=$urlP.Count
        $hdrVals=@(); if ($hdrP.Count) { $hdrVals=@($vals[$off..($off+$hdrP.Count-1)]) }; $off+=$hdrP.Count
        $bodyVals=@(); if ($bodyP.Count) { $bodyVals=@($vals[$off..($off+$bodyP.Count-1)]) }
        $url=Render-PWTemplate $urlP $urlVals ([bool]$EncodeUrl)
        $renderedHeaders=Render-PWTemplate $hdrP $hdrVals $false
        $renderedBody=Render-PWTemplate $bodyP $bodyVals $false
        $posText=(($entry.Positions | ForEach-Object { $_+1 }) -join ',')
        $payloadText=Protect-PWText (($entry.Payloads) -join ' | ') @($secrets)
        if (-not (Test-PWScope $url $ScopeUrl $Exclude)) {
            $rows.Add([pscustomobject]@{ Nr=($rows.Count+1); Position=$posText; Payload=$payloadText; HTTP=0; Ms=0; Bytes=0; Truncated=$false; Reflected=$false; Match=''; Extract=''; Error='Outside scope or excluded'; Url=(Protect-PWUrl $url @($secrets)) })
            continue
        }
        $reqHeaders=@{}; foreach ($k in $Headers.Keys) { $reqHeaders[$k]=$Headers[$k] }
        try { $extra=ConvertFrom-PWHeaderText $renderedHeaders } catch {
            $rows.Add([pscustomobject]@{ Nr=($rows.Count+1); Position=$posText; Payload=$payloadText; HTTP=0; Ms=0; Bytes=0; Truncated=$false; Reflected=$false; Match=''; Extract=''; Error=(Protect-PWText $_.Exception.Message @($secrets)); Url=(Protect-PWUrl $url @($secrets)) })
            continue
        }
        foreach ($k in $extra.Keys) { $reqHeaders[$k]=$extra[$k] }
        try {
            $r=Invoke-PWHttp -Url $url -ScopeUrl $ScopeUrl -Method $Method -Headers $reqHeaders -Body $renderedBody -Exclude $Exclude -TimeoutSeconds $TimeoutSeconds -Control $Control -CookieContainer $CookieContainer
            $sent++
            $reflected=$false; foreach ($pl in $entry.Payloads) { if ($pl -and $r.Body.Contains($pl)) { $reflected=$true; break } }
            $grep=Get-PWGrep $r.Body $GrepMatch $GrepExtract
            $safeUrl=Protect-PWUrl $r.Url @($secrets)
            $rows.Add([pscustomobject]@{ Nr=($rows.Count+1); Position=$posText; Payload=$payloadText; HTTP=$r.Status; Ms=$r.HeaderMs; Bytes=$r.BytesRead; Truncated=$r.Truncated; Reflected=$reflected; Match=$grep.Match; Extract=(Protect-PWText $grep.Extract @($secrets)); Error=''; Url=$safeUrl; Antwort=(Protect-PWText $r.Body.Substring(0,[Math]::Min(500,$r.Body.Length)) @($secrets)); RequestMethod=$Method;RequestUrl=$url;RequestHeaders=$renderedHeaders;RequestBody=$renderedBody })
            $history.Add([pscustomobject]@{ ZeitpunktUtc=[DateTime]::UtcNow.ToString('o'); Methode=$Method; Url=$safeUrl; Status=$r.Status; DauerMs=$r.HeaderMs; Typ='Intruder'; Fehler='' })
        } catch {
            if (-not $Control.Cancel) {
                $msg=Protect-PWText $_.Exception.Message @($secrets); $safeUrl=Protect-PWUrl $url @($secrets)
                $rows.Add([pscustomobject]@{ Nr=($rows.Count+1); Position=$posText; Payload=$payloadText; HTTP=0; Ms=0; Bytes=0; Truncated=$false; Reflected=$false; Match=''; Extract=''; Error=$msg; Url=$safeUrl })
                $history.Add([pscustomobject]@{ ZeitpunktUtc=[DateTime]::UtcNow.ToString('o'); Methode=$Method; Url=$safeUrl; Status=0; DauerMs=0; Typ='Intruder'; Fehler=$msg })
            }
        }
    }
    $status=if ($Control.Cancel) { 'Cancelled' } elseif ($gen.Limited) { 'Limit reached' } else { 'Finished' }
    $summary=[pscustomobject]@{ Typ='Intruder'; Modus=$Mode; Positionen=$total; Geplant=$plan.Count; Anfragen=$sent; Reflektiert=@($rows | Where-Object { $_.Reflected }).Count; Limitiert=$gen.Limited; StartUtc=$start.ToString('o'); EndeUtc=[DateTime]::UtcNow.ToString('o'); Scope=(Protect-PWUrl $ScopeUrl @($secrets)); Status=$status; MaxAnfragen=$MaxRequests; Hinweis='Reflection is not proof of exploitability. Payloads/URLs may be sensitive; review before sharing.' }
    [pscustomobject]@{ Rows=$rows.ToArray(); History=$history.ToArray(); Findings=@(); Summary=$summary; Cancelled=[bool]$Control.Cancel }
}

# --- Table-driven request testing ($var placeholders + a pasted value table) ---
# The request template (URL, headers, body) may contain $name placeholders. A
# table provides one column per variable (header row = names) and one test case
# per following row. Every request goes through Invoke-PWHttp and therefore under
# scope checking, header guards and the usual limits.
function ConvertFrom-PWTableText {
    # Returns @{ Columns=string[]; Rows=string[][] }. Separator auto-detected per
    # header line: tab, then semicolon, then comma.
    param([string]$Text)
    $lines=@(($Text -split '\r?\n') | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') })
    if ($lines.Count -lt 2) { throw 'The table needs a header row and at least one data row.' }
    $sep=if ($lines[0].Contains("`t")) { "`t" } elseif ($lines[0].Contains(';')) { ';' } else { ',' }
    $columns=@(($lines[0] -split [regex]::Escape($sep)) | ForEach-Object { $_.Trim() })
    if (@($columns | Where-Object { $_ }).Count -ne $columns.Count) { throw 'Empty column name in the header row.' }
    foreach ($col in $columns) { if ($col -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw "Invalid column name '$col'. Use letters, digits and underscore only." } }
    $rows=[Collections.Generic.List[object]]::new()
    for ($i=1; $i -lt $lines.Count; $i++) {
        $cells=@(($lines[$i] -split [regex]::Escape($sep)) | ForEach-Object { $_ })
        [void]$rows.Add($cells)
    }
    [pscustomobject]@{ Columns=$columns; Rows=$rows.ToArray(); Separator=$sep }
}

function Expand-PWVars {
    param([string]$Template,[hashtable]$Map,[string[]]$OrderedNames,[bool]$Encode)
    $out=$Template
    foreach ($name in $OrderedNames) {
        $val=[string]$Map[$name]
        $rep=if ($Encode) { [Uri]::EscapeDataString($val) } else { $val }
        $out=[regex]::Replace($out,'\$'+[regex]::Escape($name)+'(?![A-Za-z0-9_])',[Text.RegularExpressions.MatchEvaluator]{ param($m) $rep })
    }
    return $out
}

function Invoke-PWDataTable {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$ScopeUrl='',
        [Parameter(Mandatory)][string]$UrlTemplate,
        [ValidateSet('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS')][string]$Method='GET',
        [string]$HeadersTemplate='',[string]$BodyTemplate='',
        [Parameter(Mandatory)][string]$TableText,[hashtable]$Headers=@{},[string[]]$Exclude=@(),
        [ValidateRange(0,10000)][int]$DelayMs=250,[ValidateRange(1,60)][int]$TimeoutSeconds=15,
        [ValidateRange(1,5000)][int]$MaxRequests=500,[switch]$EncodeUrl,[switch]$AllowStateChanging,
        [string]$GrepMatch='',[string]$GrepExtract='',
        [Net.CookieContainer]$CookieContainer,[hashtable]$Control)
    if (-not $Control) { $Control=[hashtable]::Synchronized(@{Cancel=$false;Request=$null;Message=''}) }
    if ($Method -in @('POST','PUT','PATCH','DELETE') -and -not $AllowStateChanging) { throw 'Enable state-changing requests first.' }
    if ($BodyTemplate -and $Method -in @('GET','HEAD')) { throw 'GET/HEAD are sent without a request body; change the method or clear the body.' }

    $table=ConvertFrom-PWTableText $TableText
    $columns=$table.Columns
    # Longest names first so $var1 is not matched inside $var10 (the lookahead also guards this).
    $ordered=@($columns | Sort-Object -Property Length -Descending)
    $used=@($columns | Where-Object { $UrlTemplate -match ('\$'+[regex]::Escape($_)+'(?![A-Za-z0-9_])') -or $HeadersTemplate -match ('\$'+[regex]::Escape($_)+'(?![A-Za-z0-9_])') -or $BodyTemplate -match ('\$'+[regex]::Escape($_)+'(?![A-Za-z0-9_])') })
    if (-not $used.Count) { throw 'No column placeholder found. Reference a column as $name in the URL, headers or body.' }

    $secrets=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($key in $Headers.Keys) {
        if ($key -match '(?i)authorization|cookie|token|secret|key') {
            [void]$secrets.Add([string]$Headers[$key]); [void]$secrets.Add(([string]$Headers[$key] -replace '^(?i)Bearer\s+',''))
            if ($key -ieq 'Cookie') { foreach ($c in ([string]$Headers[$key] -split ';')) { $pr=$c -split '=',2; if ($pr.Count -eq 2) { [void]$secrets.Add($pr[1].Trim()) } } }
        }
    }

    $rows=[Collections.Generic.List[object]]::new(); $history=[Collections.Generic.List[object]]::new()
    $start=[DateTime]::UtcNow; $sent=0; $limited=$false; $rowNo=0
    foreach ($cells in $table.Rows) {
        if ($Control.Cancel) { break }
        if ($rows.Count -ge $MaxRequests) { $limited=$true; break }
        $rowNo++
        $map=@{}; for ($c=0; $c -lt $columns.Count; $c++) { $value=if ($c -lt $cells.Count) { [string]$cells[$c] } else { '' }; if ($value.Length -gt 2048) { throw 'A table cell may hold at most 2048 characters.' }; $map[$columns[$c]]=$value }
        $Control.Message=('Data table {0}/{1}' -f $rowNo,$table.Rows.Count)
        $until=[DateTime]::UtcNow.AddMilliseconds($DelayMs)
        while ([DateTime]::UtcNow -lt $until) { if ($Control.Cancel) { break }; Start-Sleep -Milliseconds 25 }
        if ($Control.Cancel) { break }
        $url=Expand-PWVars $UrlTemplate $map $ordered ([bool]$EncodeUrl)
        $renderedHeaders=Expand-PWVars $HeadersTemplate $map $ordered $false
        $renderedBody=Expand-PWVars $BodyTemplate $map $ordered $false
        $result=[ordered]@{ '#'=$rowNo }; foreach ($col in $columns) { $result[$col]=$map[$col] }
        if (-not (Test-PWScope $url $ScopeUrl $Exclude)) {
            $result.HTTP=0; $result.Ms=0; $result.Bytes=0; $result.Reflected=$false; $result.Match=''; $result.Extract=''; $result.Error='Outside scope or excluded'; $result.Url=(Protect-PWUrl $url @($secrets))
            $rows.Add([pscustomobject]$result); continue
        }
        $reqHeaders=@{}; foreach ($k in $Headers.Keys) { $reqHeaders[$k]=$Headers[$k] }
        try { $extra=ConvertFrom-PWHeaderText $renderedHeaders } catch {
            $result.HTTP=0; $result.Ms=0; $result.Bytes=0; $result.Reflected=$false; $result.Match=''; $result.Extract=''; $result.Error=(Protect-PWText $_.Exception.Message @($secrets)); $result.Url=(Protect-PWUrl $url @($secrets))
            $rows.Add([pscustomobject]$result); continue
        }
        foreach ($k in $extra.Keys) { $reqHeaders[$k]=$extra[$k] }
        try {
            $r=Invoke-PWHttp -Url $url -ScopeUrl $ScopeUrl -Method $Method -Headers $reqHeaders -Body $renderedBody -Exclude $Exclude -TimeoutSeconds $TimeoutSeconds -Control $Control -CookieContainer $CookieContainer
            $sent++
            $reflected=$false; foreach ($col in $used) { $v=[string]$map[$col]; if ($v -and $r.Body.Contains($v)) { $reflected=$true; break } }
            $grep=Get-PWGrep $r.Body $GrepMatch $GrepExtract
            $safeUrl=Protect-PWUrl $r.Url @($secrets)
            $result.HTTP=$r.Status; $result.Ms=$r.HeaderMs; $result.Bytes=$r.BytesRead; $result.Reflected=$reflected; $result.Match=$grep.Match; $result.Extract=(Protect-PWText $grep.Extract @($secrets)); $result.Error=''; $result.Url=$safeUrl
            $rows.Add([pscustomobject]$result)
            $history.Add([pscustomobject]@{ ZeitpunktUtc=[DateTime]::UtcNow.ToString('o'); Methode=$Method; Url=$safeUrl; Status=$r.Status; DauerMs=$r.HeaderMs; Typ='Data table'; Fehler='' })
        } catch {
            if (-not $Control.Cancel) {
                $msg=Protect-PWText $_.Exception.Message @($secrets); $safeUrl=Protect-PWUrl $url @($secrets)
                $result.HTTP=0; $result.Ms=0; $result.Bytes=0; $result.Reflected=$false; $result.Match=''; $result.Extract=''; $result.Error=$msg; $result.Url=$safeUrl
                $rows.Add([pscustomobject]$result)
                $history.Add([pscustomobject]@{ ZeitpunktUtc=[DateTime]::UtcNow.ToString('o'); Methode=$Method; Url=$safeUrl; Status=0; DauerMs=0; Typ='Data table'; Fehler=$msg })
            }
        }
    }
    $status=if ($Control.Cancel) { 'Cancelled' } elseif ($limited) { 'Request limit reached' } else { 'Finished' }
    $summary=[pscustomobject]@{ Typ='Data table'; Spalten=($columns -join ', '); Zeilen=$table.Rows.Count; Anfragen=$sent; Reflektiert=@($rows | Where-Object { $_.Reflected }).Count; Limitiert=$limited; StartUtc=$start.ToString('o'); EndeUtc=[DateTime]::UtcNow.ToString('o'); Scope=(Protect-PWUrl $ScopeUrl @($secrets)); Status=$status; MaxAnfragen=$MaxRequests; Hinweis='Reflection is not proof of exploitability. Values and URLs may be sensitive; review before sharing.' }
    [pscustomobject]@{ Rows=$rows.ToArray(); History=$history.ToArray(); Findings=@(); Summary=$summary; Cancelled=[bool]$Control.Cancel }
}

Export-ModuleMember -Function Invoke-PWNativeScan,Get-PWNativeRules,Invoke-PWRoleComparison,Protect-PWText,Protect-PWUrl,Invoke-PWIntruder,Get-PWIntruderPreview,Invoke-PWDataTable,ConvertFrom-PWTableText
