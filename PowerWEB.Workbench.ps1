# SPDX-License-Identifier: MIT
[CmdletBinding()]
param([switch]$NoShow)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase
$modulePath=Join-Path $PSScriptRoot 'PowerWEB.Audit.psm1'
Import-Module $modulePath -Force
Import-Module (Join-Path $PSScriptRoot 'PowerWEB.Scanner.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'PowerWEB.Tls.psm1') -Force
$proxyModulePath=Join-Path $PSScriptRoot 'PowerWEB.Proxy.psm1'
Import-Module $proxyModulePath -Force
Import-Module (Join-Path $PSScriptRoot 'PowerWEB.Tools.psm1') -Force
[xml]$layout=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'PowerWEB.xaml') -Raw -Encoding UTF8
$window=[Windows.Markup.XamlReader]::Load([Xml.XmlNodeReader]::new($layout))
$controls=@{}
$ns=[Xml.XmlNamespaceManager]::new($layout.NameTable); $ns.AddNamespace('x','http://schemas.microsoft.com/winfx/2006/xaml')
foreach ($node in $layout.SelectNodes('//*[@x:Name]',$ns)) { $name=$node.GetAttribute('Name','http://schemas.microsoft.com/winfx/2006/xaml'); $controls[$name]=$window.FindName($name) }
$controls.Method.ItemsSource=@('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'); $controls.Method.SelectedIndex=0
$controls.Risk.ItemsSource=@('Info','Low','Medium','High','Critical'); $controls.Risk.SelectedIndex=0
$controls.FindingStatus.ItemsSource=@('Open','Confirmed','False positive','Fixed'); $controls.FindingStatus.SelectedIndex=0
$controls.ChecklistStatus.ItemsSource=@('Open','Reviewed','Finding','Not applicable')
$controls.IntruderMethod.ItemsSource=@('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'); $controls.IntruderMethod.SelectedIndex=0
$controls.IntruderMode.ItemsSource=@('Sniper','Battering ram','Pitchfork','Cluster bomb'); $controls.IntruderMode.SelectedIndex=0
$controls.DataMethod.ItemsSource=@('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'); $controls.DataMethod.SelectedIndex=0
$controls.RepeaterMethod.ItemsSource=@('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'); $controls.RepeaterMethod.SelectedIndex=0
function Find-PWBrowser {
    # Locate an installed Chrome or Edge for the proxy's "Open browser" launcher.
    foreach ($candidate in @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe","${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe","$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe","${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe","$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe")) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return ''
}
$controls.BrowserPath.Text=Find-PWBrowser
$state=@{ Project=(New-PWProject); Worker=$null; Handle=$null; Control=$null; Kind=''; Response=$null; Baseline=$null; Finding=$null; Dirty=$false; RequestUrl=''; RequestMethod='' }
$state.CurrentSession='A'
$state.Sessions=@{A=@{Headers='';Cookies=[Net.CookieContainer]::new();Origin=''};B=@{Headers='';Cookies=[Net.CookieContainer]::new();Origin=''}}
$controls.SessionChoice.ItemsSource=@('A','B');$controls.SessionChoice.SelectedIndex=0
$timer=[Windows.Threading.DispatcherTimer]::new(); $timer.Interval=[TimeSpan]::FromMilliseconds(150)
$state.Proxy=$null; $state.ProxyPS=$null; $state.ProxyHandle=$null; $state.ProxyCurrent=$null; $state.ProxyHistCount=-1; $state.ProxyCaTrusted=$false
$state.RepeaterSlots=[Collections.Generic.List[object]]::new(); $state.RepeaterSlot=$null
$state.RequestArchive=@{}; $state.PendingReqId=''
$proxyTimer=[Windows.Threading.DispatcherTimer]::new(); $proxyTimer.Interval=[TimeSpan]::FromMilliseconds(250)

function Show-Error($ErrorRecord) { $controls.Status.Text='Error: '+$ErrorRecord.Exception.Message }
function Get-Lines([string]$Text) { @($Text -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
function Update-ProxyCaStatus($Ca) {
    $info=Get-PWCaTrustStatus $Ca
    $state.ProxyCaTrusted=[bool]$info.Installed
    $controls.ProxyCaStatus.Text=$(if ($info.Installed) { 'CA trusted for this Windows user' } else { 'CA not trusted - click Trust CA once' })
    $controls.ProxyCaStatus.ToolTip='PowerWEB CA SHA-256: '+$info.Sha256
    return $info
}
function Get-ProxyBrowserArguments([string]$Profile,[string]$ProxyAddress,[string]$Url) {
    $start=if ($Url) { $Url } else { 'about:blank' }
    @('--new-window','--incognito','--no-first-run','--no-default-browser-check',('--user-data-dir="'+$Profile+'"'),('--proxy-server="http='+$ProxyAddress+';https='+$ProxyAddress+'"'),'--proxy-bypass-list="<-loopback>"',$start)
}
function Sync-Project {
    [void]$controls.Checklist.CommitEdit([Windows.Controls.DataGridEditingUnit]::Cell,$true)
    [void]$controls.Checklist.CommitEdit([Windows.Controls.DataGridEditingUnit]::Row,$true)
    $state.Project.Name=$controls.ProjectName.Text; $state.Project.ScopeUrl=$controls.Scope.Text.Trim(); $state.Project.Notes=$controls.Notes.Text
    $state.Project.Settings=[pscustomobject]@{ MaxPages=$controls.MaxPages.Text; MaxDepth=$controls.MaxDepth.Text; DelayMs=$controls.Delay.Text; TimeoutSeconds=$controls.Timeout.Text; Active=[bool]$controls.Active.IsChecked; Seeds=@(Get-Lines $controls.Seeds.Text); Excludes=@(Get-Lines $controls.Excludes.Text) }
    $state.Project.Version='4.0'
    $ruleSelection=@{};foreach($name in @('NativeSqlError','NativeSqlBool','NativeTemplate','NativeHtml','NativeRedirect','NativeCrlf','NativeCors')){$ruleSelection[$name]=[bool]$controls[$name].IsChecked}
    $state.Project.Settings | Add-Member -NotePropertyName Native -NotePropertyValue ([pscustomobject]@{MaxPages=$controls.NativePages.Text;MaxRequests=$controls.NativeRequests.Text;MaxParameters=$controls.NativeParameters.Text;MaxMinutes=$controls.NativeMinutes.Text;Rules=[pscustomobject]$ruleSelection})
}
function Refresh-Findings {
    $term=$controls.Filter.Text
    $controls.Findings.ItemsSource=@($state.Project.Findings | Where-Object { -not $term -or (($_.Titel+' '+$_.Url+' '+$_.Risiko+' '+$_.Status).IndexOf($term,[StringComparison]::OrdinalIgnoreCase) -ge 0) })
}
function Refresh-Project {
    $controls.ProjectName.Text=$state.Project.Name; $controls.Scope.Text=$state.Project.ScopeUrl; $controls.Notes.Text=$state.Project.Notes
    $s=$state.Project.Settings; $controls.MaxPages.Text=[string]$s.MaxPages; $controls.MaxDepth.Text=[string]$s.MaxDepth; $controls.Delay.Text=[string]$s.DelayMs; $controls.Timeout.Text=[string]$s.TimeoutSeconds
    $controls.Active.IsChecked=[bool]$s.Active; $controls.Seeds.Text=$s.Seeds -join "`r`n"; $controls.Excludes.Text=$s.Excludes -join "`r`n"
    # Missing optional settings in older/new projects must not inherit a previous project.
    foreach($name in @('NativePages','NativeRequests','NativeParameters','NativeMinutes')) {
        $node=$layout.SelectSingleNode("//*[@x:Name='$name']",$ns);$controls[$name].Text=$node.GetAttribute('Text')
    }
    foreach($name in @('NativeSqlError','NativeSqlBool','NativeTemplate','NativeHtml','NativeRedirect','NativeCrlf','NativeCors')) {
        $node=$layout.SelectSingleNode("//*[@x:Name='$name']",$ns);$controls[$name].IsChecked=$node.GetAttribute('IsChecked') -eq 'True'
    }
    if($s.PSObject.Properties.Name -contains 'Native'){
        $controls.NativePages.Text=$s.Native.MaxPages;$controls.NativeRequests.Text=$s.Native.MaxRequests;$controls.NativeParameters.Text=$s.Native.MaxParameters;$controls.NativeMinutes.Text=$s.Native.MaxMinutes
        foreach($prop in $s.Native.Rules.PSObject.Properties){if($prop.Name -in @('NativeSqlError','NativeSqlBool','NativeTemplate','NativeHtml','NativeRedirect','NativeCrlf','NativeCors')){$controls[$prop.Name].IsChecked=[bool]$prop.Value}}
    }
    $controls.Checklist.ItemsSource=@($state.Project.Checklist); $controls.History.ItemsSource=@($state.Project.History); Refresh-Findings
    [void](Refresh-Sitemap)
}
function Set-Busy([bool]$Busy) {
    foreach ($name in @('Start','Send','Fuzz','Scope','ProjectName','Notes','Seeds','Excludes','MaxPages','MaxDepth','Delay','Timeout','AuthHeaders','Active','NewProject','LoadProject','SaveProject','Export','RequestUrl','Method','RequestHeaders','RequestBody','AllowWrite','FuzzUrl','Payloads')) { $controls[$name].IsEnabled=-not $Busy }
    $controls.Cancel.IsEnabled=$Busy; $controls.StopFuzz.IsEnabled=$Busy
    foreach($name in @('NativeStart','NativePages','NativeRequests','NativeParameters','NativeMinutes','NativeAuthorize','NativeSqlError','NativeSqlBool','NativeTemplate','NativeHtml','NativeRedirect','NativeCrlf','NativeCors','SessionChoice','SessionClear','SessionInfo','RoleCompare','RoleUrl')){$controls[$name].IsEnabled=-not $Busy}
    $controls.NativeCancel.IsEnabled=$Busy
    foreach($name in @('IntruderStart','IntruderPreview','IntruderToRequest','IntruderMarkUrl','IntruderMarkHeaders','IntruderMarkBody','IntruderClearMarks','IntruderMethod','IntruderUrl','IntruderFromRequest','IntruderMode','IntruderHeaders','IntruderBody','IntruderSet1','IntruderSet2','IntruderSet3','IntruderSet4','IntruderMax','IntruderEncode','IntruderAuthorize')){$controls[$name].IsEnabled=-not $Busy}
    $controls.IntruderCancel.IsEnabled=$Busy
    foreach($name in @('DataStart','DataMethod','DataUrl','DataFromRequest','DataHeaders','DataBody','DataTable','DataMax','DataEncode','DataAuthorize','DataGrepMatch','DataGrepExtract')){$controls[$name].IsEnabled=-not $Busy}
    $controls.DataCancel.IsEnabled=$Busy
    foreach($name in @('TlsStart','TlsHost','TlsPort','TlsEnumerate','TlsActiveAuthorize','TlsTimeout')){$controls[$name].IsEnabled=-not $Busy}
    $controls.TlsCancel.IsEnabled=$Busy
    foreach($name in @('IntruderGrepMatch','IntruderGrepExtract','RepeaterSlots','RepeaterNew','RepeaterDelete','RepeaterMethod','RepeaterUrl','RepeaterSend','RepeaterToIntruder','RepeaterHeaders','RepeaterBody','RepeaterAllow')){$controls[$name].IsEnabled=-not $Busy}
}
function Get-Options {
    Sync-Project
    # Scope is optional. A blank scope means "no restriction"; a filled one must be
    # a valid URL (catches typos). The origin/session-host binding only applies
    # when a scope is set, since without one there is no host to bind a session to.
    $scope=$state.Project.ScopeUrl
    if ($scope -and -not (Test-PWScope $scope $scope)) { throw 'The target scope on tab 1 is not a valid URL. Leave it empty to work without a scope.' }
    $pause=0; $timeout=0
    if (-not [int]::TryParse($controls.Delay.Text,[ref]$pause) -or $pause -lt 0 -or $pause -gt 10000) { throw 'Delay must be between 0 and 10000 ms.' }
    if (-not [int]::TryParse($controls.Timeout.Text,[ref]$timeout) -or $timeout -lt 1 -or $timeout -gt 60) { throw 'Timeout must be between 1 and 60 seconds.' }
    $session=$state.Sessions[$state.CurrentSession]
    if ($scope) {
        $origin=([Uri]$scope).GetLeftPart([UriPartial]::Authority)
        if($session.Origin -and $session.Origin -ne $origin){throw 'Session belongs to a different host/port. Clear it on tab 7 or pick another session.'}
        $session.Origin=$origin
    }
    $session.Headers=$controls.AuthHeaders.Text
    @{ ScopeUrl=$scope; Headers=(ConvertFrom-PWHeaderText $controls.AuthHeaders.Text); CookieContainer=$session.Cookies; Exclude=@(Get-Lines $controls.Excludes.Text); DelayMs=$pause; TimeoutSeconds=$timeout }
}
function Start-Worker([string]$Kind,[hashtable]$Options) {
    if ($state.Worker) { throw 'A run is already active.' }
    $state.Kind=$Kind; $state.Control=[hashtable]::Synchronized(@{ Cancel=$false; Request=$null; Message='Run starting ...' }); $Options.Control=$state.Control
    if ($Kind -eq 'Request' -or $Kind -eq 'RepeaterReq') { $state.RequestUrl=$Options.Url; $state.RequestMethod=$Options.Method }
    $state.Worker=[PowerShell]::Create()
    $code='param($module,$kind,$options) $ErrorActionPreference="Stop"; Import-Module $module -Force; Import-Module (Join-Path (Split-Path $module) "PowerWEB.Scanner.psm1") -Force; Import-Module (Join-Path (Split-Path $module) "PowerWEB.Tls.psm1") -Force; switch($kind) { "Scan" { Invoke-PWAudit @options } "Request" { Invoke-PWHttp @options } "Fuzz" { Invoke-PWFuzz @options } "Native" { Invoke-PWNativeScan @options } "Roles" { Invoke-PWRoleComparison @options } "Intruder" { Invoke-PWIntruder @options } "DataTable" { Invoke-PWDataTable @options } "RepeaterReq" { Invoke-PWHttp @options } "Tls" { Invoke-PWTlsScan @options } }'
    try {
        [void]$state.Worker.AddScript($code).AddArgument($modulePath).AddArgument($Kind).AddArgument($Options)
        $state.Handle=$state.Worker.BeginInvoke(); Set-Busy $true; $timer.Start()
    } catch { $state.Worker.Dispose(); $state.Worker=$null; Set-Busy $false; throw }
}
function Merge-Findings($Items) {
    # O(n) dedup via a key set instead of a per-item Where-Object scan plus an
    # array rebuild per addition. Same match rule: Titel case-insensitive,
    # Url/Nachweis case-sensitive (key mirrors -eq / -ceq / -ceq).
    $incoming=@($Items)
    if (-not $incoming.Count) { return }
    $sep=[char]0
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($existing in @($state.Project.Findings)) {
        [void]$seen.Add(([string]$existing.Titel).ToLowerInvariant()+$sep+[string]$existing.Url+$sep+[string]$existing.Nachweis)
    }
    $added=[Collections.Generic.List[object]]::new()
    foreach ($f in $incoming) {
        if ($seen.Add(([string]$f.Titel).ToLowerInvariant()+$sep+[string]$f.Url+$sep+[string]$f.Nachweis)) { $added.Add($f) }
    }
    if ($added.Count) { $state.Project.Findings=@($state.Project.Findings)+$added.ToArray() }
}
function Format-Response($Response) {
    $lines=[Collections.Generic.List[string]]::new()
    $lines.Add(('HTTP {0} | {1} ms to headers | {2} bytes read | Truncated: {3}' -f $Response.Status,$Response.HeaderMs,$Response.BytesRead,$Response.Truncated))
    foreach ($key in ($Response.Headers.Keys | Sort-Object)) {
        $value=if ($key -match '(?i)cookie|authorization|token|secret|key|authenticate') { '[hidden]' } else { $Response.Headers[$key] }
        $lines.Add("${key}: $value")
    }
    if ($Response.Certificate) { $lines.Add('Certificate: '+($Response.Certificate | ConvertTo-Json -Compress)) }
    $lines.Add(''); $lines.Add($Response.Body); return ($lines -join "`r`n")
}
function Show-Response($Response) { $controls.Response.Text=Format-Response $Response }
function New-PWTreeItem($Node,$ReqMap) {
    $item=[Windows.Controls.TreeViewItem]::new()
    # A node carries the richest request PowerWEB observed for its URL, so the
    # send-to buttons reconstruct the real method/headers/body, not a bare GET.
    $req=$null; if ($Node.Url -and $ReqMap.ContainsKey($Node.Url)) { $req=$ReqMap[$Node.Url] }
    $method=if ($req) { $req.Method } else { '' }
    $label=$Node.Name
    if ($method -and $method -ne 'GET') { $label='[{0}] {1}' -f $method,$label }
    if ($Node.Children.Count) { $label='{0}  ({1})' -f $label,$Node.Children.Count }
    $item.Header=$label; $item.Tag=[pscustomobject]@{ Url=$Node.Url; Req=$req }
    foreach ($child in $Node.Children) { [void]$item.Items.Add((New-PWTreeItem $child $ReqMap)) }
    if ($Node.Children.Count -le 12) { $item.IsExpanded=$true }
    return $item
}
function Get-SitemapRequestMap {
    # URL -> best-known request @{Method;Headers;Body;Full}. Full is $true when
    # headers/body are the actually observed ones (proxy or archived manual
    # request), $false when only the method/URL is known. Later, richer sources
    # win: proxy full capture and the manual request archive override a bare row.
    $map=@{}
    $skip='^(host|content-length|connection|proxy-connection|keep-alive|transfer-encoding)$'
    foreach ($row in @($state.Project.History)) {
        if (-not $row.Url) { continue }
        $u=[string]$row.Url; $m=if ($row.PSObject.Properties.Name -contains 'Methode' -and $row.Methode) { [string]$row.Methode } else { 'GET' }
        if (-not $map.ContainsKey($u)) { $map[$u]=@{ Method=$m; Headers=''; Body=''; Full=$false } }
        # A manual request keeps its full headers/body in the session archive.
        $rid=if ($row.PSObject.Properties.Name -contains 'ReqId') { [string]$row.ReqId } else { '' }
        if ($rid -and $state.RequestArchive.ContainsKey($rid)) {
            $a=$state.RequestArchive[$rid]; $map[$u]=@{ Method=$a.Method; Headers=$a.Headers; Body=$a.Body; Full=$true }
        }
    }
    foreach ($f in @($state.Project.Findings)) { if ($f.Url -and -not $map.ContainsKey([string]$f.Url)) { $map[[string]$f.Url]=@{ Method='GET'; Headers=''; Body=''; Full=$false } } }
    # Proxy history is the richest source: real method, headers and body.
    if ($state.Proxy -and $state.Proxy.History) {
        foreach ($row in @($state.Proxy.History.ToArray())) {
            if (-not $row.Url) { continue }
            $u=[string]$row.Url; $hdrs=@()
            foreach ($h in $row.FullHeaders) { if ($h.Name -inotmatch $skip) { $hdrs+=('{0}: {1}' -f $h.Name,$h.Value) } }
            $map[$u]=@{ Method=[string]$row.Methode; Headers=($hdrs -join "`r`n"); Body=[string]$row.BodyText; Full=$true }
        }
    }
    return $map
}
function Refresh-Sitemap {
    $controls.SitemapTree.Items.Clear()
    $map=Get-SitemapRequestMap
    $tree=Get-PWSitemap ([string[]]@($map.Keys))
    foreach ($root in $tree) { [void]$controls.SitemapTree.Items.Add((New-PWTreeItem $root $map)) }
    return @($tree).Count
}
function Get-SelectedSitemapNode {
    $sel=$controls.SitemapTree.SelectedItem
    if ($sel -and $sel.Tag -and $sel.Tag.Url) { return $sel.Tag }
    return $null
}
function Get-PWLineDiff($A,$B) {
    # Simple LCS-based line diff; returns unified +/-/space lines.
    # Jagged arrays (not [int[,]]) for Windows PowerShell 5.1 parser compatibility.
    $x=@($A -split '\r?\n'); $y=@($B -split '\r?\n'); $n=$x.Count; $m=$y.Count
    $lcs=@(); for ($i=0; $i -le $n; $i++) { $lcs+=,(New-Object 'int[]' ($m+1)) }
    for ($i=$n-1; $i -ge 0; $i--) {
        for ($j=$m-1; $j -ge 0; $j--) {
            if ($x[$i] -ceq $y[$j]) { $lcs[$i][$j]=$lcs[$i+1][$j+1]+1 }
            else { $a=$lcs[$i+1][$j]; $b=$lcs[$i][$j+1]; $lcs[$i][$j]=$(if ($a -ge $b) { $a } else { $b }) }
        }
    }
    $out=[Collections.Generic.List[string]]::new(); $i=0; $j=0
    while ($i -lt $n -and $j -lt $m) {
        if ($x[$i] -ceq $y[$j]) { $out.Add('  '+$x[$i]); $i++; $j++ }
        elseif ($lcs[$i+1][$j] -ge $lcs[$i][$j+1]) { $out.Add('- '+$x[$i]); $i++ }
        else { $out.Add('+ '+$y[$j]); $j++ }
    }
    while ($i -lt $n) { $out.Add('- '+$x[$i]); $i++ }
    while ($j -lt $m) { $out.Add('+ '+$y[$j]); $j++ }
    return ($out -join "`r`n")
}
$timer.Add_Tick({
    if (-not $state.Handle) { return }
    $controls.Status.Text=$state.Control.Message
    if (-not $state.Handle.IsCompleted) { return }
    $timer.Stop()
    try {
        $output=$state.Worker.EndInvoke($state.Handle)
        if ($state.Worker.HadErrors) { throw $state.Worker.Streams.Error[0] }
        if ($output.Count -lt 1) { throw 'Run returned no result.' }
        $result=$output[0]
        switch ($state.Kind) {
            'Native' {
                Merge-Findings $result.Findings;$state.Project.History=@($state.Project.History)+@($result.History);$state.Project.Runs=@($state.Project.Runs)+@($result.Summary);$controls.NativeResults.ItemsSource=@($result.Tests)
                $controls.Status.Text='Native engine: {0}; {1} requests, {2} findings. Control evidence is in the JSON/HTML report.' -f $result.Summary.Status,$result.Summary.Anfragen,@($result.Findings).Count
            }
            'Roles' {
                $state.Project.Runs=@($state.Project.Runs)+@([pscustomobject]@{Typ='Role comparison';ZeitpunktUtc=[DateTime]::UtcNow.ToString('o');Ergebnis=$result})
                $comparisonText=if($result.TextVergleichbar){[string]$result.TextGleich}else{'not comparable'}
                $controls.Status.Text='A/B: HTTP {0}/{1}; text identical: {2}; truncated: {3}. Assess expected permissions manually.' -f $result.StatusA,$result.StatusB,$comparisonText,$result.Gekuerzt
            }
            'Scan' {
                Merge-Findings $result.Findings; $state.Project.History=@($state.Project.History)+@($result.History); $state.Project.Runs=@($state.Project.Runs)+@($result.Summary)
                $controls.Status.Text='{0}: {1} pages, {2} requests, {3} errors. {4} URLs still queued. Findings on tab 2.' -f $result.Summary.Status,$result.Summary.Seiten,$result.Summary.Anfragen,$result.Summary.Fehler,$result.Summary.RestQueue
            }
            'Request' {
                $state.Response=$result; Show-Response $result; Merge-Findings @(Get-PWPassiveFindings $result)
                $state.Project.History=@($state.Project.History)+@([pscustomobject]@{ ZeitpunktUtc=[DateTime]::UtcNow.ToString('o'); Methode=$result.Method; Url=$result.Url; Status=$result.Status; DauerMs=$result.HeaderMs; Typ='Manual'; Fehler=''; ReqId=$state.PendingReqId })
                $controls.Status.Text='Response received. HTTP '+$result.Status
            }
            'RepeaterReq' {
                if ($state.RepeaterSlot) { $state.RepeaterSlot.Response=(Format-Response $result) }
                $controls.RepeaterResponse.Text=Format-Response $result
                $state.Project.History=@($state.Project.History)+@([pscustomobject]@{ ZeitpunktUtc=[DateTime]::UtcNow.ToString('o'); Methode=$result.Method; Url=$result.Url; Status=$result.Status; DauerMs=$result.HeaderMs; Typ='Repeater'; Fehler='' })
                $controls.Status.Text='Repeater response. HTTP '+$result.Status
            }
            'Fuzz' {
                $controls.FuzzResults.ItemsSource=@($result.Rows); Merge-Findings $result.Findings; $state.Project.History=@($state.Project.History)+@($result.History)
                $state.Project.Runs=@($state.Project.Runs)+@([pscustomobject]@{ Typ='Parameter test'; EndeUtc=[DateTime]::UtcNow.ToString('o'); Scope=$state.Project.ScopeUrl; Anfragen=@($result.History).Count; Abgebrochen=$result.Cancelled; Ergebnisse=$result.Rows })
                $controls.Status.Text=if ($result.Cancelled) { 'Parameter test cancelled; partial results kept.' } else { 'Parameter test finished. Results are hints, not proof of exploitability.' }
            }
            'Intruder' {
                $controls.IntruderResults.ItemsSource=@($result.Rows); $state.Project.History=@($state.Project.History)+@($result.History); $state.Project.Runs=@($state.Project.Runs)+@($result.Summary)
                $controls.Status.Text='Intruder ({0}): {1} requests, {2} with reflection. {3}' -f $result.Summary.Modus,$result.Summary.Anfragen,$result.Summary.Reflektiert,$result.Summary.Status
            }
            'DataTable' {
                $controls.DataResults.ItemsSource=@($result.Rows); $state.Project.History=@($state.Project.History)+@($result.History); $state.Project.Runs=@($state.Project.Runs)+@($result.Summary)
                $controls.Status.Text='Data table: {0} rows, {1} requests, {2} with reflection. {3}' -f $result.Summary.Zeilen,$result.Summary.Anfragen,$result.Summary.Reflektiert,$result.Summary.Status
            }
            'Tls' {
                Merge-Findings $result.Findings; $state.Project.History=@($state.Project.History)+@($result.History)
                # Keep the whole result in Runs so protocols, ciphers, certificate and
                # vulnerabilities appear in the exported report (JSON dump of runs).
                $state.Project.Runs=@($state.Project.Runs)+@([pscustomobject]@{ Typ='TLS scan'; ZeitpunktUtc=[DateTime]::UtcNow.ToString('o'); Summary=$result.Summary; Protocols=$result.Protocols; Certificate=$result.Certificate; Vulnerabilities=$result.Vulnerabilities })
                $controls.TlsProtocols.ItemsSource=@($result.Protocols | ForEach-Object { [pscustomobject]@{ Protokoll=$_.Name; Unterstuetzt=$_.Supported; Ciphers=@($_.Ciphers).Count } })
                $controls.TlsCiphers.ItemsSource=@($result.Protocols | ForEach-Object { $_.Ciphers } | Sort-Object Id -Unique | ForEach-Object { [pscustomobject]@{ ID=$_.IdHex; Name=$_.Name; Kx=$_.Kx; Enc=$_.Enc; Bits=$_.Bits; PFS=$_.PFS; Flags=($_.Flags -join ','); Weak=(@($_.Flags | Where-Object { $_ -in @('NULL','ANON','EXPORT','RC4','DES','3DES','MD5') }).Count -gt 0) } })
                $controls.TlsVulns.ItemsSource=@($result.Vulnerabilities)
                $controls.TlsCert.Text=if ($result.Certificate) { ($result.Certificate | Format-List | Out-String).Trim() } else { 'No certificate retrieved.' }
                $controls.TlsSummary.Text='TLS scan {0}: rating {1}; protocols: {2}; {3} cipher(s); {4} finding(s) added to tab 2.' -f $result.Summary.Status,$result.Summary.Rating,$result.Summary.Protokolle,$result.Summary.Ciphers,@($result.Findings).Count
                $controls.Status.Text=$controls.TlsSummary.Text
            }
        }
        $state.Dirty=$true; Refresh-Findings; $controls.History.ItemsSource=@($state.Project.History)
    } catch {
        if ($state.Kind -eq 'Request' -or $state.Kind -eq 'RepeaterReq') {
            $state.Project.History=@($state.Project.History)+@([pscustomobject]@{ ZeitpunktUtc=[DateTime]::UtcNow.ToString('o'); Methode=$state.RequestMethod; Url=$state.RequestUrl; Status=0; DauerMs=0; Typ=$(if($state.Kind -eq 'RepeaterReq'){'Repeater'}else{'Manual'}); Fehler=$_.Exception.Message })
            $state.Dirty=$true; $controls.History.ItemsSource=@($state.Project.History)
        }
        if ($state.Control.Cancel) { $controls.Status.Text='Request cancelled.' } else { Show-Error $_ }
    }
    finally { $state.Worker.Dispose(); $state.Worker=$null; $state.Handle=$null; Set-Busy $false }
})
$controls.Start.Add_Click({
    try {
        $options=Get-Options; $pages=0; $depth=0
        if (-not $options.ScopeUrl) { throw 'A crawl needs a target scope on tab 1 to know where to start. For scope-free work use Requests, Repeater, Intruder, Data table or the proxy.' }
        if (-not [int]::TryParse($controls.MaxPages.Text,[ref]$pages) -or $pages -lt 1 -or $pages -gt 200) { throw 'Max pages must be between 1 and 200.' }
        if (-not [int]::TryParse($controls.MaxDepth.Text,[ref]$depth) -or $depth -lt 0 -or $depth -gt 10) { throw 'Link depth must be between 0 and 10.' }
        $options.MaxPages=$pages; $options.MaxDepth=$depth; $options.SeedUrls=@(Get-Lines $controls.Seeds.Text); $options.Active=[bool]$controls.Active.IsChecked; Start-Worker 'Scan' $options
    } catch { Show-Error $_ }
})
$cancel={
    if ($state.Control) {
        $state.Control.Cancel=$true; $state.Control.Message='Cancellation requested; partial results are kept ...'
        $request=$state.Control.Request; if ($request) { try { $request.Abort() } catch { } }
    }
}
$controls.Cancel.Add_Click($cancel); $controls.StopFuzz.Add_Click($cancel)
$controls.NativeCancel.Add_Click($cancel)
$controls.IntruderCancel.Add_Click($cancel)
$controls.DataCancel.Add_Click($cancel)
$controls.TlsCancel.Add_Click($cancel)
$controls.TlsStart.Add_Click({
    try {
        $hostText=$controls.TlsHost.Text.Trim()
        if (-not $hostText) { $scopeText=$controls.Scope.Text.Trim(); if ($scopeText) { $hostText=$scopeText } }
        if (-not $hostText) { throw 'Enter a host (or set a target scope on tab 1).' }
        $port=0; if (-not [int]::TryParse($controls.TlsPort.Text,[ref]$port) -or $port -lt 1 -or $port -gt 65535) { throw 'Port must be between 1 and 65535.' }
        $timeout=0; if (-not [int]::TryParse($controls.TlsTimeout.Text,[ref]$timeout) -or $timeout -lt 1 -or $timeout -gt 60) { throw 'Timeout must be between 1 and 60 seconds.' }
        # A host given as a URL or host:port carries its own port; let the scanner parse it.
        $portParam=$port; if ($hostText -match '://' -or $hostText -match ':\d+$') { $portParam=0 }
        $options=@{ Target=$hostText; Port=$portParam; TimeoutSeconds=$timeout; EnumerateCiphers=[bool]$controls.TlsEnumerate.IsChecked; AllowActiveVulnChecks=[bool]$controls.TlsActiveAuthorize.IsChecked }
        $controls.TlsActiveAuthorize.IsChecked=$false
        $controls.TlsSummary.Text='TLS scan running ...'
        Start-Worker 'Tls' $options
    } catch { Show-Error $_ }
})
$controls.SessionChoice.Add_SelectionChanged({
    if($controls.SessionChoice.SelectedItem){$state.Sessions[$state.CurrentSession].Headers=$controls.AuthHeaders.Text;$state.CurrentSession=[string]$controls.SessionChoice.SelectedItem;$controls.AuthHeaders.Text=$state.Sessions[$state.CurrentSession].Headers;$controls.Status.Text='Active session: '+$state.CurrentSession}
})
$controls.SessionClear.Add_Click({$state.Sessions[$state.CurrentSession]=@{Headers='';Cookies=[Net.CookieContainer]::new();Origin=''};$controls.AuthHeaders.Text='';$controls.Status.Text='Session '+$state.CurrentSession+' cleared.'})
$controls.SessionInfo.Add_Click({$controls.Status.Text='Session {0}: {1} cookies stored (values hidden).' -f $state.CurrentSession,$state.Sessions[$state.CurrentSession].Cookies.Count})
$controls.NativeStart.Add_Click({
    try{
        if(-not $controls.NativeAuthorize.IsChecked){throw 'Authorize the active tests on tab 7 first.'}
        $options=Get-Options
        if (-not $options.ScopeUrl) { throw 'The native engine crawls the target and needs a scope on tab 1.' }
        $options.SeedUrls=@(Get-Lines $controls.Seeds.Text);$options.MaxDepth=[int]$controls.MaxDepth.Text;$options.MaxPages=[int]$controls.NativePages.Text;$options.MaxRequests=[int]$controls.NativeRequests.Text;$options.MaxParameters=[int]$controls.NativeParameters.Text;$options.MaxMinutes=[int]$controls.NativeMinutes.Text
        $map=[ordered]@{NativeSqlError='PW-SQL-ERROR';NativeSqlBool='PW-SQL-BOOL';NativeTemplate='PW-TEMPLATE';NativeHtml='PW-HTML';NativeRedirect='PW-REDIRECT';NativeCrlf='PW-CRLF';NativeCors='PW-CORS'}
        $options.Rules=@(foreach($name in $map.Keys){if($controls[$name].IsChecked){$map[$name]}})
        if(-not $options.Rules.Count){throw 'Select at least one rule.'}
        $controls.NativeAuthorize.IsChecked=$false;Start-Worker 'Native' $options
    }catch{Show-Error $_}
})
$controls.RoleCompare.Add_Click({
    try{
        $options=Get-Options
        if (-not $options.ScopeUrl) { throw 'Role comparison binds two sessions to one host and needs a scope on tab 1.' }
        $origin=([Uri]$options.ScopeUrl).GetLeftPart([UriPartial]::Authority)
        foreach($s in $state.Sessions.Values){if($s.Origin -and $s.Origin -ne $origin){throw 'Both sessions must belong to the current target host.'}}
        foreach($s in $state.Sessions.Values){$s.Origin=$origin}
        $roleOptions=@{Url=$controls.RoleUrl.Text.Trim();ScopeUrl=$options.ScopeUrl;Exclude=$options.Exclude;TimeoutSeconds=$options.TimeoutSeconds;HeadersA=(ConvertFrom-PWHeaderText $state.Sessions.A.Headers);HeadersB=(ConvertFrom-PWHeaderText $state.Sessions.B.Headers);CookiesA=$state.Sessions.A.Cookies;CookiesB=$state.Sessions.B.Cookies}
        Start-Worker 'Roles' $roleOptions
    }catch{Show-Error $_}
})
function Choose-Executable([string]$ControlName) {
    $dialog=[Microsoft.Win32.OpenFileDialog]::new(); $dialog.Filter='Programm (*.exe)|*.exe'
    if ($dialog.ShowDialog($window)) { $controls[$ControlName].Text=$dialog.FileName }
}
$controls.ChooseBrowser.Add_Click({ Choose-Executable 'BrowserPath' })
$controls.Send.Add_Click({
    try {
        $options=Get-Options; $options.Remove('DelayMs'); $options.Url=$controls.RequestUrl.Text.Trim(); $options.Method=[string]$controls.Method.SelectedItem; $options.Body=$controls.RequestBody.Text
        if ($options.Method -in @('POST','PUT','PATCH','DELETE') -and -not $controls.AllowWrite.IsChecked) { throw 'Authorize a state-changing request with the checkbox in the request editor first.' }
        $extra=ConvertFrom-PWHeaderText $controls.RequestHeaders.Text; foreach ($key in $extra.Keys) { $options.Headers[$key]=$extra[$key] }
        $reqId=[Guid]::NewGuid().ToString('N').Substring(0,10); $state.PendingReqId=$reqId
        $state.RequestArchive[$reqId]=@{ Method=$options.Method; Url=$options.Url; Headers=$controls.RequestHeaders.Text; Body=$controls.RequestBody.Text }
        $controls.AllowWrite.IsChecked=$false; Start-Worker 'Request' $options
    } catch { Show-Error $_ }
})
$controls.Fuzz.Add_Click({ try { $options=Get-Options; $options.Template=$controls.FuzzUrl.Text.Trim(); $options.Payloads=@(Get-Lines $controls.Payloads.Text); Start-Worker 'Fuzz' $options } catch { Show-Error $_ } })
$controls.IntruderFromRequest.Add_Click({
    $controls.IntruderUrl.Text=$controls.RequestUrl.Text; $controls.IntruderMethod.SelectedItem=[string]$controls.Method.SelectedItem; $controls.IntruderHeaders.Text=$controls.RequestHeaders.Text; $controls.IntruderBody.Text=$controls.RequestBody.Text
    $controls.Status.Text='Taken from tab 3. Mark positions with a pair of section signs.'
})
function Mark-IntruderSelection([string]$Name){
    $box=$controls[$Name];if($box.SelectionLength -lt 1){$controls.Status.Text='Select the value in the '+$Name+' field first.';return}
    $start=$box.SelectionStart;$length=$box.SelectionLength;$mark=[string][char]0x00A7
    $box.Text=$box.Text.Substring(0,$start)+$mark+$box.Text.Substring($start,$length)+$mark+$box.Text.Substring($start+$length)
    $box.SelectionStart=$start+1;$box.SelectionLength=$length;$controls.Status.Text='Position marked. Enter payloads and preview.'
}
$controls.IntruderMarkUrl.Add_Click({Mark-IntruderSelection 'IntruderUrl'})
$controls.IntruderMarkHeaders.Add_Click({Mark-IntruderSelection 'IntruderHeaders'})
$controls.IntruderMarkBody.Add_Click({Mark-IntruderSelection 'IntruderBody'})
$controls.IntruderClearMarks.Add_Click({foreach($name in @('IntruderUrl','IntruderHeaders','IntruderBody')){$controls[$name].Text=$controls[$name].Text.Replace(([string][char]0x00A7),'')};$controls.IntruderPlan.Text='Mark a position and enter payloads to preview.'})
function Get-IntruderPlanOptions {
    $max=0; if (-not [int]::TryParse($controls.IntruderMax.Text,[ref]$max) -or $max -lt 1 -or $max -gt 5000) { throw 'Max requests must be between 1 and 5000.' }
    $modeMap=@{ 'Sniper'='Sniper'; 'Battering ram'='BatteringRam'; 'Pitchfork'='Pitchfork'; 'Cluster bomb'='ClusterBomb' }
    $sets=@(); foreach ($n in 'IntruderSet1','IntruderSet2','IntruderSet3','IntruderSet4') { $sets+=,@(Get-Lines $controls[$n].Text) }
    while ($sets.Count -gt 1 -and -not $sets[$sets.Count-1].Count) { $sets=@($sets[0..($sets.Count-2)]) }
    @{UrlTemplate=$controls.IntruderUrl.Text.Trim();HeadersTemplate=$controls.IntruderHeaders.Text;BodyTemplate=$controls.IntruderBody.Text;Mode=$modeMap[[string]$controls.IntruderMode.SelectedItem];PayloadSets=$sets;MaxRequests=$max}
}
$controls.IntruderPreview.Add_Click({
    try {
        $plan=Get-IntruderPlanOptions;$preview=Get-PWIntruderPreview @plan
        $controls.IntruderPlan.Text='{0} positions ({1}); {2} requests planned{3}.' -f $preview.Positionen.Count,(($preview.Positionen|ForEach-Object { "$($_.Number):$($_.Field)" }) -join ', '),$preview.Geplant,$(if($preview.Begrenzt){' (request limit reached)'}else{''})
    } catch { Show-Error $_ }
})
$controls.IntruderStart.Add_Click({
    try {
        $options=Get-Options
        $m=[string]$controls.IntruderMethod.SelectedItem
        if ($m -in @('POST','PUT','PATCH','DELETE') -and -not $controls.IntruderAuthorize.IsChecked) { throw 'Authorize the state-changing method with the intruder checkbox first.' }
        $plan=Get-IntruderPlanOptions; $preview=Get-PWIntruderPreview @plan
        foreach($key in $plan.Keys){$options[$key]=$plan[$key]};$options.Method=$m
        $controls.IntruderPlan.Text='{0} positions; {1} requests planned.' -f $preview.Positionen.Count,$preview.Geplant
        $options.EncodeUrl=[bool]$controls.IntruderEncode.IsChecked; $options.AllowStateChanging=[bool]$controls.IntruderAuthorize.IsChecked
        $options.GrepMatch=$controls.IntruderGrepMatch.Text; $options.GrepExtract=$controls.IntruderGrepExtract.Text
        $controls.IntruderAuthorize.IsChecked=$false
        Start-Worker 'Intruder' $options
    } catch { Show-Error $_ }
})
$controls.IntruderResults.Add_SelectionChanged({$row=$controls.IntruderResults.SelectedItem;$controls.IntruderResponse.Text=if($row){[string]$row.Antwort}else{''}})
$controls.IntruderToRequest.Add_Click({
    $row=$controls.IntruderResults.SelectedItem
    if(-not $row -or -not $row.RequestUrl){$controls.Status.Text='Select a completed test request first.';return}
    $controls.RequestUrl.Text=$row.RequestUrl;$controls.Method.SelectedItem=$row.RequestMethod;$controls.RequestHeaders.Text=$row.RequestHeaders;$controls.RequestBody.Text=$row.RequestBody;$controls.AllowWrite.IsChecked=$false
    $controls.Tabs.SelectedIndex=2;$controls.Status.Text='Test request opened in the request editor. Review it before sending.'
})
$controls.DataFromRequest.Add_Click({
    $controls.DataUrl.Text=$controls.RequestUrl.Text; $controls.DataMethod.SelectedItem=[string]$controls.Method.SelectedItem; $controls.DataHeaders.Text=$controls.RequestHeaders.Text; $controls.DataBody.Text=$controls.RequestBody.Text
    $controls.Status.Text='Taken from tab 3. Reference table columns as $name in the URL, headers or body.'
})
$controls.DataStart.Add_Click({
    try {
        $options=Get-Options
        $m=[string]$controls.DataMethod.SelectedItem
        if ($m -in @('POST','PUT','PATCH','DELETE') -and -not $controls.DataAuthorize.IsChecked) { throw 'Authorize the state-changing method with the data-table checkbox first.' }
        $max=0; if (-not [int]::TryParse($controls.DataMax.Text,[ref]$max) -or $max -lt 1 -or $max -gt 5000) { throw 'Max requests must be between 1 and 5000.' }
        $options.UrlTemplate=$controls.DataUrl.Text.Trim(); $options.Method=$m
        $options.HeadersTemplate=$controls.DataHeaders.Text; $options.BodyTemplate=$controls.DataBody.Text
        $options.TableText=$controls.DataTable.Text; $options.MaxRequests=$max
        $options.EncodeUrl=[bool]$controls.DataEncode.IsChecked; $options.AllowStateChanging=[bool]$controls.DataAuthorize.IsChecked
        $options.GrepMatch=$controls.DataGrepMatch.Text; $options.GrepExtract=$controls.DataGrepExtract.Text
        $controls.DataAuthorize.IsChecked=$false
        Start-Worker 'DataTable' $options
    } catch { Show-Error $_ }
})
$proxyTimer.Add_Tick({
    if (-not $state.Proxy) { return }
    $controls.ProxyOpenBrowser.IsEnabled=[bool]($state.Proxy.Listening -and (-not $state.Proxy.MitmOn -or $state.ProxyCaTrusted))
    $controls.ProxyNotice.Text=$state.Proxy.LastBlock
    if ($state.Proxy.Error) { $controls.Status.Text='Proxy error: '+$state.Proxy.Error }
    elseif ($state.Proxy.Listening -and $state.Proxy.MitmOn -and -not $state.ProxyCaTrusted) { $controls.Status.Text='Proxy running. Click Trust CA once before opening Chrome or Edge.' }
    elseif ($state.Proxy.Listening) { $controls.Status.Text='{0} | requests: {1}' -f $state.Proxy.Message,$state.Proxy.Count }
    if ($state.Proxy.History.Count -ne $state.ProxyHistCount) {
        $state.ProxyHistCount=$state.Proxy.History.Count
        $controls.ProxyHistory.ItemsSource=@($state.Proxy.History.ToArray())
        if ($controls.Tabs.SelectedIndex -eq 11) { [void](Refresh-Sitemap) }
    }
    if (-not $state.ProxyCurrent -and $state.Proxy.Pending.Count -gt 0) {
        $state.ProxyCurrent=$state.Proxy.Pending.Dequeue()
        $controls.ProxyInterceptBox.Text=$state.ProxyCurrent.Raw
        $controls.ProxySubTabs.SelectedIndex=1
        $controls.ProxyForward.IsEnabled=$true; $controls.ProxyDrop.IsEnabled=$true
        $controls.Status.Text=('Intercept: {0} waiting ({1})' -f $state.ProxyCurrent.Kind,$state.ProxyCurrent.Url)
    }
})
$controls.ProxyStart.Add_Click({
    try {
        if ($state.Proxy) { throw 'Proxy is already running.' }
        Sync-Project
        $port=0; if (-not [int]::TryParse($controls.ProxyPort.Text,[ref]$port) -or $port -lt 1 -or $port -gt 65535) { throw 'Port must be between 1 and 65535.' }
        # Scope is optional for the proxy. With no scope it forwards every request;
        # with a scope set it filters by origin (and path/exclusions under MITM).
        $scope=$state.Project.ScopeUrl
        if ($scope -and -not (Test-PWScope $scope $scope)){throw 'The target scope on tab 1 is not a valid URL. Leave it empty to run the proxy without a scope.'}
        $exclude=@(Get-Lines $controls.Excludes.Text)
        $mitm=[bool]$controls.ProxyMitm.IsChecked; $rootCa=$null; $caTrust=$null
        if ($scope) { $scopeUri=[Uri]$scope; if ($scopeUri.Scheme -eq 'https' -and ($scopeUri.AbsolutePath -ne '/' -or $exclude.Count -gt 0) -and -not $mitm) { $mitm=$true; $controls.ProxyMitm.IsChecked=$true } }
        if ($mitm) { try { $rootCa=Get-PWRootCa; $caTrust=Update-ProxyCaStatus $rootCa } catch { throw ('Could not prepare the MITM CA: '+$_.Exception.Message) } }
        $proxyState=New-PWProxyState -Port $port -ScopeUrl $scope -Exclude $exclude -RulesText $controls.ProxyRules.Text -ResponseRulesText $controls.ProxyResponseRules.Text -InterceptOn ([bool]$controls.ProxyIntercept.IsChecked) -InterceptResponses ([bool]$controls.ProxyInterceptResp.IsChecked) -InterceptScopeOnly ([bool]$controls.ProxyIntScope.IsChecked) -InterceptSkipStatic ([bool]$controls.ProxyIntSkipStatic.IsChecked) -InterceptMethods (Get-ProxyInterceptMethods) -InterceptUrlContains ($controls.ProxyIntUrlContains.Text.Trim()) -InterceptUrlExcludes ($controls.ProxyIntUrlExcludes.Text) -MitmOn $mitm -RootCa $rootCa
        if ($mitm -and $scope) { $scopeHost=([Uri]$scope).Host; [void](Get-PWLeaf $proxyState $scopeHost) }
        $state.Proxy=$proxyState
        $state.ProxyHistCount=-1
        $ps=[PowerShell]::Create()
        $code='param($module,$state) $ErrorActionPreference="Stop"; Import-Module $module -Force; Start-PWProxyServer -State $state -ModulePath $module'
        [void]$ps.AddScript($code).AddArgument($proxyModulePath).AddArgument($state.Proxy)
        $state.ProxyPS=$ps; $state.ProxyHandle=$ps.BeginInvoke()
        $controls.ProxyNotice.Text=''
        $proxyTimer.Start(); $controls.ProxyStart.IsEnabled=$false; $controls.ProxyOpenBrowser.IsEnabled=$false; $controls.ProxyStop.IsEnabled=$true; $controls.ProxyMitm.IsEnabled=$false; $controls.ProxyPort.IsEnabled=$false
        $controls.Status.Text=('Proxy starting on 127.0.0.1:{0}. {1}' -f $port,$(if ($mitm) { if ($caTrust.Installed) { 'PowerWEB CA is trusted for this Windows user.' } else { 'Click Trust CA once, then reopen the test browser.' } } else { 'Set the browser proxy accordingly.' }))
    } catch { Show-Error $_ }
})
$controls.ProxyOpenBrowser.Add_Click({
    try {
        if(-not $state.Proxy -or -not $state.Proxy.Listening){throw 'Start the proxy and wait until it is listening.'}
        if ($state.Proxy.MitmOn -and -not (Update-ProxyCaStatus $state.Proxy.RootCa).Installed) { throw 'Click Trust CA once before opening the browser through the HTTPS proxy.' }
        $browserPath=$controls.BrowserPath.Text.Trim()
        if(-not (Test-Path -LiteralPath $browserPath -PathType Leaf)){throw 'Choose Chrome or Edge on the Proxy tab first.'}
        $profile=Join-Path ([IO.Path]::GetTempPath()) ('powerweb-proxy-'+[Guid]::NewGuid().ToString('N'))
        $proxyAddress='127.0.0.1:'+$state.Proxy.Port
        $arguments=@(Get-ProxyBrowserArguments $profile $proxyAddress $state.Project.ScopeUrl)
        $launched=Start-Process -FilePath $browserPath -ArgumentList $arguments -PassThru
        $controls.Status.Text='Browser opened through '+$proxyAddress+'. Temporary profile: '+$profile
    } catch { Show-Error $_ }
})
$stopProxy={
    if (-not $state.Proxy) { return }
    $state.Proxy.Stop=$true
    if ($state.ProxyCurrent) { $state.ProxyCurrent.Decision='drop'; $state.ProxyCurrent.Done=$true; $state.ProxyCurrent=$null }
    Start-Sleep -Milliseconds 120
    try { if ($state.ProxyPS) { if (-not $state.ProxyHandle.IsCompleted) { $state.ProxyPS.Stop() }; $state.ProxyPS.Dispose() } } catch {}
    $state.ProxyPS=$null; $state.ProxyHandle=$null; $state.Proxy=$null; $proxyTimer.Stop()
    $controls.ProxyForward.IsEnabled=$false; $controls.ProxyDrop.IsEnabled=$false; $controls.ProxyInterceptBox.Text=''
    $controls.ProxyStart.IsEnabled=$true; $controls.ProxyOpenBrowser.IsEnabled=$false; $controls.ProxyStop.IsEnabled=$false; $controls.ProxyMitm.IsEnabled=$true; $controls.ProxyPort.IsEnabled=$true; $controls.ProxyNotice.Text=''; $controls.Status.Text='Proxy stopped.'
}
$controls.ProxyStop.Add_Click($stopProxy)
function Get-ProxyInterceptMethods { @($controls.ProxyIntMethods.Text -split ',' | ForEach-Object { $_.Trim().ToUpperInvariant() } | Where-Object { $_ }) }
function Update-ProxyInterceptState {
    # One-line live summary of the interception mode shown on the Intercept tab.
    $on=[bool]$controls.ProxyIntercept.IsChecked; $ron=[bool]$controls.ProxyInterceptResp.IsChecked
    $conds=@()
    if ([bool]$controls.ProxyIntScope.IsChecked) { $conds+='in-scope' }
    if ([bool]$controls.ProxyIntSkipStatic.IsChecked) { $conds+='skip static' }
    $m=Get-ProxyInterceptMethods; if ($m.Count) { $conds+=('methods '+($m -join '/')) }
    if ($controls.ProxyIntUrlContains.Text.Trim()) { $conds+=('url~'+$controls.ProxyIntUrlContains.Text.Trim()) }
    if ($controls.ProxyIntUrlExcludes.Text.Trim()) { $conds+='url excludes' }
    $kinds=@(); if ($on) { $kinds+='requests' }; if ($ron) { $kinds+='responses' }
    $txt=if ($kinds.Count) { 'Intercept: '+($kinds -join ' + ') } else { 'Intercept: off (all traffic passes)' }
    if ($kinds.Count -and $conds.Count) { $txt+=' — holding only: '+($conds -join ', ') }
    elseif ($kinds.Count) { $txt+=' — holding every request' }
    $controls.ProxyInterceptState.Text=$txt
}
function Set-ProxyInterceptConditions {
    # Push the Intercept-tab conditions into the running proxy state (live).
    if ($state.Proxy) {
        $state.Proxy.InterceptScopeOnly=[bool]$controls.ProxyIntScope.IsChecked
        $state.Proxy.InterceptSkipStatic=[bool]$controls.ProxyIntSkipStatic.IsChecked
        $state.Proxy.InterceptMethods=Get-ProxyInterceptMethods
        $state.Proxy.InterceptUrlContains=$controls.ProxyIntUrlContains.Text.Trim()
        $state.Proxy.InterceptUrlExcludes=$controls.ProxyIntUrlExcludes.Text
    }
    Update-ProxyInterceptState
}
$controls.ProxyApplyRules.Add_Click({
    try {
        $requestRules=@(ConvertFrom-PWProxyRules $controls.ProxyRules.Text)
        $responseRules=@(ConvertFrom-PWProxyRules $controls.ProxyResponseRules.Text)
        if ($state.Proxy) {
        $state.Proxy.Rules=$requestRules
        $state.Proxy.ResponseRules=$responseRules
        $state.Proxy.InterceptOn=[bool]$controls.ProxyIntercept.IsChecked
        $state.Proxy.InterceptResponses=[bool]$controls.ProxyInterceptResp.IsChecked
        Set-ProxyInterceptConditions
        $controls.Status.Text=('Rules applied: {0} request, {1} response. Interception conditions updated.' -f $requestRules.Count,$responseRules.Count)
        } else { Update-ProxyInterceptState; $controls.Status.Text='Rules valid and ready for proxy start.' }
    } catch { Show-Error $_ }
})
$proxyInterceptToggle={ if ($state.Proxy) { $state.Proxy.InterceptOn=[bool]$controls.ProxyIntercept.IsChecked }; Update-ProxyInterceptState }
$controls.ProxyIntercept.Add_Checked($proxyInterceptToggle); $controls.ProxyIntercept.Add_Unchecked($proxyInterceptToggle)
$proxyInterceptRespToggle={ if ($state.Proxy) { $state.Proxy.InterceptResponses=[bool]$controls.ProxyInterceptResp.IsChecked }; Update-ProxyInterceptState }
$controls.ProxyInterceptResp.Add_Checked($proxyInterceptRespToggle); $controls.ProxyInterceptResp.Add_Unchecked($proxyInterceptRespToggle)
# Live-apply the interception conditions as the tester changes them.
$proxyCondToggle={ Set-ProxyInterceptConditions }
$controls.ProxyIntScope.Add_Checked($proxyCondToggle); $controls.ProxyIntScope.Add_Unchecked($proxyCondToggle)
$controls.ProxyIntSkipStatic.Add_Checked($proxyCondToggle); $controls.ProxyIntSkipStatic.Add_Unchecked($proxyCondToggle)
$controls.ProxyIntMethods.Add_TextChanged($proxyCondToggle)
$controls.ProxyIntUrlContains.Add_TextChanged($proxyCondToggle)
$controls.ProxyIntUrlExcludes.Add_TextChanged($proxyCondToggle)
Update-ProxyInterceptState
$controls.ProxyExportCa.Add_Click({
    try {
        [void](Get-PWRootCa); $src=Get-PWCaCertPath
        $dialog=[Microsoft.Win32.SaveFileDialog]::new(); $dialog.Filter='Certificate (*.crt)|*.crt'; $dialog.FileName='powerweb-ca.crt'
        if ($dialog.ShowDialog($window)) { Copy-Item -LiteralPath $src -Destination $dialog.FileName -Force; $controls.Status.Text='CA certificate saved. Import it into your browser/OS trust store to decrypt HTTPS.' }
        else { $controls.Status.Text='CA certificate is at: '+$src }
    } catch { Show-Error $_ }
})
$controls.ProxyTrustCa.Add_Click({
    try {
        $ca=Get-PWRootCa
        $info=Update-ProxyCaStatus $ca
        if ($info.Installed) { $controls.Status.Text='PowerWEB CA is already trusted for this Windows user.'; return }
        $message="Trust this PowerWEB CA for the current Windows user?`r`n`r`nSHA-256: $($info.Sha256)`r`n`r`nThis trust also applies to other apps in this Windows account until you remove it. Use only for authorized testing."
        $answer=[Windows.MessageBox]::Show($window,$message,'Trust PowerWEB CA',[Windows.MessageBoxButton]::YesNo,[Windows.MessageBoxImage]::Warning)
        if ($answer -ne [Windows.MessageBoxResult]::Yes) { return }
        $after=Add-PWCaTrust $ca
        if (-not $after.Installed) { throw 'PowerWEB CA was not added to Current User Trusted Root Certification Authorities.' }
        [void](Update-ProxyCaStatus $ca)
        $controls.Status.Text='PowerWEB CA trusted once for this Windows user. Reopen the test browser; individual page exceptions are no longer needed.'
    } catch { Show-Error $_ }
})
$controls.ProxyRemoveCaTrust.Add_Click({
    try {
        $ca=Get-PWRootCa
        $after=Remove-PWCaTrust $ca
        if ($after.Installed) { throw 'PowerWEB CA remains in the current-user Root store.' }
        [void](Update-ProxyCaStatus $ca)
        $controls.Status.Text='PowerWEB CA trust removed for this Windows user. Reopen the browser.'
    } catch { Show-Error $_ }
})
$controls.ProxyForward.Add_Click({
    if ($state.ProxyCurrent) { $state.ProxyCurrent.Edited=$controls.ProxyInterceptBox.Text; $state.ProxyCurrent.Decision='forward'; $state.ProxyCurrent.Done=$true; $state.ProxyCurrent=$null; $controls.ProxyInterceptBox.Text=''; $controls.ProxyForward.IsEnabled=$false; $controls.ProxyDrop.IsEnabled=$false }
})
$controls.ProxyDrop.Add_Click({
    if ($state.ProxyCurrent) { $state.ProxyCurrent.Decision='drop'; $state.ProxyCurrent.Done=$true; $state.ProxyCurrent=$null; $controls.ProxyInterceptBox.Text=''; $controls.ProxyForward.IsEnabled=$false; $controls.ProxyDrop.IsEnabled=$false }
})
$controls.ProxyToRepeater.Add_Click({
    $row=$controls.ProxyHistory.SelectedItem
    if (-not $row) { $controls.Status.Text='Select a row in the proxy history first.'; return }
    if($row.Methode -eq 'CONNECT'){$controls.Status.Text='Select an individual HTTP request rather than a CONNECT tunnel.';return}
    $hdrs=@(); foreach ($h in $row.FullHeaders) { if ($h.Name -inotmatch '^(host|content-length|connection|proxy-connection|keep-alive|transfer-encoding)$') { $hdrs+=('{0}: {1}' -f $h.Name,$h.Value) } }
    Sync-RepeaterSlot
    $slot=[pscustomobject]@{Name=('Proxy '+($state.RepeaterSlots.Count+1));Method=$row.Methode;Url=$row.Url;Headers=($hdrs -join "`r`n");Body=[string]$row.BodyText;Response=''}
    $state.RepeaterSlots.Add($slot);Refresh-RepeaterList;$controls.RepeaterSlots.SelectedItem=$slot
    $controls.RepeaterAllow.IsChecked=$false;$controls.Tabs.SelectedIndex=10;$controls.Status.Text='Request opened in Repeater. Review it before sending.'
})
$controls.ProxyToIntruder.Add_Click({
    $row=$controls.ProxyHistory.SelectedItem
    if(-not $row -or $row.Methode -eq 'CONNECT'){$controls.Status.Text='Select an individual HTTP request in proxy history.';return}
    $hdrs=@();foreach($h in $row.FullHeaders){if($h.Name -inotmatch '^(host|content-length|connection|proxy-connection|keep-alive|transfer-encoding)$'){$hdrs+=('{0}: {1}' -f $h.Name,$h.Value)}}
    $url=$row.Url
    $match=[regex]::Match($url,'(?i)([?&](?![^=]*(?:password|token|secret|auth|session|key|signature))[^=&]+)=([^&#]*)')
    if($match.Success){$value=$match.Groups[2].Value;$url=$url.Substring(0,$match.Groups[2].Index)+([string][char]0x00A7)+$value+([string][char]0x00A7)+$url.Substring($match.Groups[2].Index+$match.Groups[2].Length)}
    $controls.IntruderUrl.Text=$url;$controls.IntruderMethod.SelectedItem=$row.Methode;$controls.IntruderHeaders.Text=$hdrs -join "`r`n";$controls.IntruderBody.Text=[string]$row.BodyText;$controls.IntruderAuthorize.IsChecked=$false
    $controls.Tabs.SelectedIndex=7;$controls.Status.Text=$(if($match.Success){'Request opened in Intruder; first query value marked. Enter payloads and preview.'}else{'Request opened in Intruder. Mark a value with section signs, then enter payloads.'})
})
$controls.ProxyHistory.Add_SelectionChanged({
    $row=$controls.ProxyHistory.SelectedItem
    $controls.ProxyDetails.Text=if($row){$row.Methode+' '+$row.Url+"`r`n"+$row.RawHeaders+"`r`n`r`n"+$row.ResponseText}else{''}
})
$controls.Baseline.Add_Click({ if ($state.Response) { $state.Baseline=$state.Response; $controls.Status.Text='Response remembered for comparison.' } })
$controls.Compare.Add_Click({
    if (-not $state.Baseline -or -not $state.Response) { $controls.Status.Text='Remember a response first, then send another request.'; return }
    $a=$state.Baseline; $b=$state.Response; $keys=@(@($a.Headers.Keys)+@($b.Headers.Keys) | Sort-Object -Unique); $changed=@($keys | Where-Object { $a.Headers[$_] -cne $b.Headers[$_] })
    $controls.Status.Text='Comparison: HTTP {0} -> {1}; bytes read {2} -> {3}; content identical: {4}; changed headers: {5}' -f $a.Status,$b.Status,$a.BytesRead,$b.BytesRead,($a.Body -ceq $b.Body),($changed -join ', ')
})
$controls.Diff.Add_Click({
    if (-not $state.Baseline -or -not $state.Response) { $controls.Status.Text='Remember a response first, then send another request.'; return }
    $controls.Response.Text=Get-PWLineDiff $state.Baseline.Body $state.Response.Body
    $controls.Status.Text='Line diff of remembered vs current response body ( - baseline, + current ).'
})
$controls.Filter.Add_TextChanged({ Refresh-Findings })
$controls.Findings.Add_SelectionChanged({
    $f=$controls.Findings.SelectedItem
    if ($f) { $state.Finding=$f; $controls.FindingTitle.Text=$f.Titel; $controls.FindingUrl.Text=$f.Url; $controls.Risk.SelectedItem=$f.Risiko; $controls.FindingStatus.SelectedItem=$f.Status; $controls.Evidence.Text=$f.Nachweis; $controls.Remedy.Text=$f.Empfehlung }
})
$controls.NewFinding.Add_Click({
    $state.Finding=$null; $controls.Findings.SelectedItem=$null; $controls.FindingTitle.Text=''; $controls.FindingUrl.Text=$controls.Scope.Text; $controls.Evidence.Text=''; $controls.Remedy.Text=''; $controls.Risk.SelectedIndex=0; $controls.FindingStatus.SelectedIndex=0
    $controls.FindingTitle.Focus() | Out-Null
})
$controls.ApplyFinding.Add_Click({
    if (-not $controls.FindingTitle.Text.Trim()) { $controls.Status.Text='Please enter a title for the finding.'; return }
    if (-not $state.Finding) {
        $state.Finding=New-PWFinding -Title $controls.FindingTitle.Text -Risk ([string]$controls.Risk.SelectedItem) -Url $controls.FindingUrl.Text -Evidence $controls.Evidence.Text -Fix $controls.Remedy.Text -Source 'Manual'
        $state.Project.Findings=@($state.Project.Findings)+@($state.Finding)
    }
    $f=$state.Finding; $f.Titel=$controls.FindingTitle.Text; $f.Url=$controls.FindingUrl.Text; $f.Risiko=[string]$controls.Risk.SelectedItem; $f.Status=[string]$controls.FindingStatus.SelectedItem; $f.Nachweis=$controls.Evidence.Text; $f.Empfehlung=$controls.Remedy.Text
    $state.Dirty=$true; Refresh-Findings; $controls.Status.Text='Finding applied. Save the project to keep it permanently.'
})
$controls.Replay.Add_Click({
    $row=$controls.History.SelectedItem
    if (-not $row) { return }
    $controls.RequestUrl.Text=$row.Url; $controls.Method.SelectedItem=$row.Methode; $controls.AllowWrite.IsChecked=$false
    $rid=if ($row.PSObject.Properties.Name -contains 'ReqId') { [string]$row.ReqId } else { '' }
    if ($rid -and $state.RequestArchive.ContainsKey($rid)) {
        $a=$state.RequestArchive[$rid]; $controls.RequestHeaders.Text=$a.Headers; $controls.RequestBody.Text=$a.Body
        $controls.Status.Text='Full request restored from this session. Review before resending.'
    } else {
        $controls.RequestBody.Text=''; $controls.Status.Text='URL and method taken over (full headers/body not archived this session). Review before sending.'
    }
    $controls.Tabs.SelectedIndex=2
})
function Sync-RepeaterSlot {
    if ($state.RepeaterSlot) {
        $state.RepeaterSlot.Method=[string]$controls.RepeaterMethod.SelectedItem
        $state.RepeaterSlot.Url=$controls.RepeaterUrl.Text; $state.RepeaterSlot.Headers=$controls.RepeaterHeaders.Text; $state.RepeaterSlot.Body=$controls.RepeaterBody.Text
    }
}
function Refresh-RepeaterList {
    $controls.RepeaterSlots.ItemsSource=$null; $controls.RepeaterSlots.DisplayMemberPath='Name'; $controls.RepeaterSlots.ItemsSource=@($state.RepeaterSlots)
}
$controls.RepeaterNew.Add_Click({
    Sync-RepeaterSlot
    $slot=[pscustomobject]@{ Name=('Slot '+($state.RepeaterSlots.Count+1)); Method='GET'; Url=$controls.Scope.Text; Headers=''; Body=''; Response='' }
    $state.RepeaterSlots.Add($slot); Refresh-RepeaterList; $controls.RepeaterSlots.SelectedItem=$slot
})
$controls.RepeaterDelete.Add_Click({
    $sel=$controls.RepeaterSlots.SelectedItem
    if ($sel) { [void]$state.RepeaterSlots.Remove($sel); $state.RepeaterSlot=$null; Refresh-RepeaterList; $controls.RepeaterResponse.Text='' }
})
$controls.RepeaterSlots.Add_SelectionChanged({
    $sel=$controls.RepeaterSlots.SelectedItem
    if ($sel) {
        $state.RepeaterSlot=$sel
        $controls.RepeaterMethod.SelectedItem=$sel.Method; $controls.RepeaterUrl.Text=[string]$sel.Url; $controls.RepeaterHeaders.Text=[string]$sel.Headers; $controls.RepeaterBody.Text=[string]$sel.Body; $controls.RepeaterResponse.Text=[string]$sel.Response
    }
})
$controls.RepeaterSend.Add_Click({
    try {
        Sync-RepeaterSlot
        if (-not $state.RepeaterSlot) { $controls.Status.Text='Create a slot first.'; return }
        $options=Get-Options; $options.Remove('DelayMs'); $options.Url=$controls.RepeaterUrl.Text.Trim(); $options.Method=[string]$controls.RepeaterMethod.SelectedItem; $options.Body=$controls.RepeaterBody.Text
        if ($options.Method -in @('POST','PUT','PATCH','DELETE') -and -not $controls.RepeaterAllow.IsChecked) { throw 'Authorize a state-changing request with the checkbox first.' }
        $extra=ConvertFrom-PWHeaderText $controls.RepeaterHeaders.Text; foreach ($key in $extra.Keys) { $options.Headers[$key]=$extra[$key] }
        $controls.RepeaterAllow.IsChecked=$false; Start-Worker 'RepeaterReq' $options
    } catch { Show-Error $_ }
})
$controls.RepeaterToIntruder.Add_Click({
    if(-not $state.RepeaterSlot){$controls.Status.Text='Select a Repeater slot first.';return}
    Sync-RepeaterSlot
    $controls.IntruderUrl.Text=$controls.RepeaterUrl.Text;$controls.IntruderMethod.SelectedItem=[string]$controls.RepeaterMethod.SelectedItem
    $controls.IntruderHeaders.Text=$controls.RepeaterHeaders.Text;$controls.IntruderBody.Text=$controls.RepeaterBody.Text;$controls.IntruderAuthorize.IsChecked=$false
    $controls.Tabs.SelectedIndex=7;$controls.Status.Text='Repeater request opened in Intruder. Mark values, then preview.'
})
# --- Sitemap tab ---
$controls.SitemapRefresh.Add_Click({ try { $n=Refresh-Sitemap; $controls.Status.Text=('Sitemap rebuilt: {0} host(s) from crawler, requests, repeater and proxy history.' -f $n) } catch { Show-Error $_ } })
function Get-NodeRequest($Node) {
    # Method/Headers/Body for a sitemap node: the observed request when known,
    # otherwise a plain GET skeleton for the node URL.
    if ($Node.Req) { return @{ Method=$Node.Req.Method; Headers=[string]$Node.Req.Headers; Body=[string]$Node.Req.Body; Full=[bool]$Node.Req.Full } }
    return @{ Method='GET'; Headers=''; Body=''; Full=$false }
}
$controls.SitemapToRequest.Add_Click({
    $node=Get-SelectedSitemapNode
    if (-not $node) { $controls.Status.Text='Select a node that carries a URL first.'; return }
    $r=Get-NodeRequest $node
    $controls.RequestUrl.Text=$node.Url; $controls.Method.SelectedItem=$r.Method; $controls.RequestHeaders.Text=$r.Headers; $controls.RequestBody.Text=$r.Body; $controls.AllowWrite.IsChecked=$false
    $controls.Tabs.SelectedIndex=2
    $controls.Status.Text=if ($r.Full) { 'Observed request sent to Requests (tab 3). Review before sending.' } else { 'URL sent to Requests (tab 3) as a {0}; no headers/body were recorded for it. Review before sending.' -f $r.Method }
})
$controls.SitemapToRepeater.Add_Click({
    $node=Get-SelectedSitemapNode
    if (-not $node) { $controls.Status.Text='Select a node that carries a URL first.'; return }
    $r=Get-NodeRequest $node; Sync-RepeaterSlot
    $slot=[pscustomobject]@{ Name=('Slot '+($state.RepeaterSlots.Count+1)); Method=$r.Method; Url=$node.Url; Headers=$r.Headers; Body=$r.Body; Response='' }
    $state.RepeaterSlots.Add($slot); Refresh-RepeaterList; $controls.RepeaterSlots.SelectedItem=$slot
    $controls.Tabs.SelectedIndex=10
    $controls.Status.Text=if ($r.Full) { 'New repeater slot from the observed request.' } else { 'New repeater slot ({0}); no headers/body were recorded for this URL.' -f $r.Method }
})
$controls.SitemapToIntruder.Add_Click({
    $node=Get-SelectedSitemapNode
    if (-not $node) { $controls.Status.Text='Select a node that carries a URL first.'; return }
    $r=Get-NodeRequest $node
    $controls.IntruderUrl.Text=$node.Url; $controls.IntruderMethod.SelectedItem=$r.Method; $controls.IntruderHeaders.Text=$r.Headers; $controls.IntruderBody.Text=$r.Body
    $controls.Tabs.SelectedIndex=7; $controls.Status.Text='Sent to Intruder. Mark positions with a pair of section signs.'
})
# Rebuild the tree whenever the Sitemap tab is opened, so it is current without
# a manual refresh. Guarded against inner Selector events bubbling up.
$controls.Tabs.Add_SelectionChanged({ param($s,$e) if ($e.OriginalSource -is [Windows.Controls.TabControl] -and $controls.Tabs.SelectedIndex -eq 11) { [void](Refresh-Sitemap) } })
$controls.SitemapImportHar.Add_Click({
    try {
        $dialog=[Microsoft.Win32.OpenFileDialog]::new(); $dialog.Filter='HAR capture (*.har)|*.har|All files (*.*)|*.*'
        if (-not $dialog.ShowDialog($window)) { return }
        $imp=Import-PWHar -Path $dialog.FileName
        $state.Project.History=@($state.Project.History)+@($imp.History)
        $created=0
        foreach ($r in $imp.Requests) {
            $slot=[pscustomobject]@{ Name=('HAR '+($state.RepeaterSlots.Count+1)); Method=$r.Method; Url=$r.Url; Headers=$r.Headers; Body=$r.Body; Response='' }
            $state.RepeaterSlots.Add($slot); $created++
        }
        Refresh-RepeaterList; $controls.History.ItemsSource=@($state.Project.History); [void](Refresh-Sitemap); $state.Dirty=$true
        $controls.Status.Text=('HAR imported: {0} history entries and {1} repeater slot(s). Review before sending.' -f @($imp.History).Count,$created)
    } catch { Show-Error $_ }
})
# --- Copy as cURL / cURL import ---
function Set-Clip([string]$Text) { try { [Windows.Clipboard]::SetText($Text); return $true } catch { return $false } }
function Copy-AsCurl([string]$Method,[string]$Url,[string]$HeadersText,[string]$Body) {
    if (-not $Url.Trim()) { $controls.Status.Text='Nothing to copy: the URL is empty.'; return }
    $curl=ConvertTo-PWCurl -Method $Method -Url $Url.Trim() -HeadersText $HeadersText -Body $Body
    if (Set-Clip $curl) { $controls.Status.Text='cURL command copied to the clipboard (secrets are copied as entered).' }
    else { $controls.Status.Text='Could not access the clipboard.' }
}
$controls.RequestCopyCurl.Add_Click({ Copy-AsCurl ([string]$controls.Method.SelectedItem) $controls.RequestUrl.Text $controls.RequestHeaders.Text $controls.RequestBody.Text })
$controls.RequestFromCurl.Add_Click({
    try {
        $text=[Windows.Clipboard]::GetText()
        if (-not $text -or $text -notmatch 'curl') { $controls.Status.Text='Copy a curl command to the clipboard first.'; return }
        $p=ConvertFrom-PWCurl $text
        if (-not $p.Url) { $controls.Status.Text='No URL found in the clipboard curl command.'; return }
        $controls.RequestUrl.Text=$p.Url; $controls.Method.SelectedItem=$p.Method; $controls.RequestHeaders.Text=$p.Headers; $controls.RequestBody.Text=$p.Body; $controls.AllowWrite.IsChecked=$false
        $controls.Tabs.SelectedIndex=2; $controls.Status.Text='Imported from clipboard curl. Review before sending.'
    } catch { Show-Error $_ }
})
$controls.RepeaterCopyCurl.Add_Click({ Sync-RepeaterSlot; Copy-AsCurl ([string]$controls.RepeaterMethod.SelectedItem) $controls.RepeaterUrl.Text $controls.RepeaterHeaders.Text $controls.RepeaterBody.Text })
$controls.RepeaterFromCurl.Add_Click({
    try {
        $text=[Windows.Clipboard]::GetText()
        if (-not $text -or $text -notmatch 'curl') { $controls.Status.Text='Copy a curl command to the clipboard first.'; return }
        $p=ConvertFrom-PWCurl $text
        if (-not $p.Url) { $controls.Status.Text='No URL found in the clipboard curl command.'; return }
        Sync-RepeaterSlot
        $slot=[pscustomobject]@{ Name=('cURL '+($state.RepeaterSlots.Count+1)); Method=$p.Method; Url=$p.Url; Headers=$p.Headers; Body=$p.Body; Response='' }
        $state.RepeaterSlots.Add($slot); Refresh-RepeaterList; $controls.RepeaterSlots.SelectedItem=$slot
        $controls.Status.Text='New repeater slot created from clipboard curl. Review before sending.'
    } catch { Show-Error $_ }
})
$controls.ProxyCopyCurl.Add_Click({
    $row=$controls.ProxyHistory.SelectedItem
    if (-not $row) { $controls.Status.Text='Select a row in the proxy history first.'; return }
    $hdrs=@(); foreach ($h in $row.FullHeaders) { if ($h.Name -inotmatch '^(host|content-length|connection|proxy-connection|keep-alive|transfer-encoding)$') { $hdrs+=('{0}: {1}' -f $h.Name,$h.Value) } }
    Copy-AsCurl ([string]$row.Methode) ([string]$row.Url) ($hdrs -join "`r`n") ([string]$row.BodyText)
})
function Save-CurrentProject {
    Sync-Project
    $dialog=[Microsoft.Win32.SaveFileDialog]::new(); $dialog.Filter='PowerWEB project (*.json)|*.json'; $dialog.FileName='PowerWEB-project.json'
    if ($dialog.ShowDialog($window)) { Save-PWProject $state.Project $dialog.FileName; $state.Dirty=$false; $controls.Status.Text='Project saved.'; return $true }
    return $false
}
function Confirm-Leave {
    if (-not $state.Dirty) { return $true }
    $answer=[Windows.MessageBox]::Show($window,'Save the project before leaving?','PowerWEB',[Windows.MessageBoxButton]::YesNoCancel)
    if ($answer -eq 'Cancel') { return $false }; if ($answer -eq 'Yes') { return (Save-CurrentProject) }; return $true
}
function Clear-PrivateState {
    foreach ($name in @('AuthHeaders','RequestHeaders','RequestBody','Response','RequestUrl','FuzzUrl','Payloads','Seeds','Filter','Evidence','Remedy','FindingTitle','FindingUrl')) { $controls[$name].Text='' }
    $controls.FuzzResults.ItemsSource=$null; $state.Response=$null; $state.Baseline=$null; $state.Finding=$null; $controls.AllowWrite.IsChecked=$false
    $state.Sessions=@{A=@{Headers='';Cookies=[Net.CookieContainer]::new();Origin=''};B=@{Headers='';Cookies=[Net.CookieContainer]::new();Origin=''}};$controls.NativeResults.ItemsSource=$null;$controls.RoleUrl.Text='';$controls.NativeAuthorize.IsChecked=$false
}
$controls.SaveProject.Add_Click({ try { [void](Save-CurrentProject) } catch { Show-Error $_ } })
$controls.LoadProject.Add_Click({
    try {
        if (-not (Confirm-Leave)) { return }
        $dialog=[Microsoft.Win32.OpenFileDialog]::new(); $dialog.Filter='PowerWEB project (*.json)|*.json'
        if ($dialog.ShowDialog($window)) { $project=Import-PWProject $dialog.FileName; Clear-PrivateState; $state.Project=$project; Refresh-Project; $state.Dirty=$false; $controls.Status.Text='Project loaded. Re-enter auth headers if needed.' }
    } catch { Show-Error $_ }
})
$controls.NewProject.Add_Click({ try { if (Confirm-Leave) { Clear-PrivateState; $state.Project=New-PWProject; Refresh-Project; $state.Dirty=$false; $controls.Status.Text='New project.' } } catch { Show-Error $_ } })
$controls.Export.Add_Click({
    try {
        Sync-Project
        $dialog=[Microsoft.Win32.SaveFileDialog]::new(); $dialog.Filter='HTML report (*.html)|*.html|JSON project (*.json)|*.json|CSV findings (*.csv)|*.csv'; $dialog.FileName='PowerWEB-report'; $dialog.AddExtension=$true
        if ($dialog.ShowDialog($window)) { $format=@('HTML','JSON','CSV')[$dialog.FilterIndex-1]; Export-PWProjectReport $state.Project $dialog.FileName $format; $controls.Status.Text='Report exported: '+$dialog.FileName }
    } catch { Show-Error $_ }
})
foreach ($name in @('ProjectName','Scope','Notes','MaxPages','MaxDepth','Delay','Timeout','Seeds','Excludes')) { $controls[$name].Add_TextChanged({ $state.Dirty=$true }) }
foreach($name in @('NativePages','NativeRequests','NativeParameters','NativeMinutes')){$controls[$name].Add_TextChanged({$state.Dirty=$true})}
foreach($name in @('NativeSqlError','NativeSqlBool','NativeTemplate','NativeHtml','NativeRedirect','NativeCrlf','NativeCors')){$controls[$name].Add_Checked({$state.Dirty=$true});$controls[$name].Add_Unchecked({$state.Dirty=$true})}
$controls.Active.Add_Checked({ $state.Dirty=$true }); $controls.Active.Add_Unchecked({ $state.Dirty=$true })
$controls.Checklist.Add_CellEditEnding({ $state.Dirty=$true })
$window.Add_Closing({ param($sender,$eventArgs)
    if ($state.Worker) { $eventArgs.Cancel=$true; $controls.Status.Text='Cancel the run first or wait for it to finish.'; return }
    if ($state.Proxy) { & $stopProxy }
    try { if (-not (Confirm-Leave)) { $eventArgs.Cancel=$true } else { $timer.Stop() } } catch { $eventArgs.Cancel=$true; Show-Error $_ }
})
Refresh-Project; $state.Dirty=$false
if (-not $NoShow) { [void]$window.ShowDialog() }
