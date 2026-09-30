# SPDX-License-Identifier: MIT
# Native, independently authored TLS/SSL scanner for PowerWEB. No OpenSSL, no
# external tools: raw ClientHello/ServerHello over a TcpClient, plus X509 parsing
# of the certificate chain the server presents. Inspired by the checks testssl.sh
# performs (protocol versions, cipher enumeration, certificate hygiene and a set
# of TLS weaknesses), reimplemented from the wire format.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PowerWEB.Audit.psm1')

# ---------------------------------------------------------------------------
# Protocol version codes (record + ClientHello.legacy_version)
# ---------------------------------------------------------------------------
$script:PWTlsVersions = [ordered]@{
    'SSLv3'   = 0x0300
    'TLS 1.0' = 0x0301
    'TLS 1.1' = 0x0302
    'TLS 1.2' = 0x0303
    'TLS 1.3' = 0x0304
}

# ---------------------------------------------------------------------------
# Cipher-suite catalogue. One line per suite:
#   hexid|Name|Kx|Au|Enc|Bits|PFS|flags
# flags is a comma list from: AEAD,CBC,RC4,3DES,DES,EXPORT,NULL,ANON,MD5,CHACHA,SEED,CAMELLIA
# The catalogue covers every security-relevant family (modern AEAD/PFS down to
# EXPORT/NULL/anon) so enumeration can classify what a server offers. It is not
# the full IANA registry; unknown IDs a server selects are still reported by id.
# ---------------------------------------------------------------------------
$script:PWCipherText = @'
1301|AES_128_GCM_SHA256|ECDHE|any|AES-GCM|128|1|AEAD
1302|AES_256_GCM_SHA384|ECDHE|any|AES-GCM|256|1|AEAD
1303|CHACHA20_POLY1305_SHA256|ECDHE|any|ChaCha20|256|1|AEAD,CHACHA
1304|AES_128_CCM_SHA256|ECDHE|any|AES-CCM|128|1|AEAD
1305|AES_128_CCM_8_SHA256|ECDHE|any|AES-CCM8|128|1|AEAD
c02b|ECDHE_ECDSA_WITH_AES_128_GCM_SHA256|ECDHE|ECDSA|AES-GCM|128|1|AEAD
c02c|ECDHE_ECDSA_WITH_AES_256_GCM_SHA384|ECDHE|ECDSA|AES-GCM|256|1|AEAD
c02f|ECDHE_RSA_WITH_AES_128_GCM_SHA256|ECDHE|RSA|AES-GCM|128|1|AEAD
c030|ECDHE_RSA_WITH_AES_256_GCM_SHA384|ECDHE|RSA|AES-GCM|256|1|AEAD
cca9|ECDHE_ECDSA_WITH_CHACHA20_POLY1305|ECDHE|ECDSA|ChaCha20|256|1|AEAD,CHACHA
cca8|ECDHE_RSA_WITH_CHACHA20_POLY1305|ECDHE|RSA|ChaCha20|256|1|AEAD,CHACHA
c023|ECDHE_ECDSA_WITH_AES_128_CBC_SHA256|ECDHE|ECDSA|AES-CBC|128|1|CBC
c024|ECDHE_ECDSA_WITH_AES_256_CBC_SHA384|ECDHE|ECDSA|AES-CBC|256|1|CBC
c027|ECDHE_RSA_WITH_AES_128_CBC_SHA256|ECDHE|RSA|AES-CBC|128|1|CBC
c028|ECDHE_RSA_WITH_AES_256_CBC_SHA384|ECDHE|RSA|AES-CBC|256|1|CBC
c009|ECDHE_ECDSA_WITH_AES_128_CBC_SHA|ECDHE|ECDSA|AES-CBC|128|1|CBC
c00a|ECDHE_ECDSA_WITH_AES_256_CBC_SHA|ECDHE|ECDSA|AES-CBC|256|1|CBC
c013|ECDHE_RSA_WITH_AES_128_CBC_SHA|ECDHE|RSA|AES-CBC|128|1|CBC
c014|ECDHE_RSA_WITH_AES_256_CBC_SHA|ECDHE|RSA|AES-CBC|256|1|CBC
c007|ECDHE_ECDSA_WITH_RC4_128_SHA|ECDHE|ECDSA|RC4|128|1|RC4
c011|ECDHE_RSA_WITH_RC4_128_SHA|ECDHE|RSA|RC4|128|1|RC4
c008|ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA|ECDHE|ECDSA|3DES|112|1|3DES,CBC
c012|ECDHE_RSA_WITH_3DES_EDE_CBC_SHA|ECDHE|RSA|3DES|112|1|3DES,CBC
009e|DHE_RSA_WITH_AES_128_GCM_SHA256|DHE|RSA|AES-GCM|128|1|AEAD
009f|DHE_RSA_WITH_AES_256_GCM_SHA384|DHE|RSA|AES-GCM|256|1|AEAD
ccaa|DHE_RSA_WITH_CHACHA20_POLY1305|DHE|RSA|ChaCha20|256|1|AEAD,CHACHA
0067|DHE_RSA_WITH_AES_128_CBC_SHA256|DHE|RSA|AES-CBC|128|1|CBC
006b|DHE_RSA_WITH_AES_256_CBC_SHA256|DHE|RSA|AES-CBC|256|1|CBC
0033|DHE_RSA_WITH_AES_128_CBC_SHA|DHE|RSA|AES-CBC|128|1|CBC
0039|DHE_RSA_WITH_AES_256_CBC_SHA|DHE|RSA|AES-CBC|256|1|CBC
0016|DHE_RSA_WITH_3DES_EDE_CBC_SHA|DHE|RSA|3DES|112|1|3DES,CBC
0015|DHE_RSA_WITH_DES_CBC_SHA|DHE|RSA|DES|56|1|DES,CBC
009c|RSA_WITH_AES_128_GCM_SHA256|RSA|RSA|AES-GCM|128|0|AEAD
009d|RSA_WITH_AES_256_GCM_SHA384|RSA|RSA|AES-GCM|256|0|AEAD
003c|RSA_WITH_AES_128_CBC_SHA256|RSA|RSA|AES-CBC|128|0|CBC
003d|RSA_WITH_AES_256_CBC_SHA256|RSA|RSA|AES-CBC|256|0|CBC
002f|RSA_WITH_AES_128_CBC_SHA|RSA|RSA|AES-CBC|128|0|CBC
0035|RSA_WITH_AES_256_CBC_SHA|RSA|RSA|AES-CBC|256|0|CBC
000a|RSA_WITH_3DES_EDE_CBC_SHA|RSA|RSA|3DES|112|0|3DES,CBC
0005|RSA_WITH_RC4_128_SHA|RSA|RSA|RC4|128|0|RC4
0004|RSA_WITH_RC4_128_MD5|RSA|RSA|RC4|128|0|RC4,MD5
0009|RSA_WITH_DES_CBC_SHA|RSA|RSA|DES|56|0|DES,CBC
003b|RSA_WITH_NULL_SHA256|RSA|RSA|NULL|0|0|NULL
0002|RSA_WITH_NULL_SHA|RSA|RSA|NULL|0|0|NULL
0001|RSA_WITH_NULL_MD5|RSA|RSA|NULL|0|0|NULL,MD5
0041|RSA_WITH_CAMELLIA_128_CBC_SHA|RSA|RSA|Camellia|128|0|CBC,CAMELLIA
0084|RSA_WITH_CAMELLIA_256_CBC_SHA|RSA|RSA|Camellia|256|0|CBC,CAMELLIA
0096|RSA_WITH_SEED_CBC_SHA|RSA|RSA|SEED|128|0|CBC,SEED
0003|RSA_EXPORT_WITH_RC4_40_MD5|RSA_EXPORT|RSA|RC4|40|0|EXPORT,RC4,MD5
0006|RSA_EXPORT_WITH_RC2_CBC_40_MD5|RSA_EXPORT|RSA|RC2|40|0|EXPORT,MD5
0008|RSA_EXPORT_WITH_DES40_CBC_SHA|RSA_EXPORT|RSA|DES|40|0|EXPORT,DES,CBC
0014|DHE_RSA_EXPORT_WITH_DES40_CBC_SHA|DHE_EXPORT|RSA|DES|40|1|EXPORT,DES,CBC
0011|DHE_DSS_EXPORT_WITH_DES40_CBC_SHA|DHE_EXPORT|DSS|DES|40|1|EXPORT,DES,CBC
0060|RSA_EXPORT1024_WITH_RC4_56_MD5|RSA_EXPORT|RSA|RC4|56|0|EXPORT,RC4,MD5
0062|RSA_EXPORT1024_WITH_DES_CBC_SHA|RSA_EXPORT|RSA|DES|56|0|EXPORT,DES,CBC
0064|RSA_EXPORT1024_WITH_RC4_56_SHA|RSA_EXPORT|RSA|RC4|56|0|EXPORT,RC4
0018|DH_anon_WITH_RC4_128_MD5|DH|anon|RC4|128|0|ANON,RC4,MD5
001b|DH_anon_WITH_3DES_EDE_CBC_SHA|DH|anon|3DES|112|0|ANON,3DES,CBC
0034|DH_anon_WITH_AES_128_CBC_SHA|DH|anon|AES-CBC|128|0|ANON,CBC
003a|DH_anon_WITH_AES_256_CBC_SHA|DH|anon|AES-CBC|256|0|ANON,CBC
0017|DH_anon_EXPORT_WITH_RC4_40_MD5|DH_EXPORT|anon|RC4|40|0|ANON,EXPORT,RC4,MD5
c015|ECDH_anon_WITH_NULL_SHA|ECDH|anon|NULL|0|0|ANON,NULL
c016|ECDH_anon_WITH_RC4_128_SHA|ECDH|anon|RC4|128|0|ANON,RC4
c017|ECDH_anon_WITH_3DES_EDE_CBC_SHA|ECDH|anon|3DES|112|0|ANON,3DES,CBC
c018|ECDH_anon_WITH_AES_128_CBC_SHA|ECDH|anon|AES-CBC|128|0|ANON,CBC
c019|ECDH_anon_WITH_AES_256_CBC_SHA|ECDH|anon|AES-CBC|256|0|ANON,CBC
'@

function Convert-PWCipherCatalog {
    $map = @{}
    foreach ($line in ($script:PWCipherText -split "`n")) {
        $t = $line.Trim()
        if (-not $t) { continue }
        $c = $t.Split('|')
        if ($c.Count -lt 8) { continue }
        $id = [Convert]::ToInt32($c[0], 16)
        $flags = @($c[7].Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $map[$id] = [pscustomobject]@{
            Id     = $id
            IdHex  = '0x' + $c[0].ToUpperInvariant()
            Name   = 'TLS_' + $c[1]
            Kx     = $c[2]
            Au     = $c[3]
            Enc    = $c[4]
            Bits   = [int]$c[5]
            PFS    = $c[6] -eq '1'
            Flags  = $flags
            Tls13  = $id -ge 0x1301 -and $id -le 0x13ff
        }
    }
    return $map
}
$script:PWCiphers = Convert-PWCipherCatalog

function Get-PWCipherInfo {
    param([int]$Id)
    if ($script:PWCiphers.ContainsKey($Id)) { return $script:PWCiphers[$Id] }
    return [pscustomobject]@{ Id=$Id; IdHex=('0x{0:X4}' -f $Id); Name=('UNKNOWN_0x{0:X4}' -f $Id); Kx='?'; Au='?'; Enc='?'; Bits=0; PFS=$false; Flags=@(); Tls13=($Id -ge 0x1301 -and $Id -le 0x13ff) }
}
function Get-PWCipherCatalog { @($script:PWCiphers.Values | Sort-Object Id) }

# ---------------------------------------------------------------------------
# Byte helpers
# ---------------------------------------------------------------------------
function Add-PWUInt16 { param([Collections.Generic.List[byte]]$List,[int]$Value) $List.Add([byte](($Value -shr 8) -band 0xFF)); $List.Add([byte]($Value -band 0xFF)) }
function Add-PWUInt24 { param([Collections.Generic.List[byte]]$List,[int]$Value) $List.Add([byte](($Value -shr 16) -band 0xFF)); $List.Add([byte](($Value -shr 8) -band 0xFF)); $List.Add([byte]($Value -band 0xFF)) }
function New-PWExtension {
    # Wrap an extension body: type(2) + len(2) + body
    param([int]$Type,[byte[]]$Body)
    $out = [Collections.Generic.List[byte]]::new()
    Add-PWUInt16 $out $Type
    Add-PWUInt16 $out $Body.Length
    if ($Body.Length) { $out.AddRange($Body) }
    return ,$out.ToArray()
}

function Get-PWEcdhKeyShare {
    # A real ephemeral secp256r1 public key (0x04 || X || Y, 65 bytes) for the
    # TLS 1.3 key_share extension. Real point so servers that validate it still
    # answer with a ServerHello. .NET Framework 4.7+ and .NET Core both support this.
    try {
        $ec = [System.Security.Cryptography.ECDiffieHellman]::Create([System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
        try {
            $p = $ec.ExportParameters($false)
            $x = $p.Q.X; $y = $p.Q.Y
            $buf = New-Object byte[] (1 + $x.Length + $y.Length)
            $buf[0] = 0x04
            [Array]::Copy($x, 0, $buf, 1, $x.Length)
            [Array]::Copy($y, 0, $buf, 1 + $x.Length, $y.Length)
            return ,$buf
        } finally { $ec.Dispose() }
    } catch {
        # Fallback: a fixed valid-length placeholder. Some servers still emit a
        # ServerHello/HRR that reveals 1.3 support even with a placeholder point.
        $buf = New-Object byte[] 65; $buf[0] = 0x04; return ,$buf
    }
}

function New-PWClientHello {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$Version,           # target: legacy_version for <=1.2, 0x0303 for 1.3
        [Parameter(Mandatory)][int[]]$CipherIds,
        [string]$ServerName = '',
        [switch]$Tls13,
        [switch]$IncludeScsvRenegotiation,             # append 0x00FF empty-renego SCSV
        [switch]$IncludeFallbackScsv,                  # append 0x5600 TLS_FALLBACK_SCSV
        [switch]$OfferHeartbeat,                        # heartbeat extension (Heartbleed probe)
        [switch]$OfferCompression                       # advertise DEFLATE (CRIME probe)
    )
    $body = [Collections.Generic.List[byte]]::new()
    # legacy_version
    Add-PWUInt16 $body $(if ($Tls13) { 0x0303 } else { $Version })
    # random (32 bytes)
    $rng = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($rng)
    $body.AddRange($rng)
    # session_id: 32 random bytes (compat / 1.3 middlebox mode)
    $sid = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($sid)
    $body.Add([byte]32); $body.AddRange($sid)
    # cipher_suites
    $cs = [Collections.Generic.List[byte]]::new()
    foreach ($id in $CipherIds) { Add-PWUInt16 $cs $id }
    if ($IncludeScsvRenegotiation) { Add-PWUInt16 $cs 0x00FF }
    if ($IncludeFallbackScsv)      { Add-PWUInt16 $cs 0x5600 }
    Add-PWUInt16 $body $cs.Count
    $body.AddRange($cs)
    # compression_methods
    if ($OfferCompression) { $body.Add([byte]2); $body.Add([byte]1); $body.Add([byte]0) }  # DEFLATE(1), null(0)
    else { $body.Add([byte]1); $body.Add([byte]0) }
    # extensions
    $ext = [Collections.Generic.List[byte]]::new()
    if ($ServerName) {
        $nameBytes = [Text.Encoding]::ASCII.GetBytes($ServerName)
        $sni = [Collections.Generic.List[byte]]::new()
        Add-PWUInt16 $sni ($nameBytes.Length + 3)   # server_name_list length
        $sni.Add([byte]0)                            # name_type host_name
        Add-PWUInt16 $sni $nameBytes.Length
        $sni.AddRange($nameBytes)
        $ext.AddRange((New-PWExtension 0x0000 $sni.ToArray()))
    }
    # supported_groups
    $groups = [Collections.Generic.List[byte]]::new()
    $groupIds = @(0x001d,0x0017,0x0018,0x0019,0x0100,0x0101)  # x25519,p256,p384,p521,ffdhe2048,ffdhe3072
    Add-PWUInt16 $groups ($groupIds.Count * 2)
    foreach ($g in $groupIds) { Add-PWUInt16 $groups $g }
    $ext.AddRange((New-PWExtension 0x000a $groups.ToArray()))
    # ec_point_formats: uncompressed
    $ext.AddRange((New-PWExtension 0x000b ([byte[]]@(1,0))))
    # signature_algorithms (broad)
    $sigs = @(0x0403,0x0503,0x0603,0x0804,0x0805,0x0806,0x0401,0x0501,0x0601,0x0203,0x0201,0x0202,0x0301)
    $sa = [Collections.Generic.List[byte]]::new()
    Add-PWUInt16 $sa ($sigs.Count * 2)
    foreach ($s in $sigs) { Add-PWUInt16 $sa $s }
    $ext.AddRange((New-PWExtension 0x000d $sa.ToArray()))
    # renegotiation_info (empty) - lets us observe secure renegotiation support
    $ext.AddRange((New-PWExtension 0xff01 ([byte[]]@(0))))
    if ($OfferHeartbeat) { $ext.AddRange((New-PWExtension 0x000f ([byte[]]@(1)))) } # peer_allowed_to_send
    if ($Tls13) {
        # supported_versions
        $sv = [Collections.Generic.List[byte]]::new()
        $sv.Add([byte]2); Add-PWUInt16 $sv 0x0304
        $ext.AddRange((New-PWExtension 0x002b $sv.ToArray()))
        # key_share: secp256r1
        $share = Get-PWEcdhKeyShare
        $ks = [Collections.Generic.List[byte]]::new()
        $entry = [Collections.Generic.List[byte]]::new()
        Add-PWUInt16 $entry 0x0017            # group secp256r1
        Add-PWUInt16 $entry $share.Length
        $entry.AddRange($share)
        Add-PWUInt16 $ks $entry.Count
        $ks.AddRange($entry)
        $ext.AddRange((New-PWExtension 0x0033 $ks.ToArray()))
        # psk_key_exchange_modes: psk_dhe_ke(1)
        $ext.AddRange((New-PWExtension 0x002d ([byte[]]@(1,1))))
    }
    Add-PWUInt16 $body $ext.Count
    $body.AddRange($ext)
    # Handshake header: type(1)=client_hello + length(3)
    $hs = [Collections.Generic.List[byte]]::new()
    $hs.Add([byte]1)
    Add-PWUInt24 $hs $body.Count
    $hs.AddRange($body)
    # Record header: type(1)=handshake, version(2), length(2)
    $recVersion = if ($Version -eq 0x0300) { 0x0300 } else { 0x0301 }
    $rec = [Collections.Generic.List[byte]]::new()
    $rec.Add([byte]0x16)
    Add-PWUInt16 $rec $recVersion
    Add-PWUInt16 $rec $hs.Count
    $rec.AddRange($hs)
    return ,$rec.ToArray()
}

# ---------------------------------------------------------------------------
# Socket + record reader
# ---------------------------------------------------------------------------
$script:PWHRRRandom = [byte[]]@(0xCF,0x21,0xAD,0x74,0xE5,0x9A,0x61,0x11,0xBE,0x1D,0x8C,0x02,0x1E,0x65,0xB8,0x91,0xC2,0xA2,0x11,0x16,0x7A,0xBB,0x8C,0x5E,0x07,0x9E,0x09,0xE2,0xC8,0xA8,0x33,0x9C)

function Read-PWExact {
    # Read exactly $Count bytes or return $null on close/timeout.
    param([IO.Stream]$Stream,[int]$Count,[datetime]$Deadline,[hashtable]$Control)
    $buf = New-Object byte[] $Count
    $off = 0
    while ($off -lt $Count) {
        if ($Control -and $Control.Cancel) { return $null }
        if ([DateTime]::UtcNow -gt $Deadline) { return $null }
        try { $n = $Stream.Read($buf, $off, $Count - $off) }
        catch { return $null }
        if ($n -le 0) { return $null }
        $off += $n
    }
    return ,$buf
}

function Invoke-PWTlsHandshake {
    # Sends one ClientHello and parses the server's response up to (and
    # optionally including) the Certificate/ServerHelloDone. Returns a structured
    # result; never throws for protocol-level rejection (that is data).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TargetHost,[int]$Port=443,
        [Parameter(Mandatory)][byte[]]$ClientHello,
        [ValidateSet('ServerHello','ServerHelloDone')][string]$ReadUntil='ServerHello',
        [int]$TimeoutSeconds=15,[hashtable]$Control,
        [switch]$KeepOpen,[ref]$StreamRef,[ref]$ClientRef)
    $result = [ordered]@{
        Connected=$false; ServerHello=$false; Version=$null; CipherId=$null; IsHRR=$false
        Extensions=@{}; CompressionMethod=$null; CertChain=@(); Alert=$null; Error=''
        Heartbeat=$false; RenegotiationInfo=$false; ServerHelloDone=$false
    }
    $client = [Net.Sockets.TcpClient]::new()
    $client.ReceiveTimeout = $TimeoutSeconds * 1000
    $client.SendTimeout = $TimeoutSeconds * 1000
    $stream = $null
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    try {
        $iar = $client.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000)) { $result.Error = 'Connection timed out.'; return [pscustomobject]$result }
        $client.EndConnect($iar)
        $result.Connected = $true
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutSeconds * 1000
        $stream.WriteTimeout = $TimeoutSeconds * 1000
        $stream.Write($ClientHello, 0, $ClientHello.Length)
        $stream.Flush()

        $hsBuffer = [Collections.Generic.List[byte]]::new()
        $done = $false
        while (-not $done) {
            if ($Control -and $Control.Cancel) { $result.Error='Cancelled.'; break }
            $header = Read-PWExact $stream 5 $deadline $Control
            if ($null -eq $header) { if (-not $result.ServerHello) { $result.Error = 'No/again response (closed or timed out).' }; break }
            $ctype = $header[0]
            $recLen = ([int]$header[3] -shl 8) -bor [int]$header[4]
            if ($recLen -lt 0 -or $recLen -gt 65535) { $result.Error='Bad record length.'; break }
            $payload = if ($recLen -gt 0) { Read-PWExact $stream $recLen $deadline $Control } else { ,([byte[]]@()) }
            if ($null -eq $payload) { $result.Error='Truncated record.'; break }
            switch ($ctype) {
                0x15 {  # alert
                    if ($payload.Length -ge 2) { $result.Alert = [pscustomobject]@{ Level=$payload[0]; Desc=$payload[1] } }
                    $done = $true
                }
                0x16 {  # handshake
                    $hsBuffer.AddRange($payload)
                    # parse complete handshake messages present so far
                    $pos = 0
                    while ($hsBuffer.Count - $pos -ge 4) {
                        $mtype = $hsBuffer[$pos]
                        $mlen = ([int]$hsBuffer[$pos+1] -shl 16) -bor ([int]$hsBuffer[$pos+2] -shl 8) -bor [int]$hsBuffer[$pos+3]
                        if ($hsBuffer.Count - $pos - 4 -lt $mlen) { break }  # need more record data
                        $mbody = $hsBuffer.GetRange($pos+4, $mlen).ToArray()
                        $pos += 4 + $mlen
                        switch ($mtype) {
                            2 { Parse-PWServerHello $mbody $result }
                            11 { $result.CertChain = Parse-PWCertificateMessage $mbody }
                            14 { $result.ServerHelloDone = $true; $done = $true }
                            default { }
                        }
                        if ($result.ServerHello -and $ReadUntil -eq 'ServerHello') { $done = $true; break }
                        if ($result.CertChain.Count -gt 0 -and $ReadUntil -eq 'ServerHelloDone' -and $result.Version -eq 0x0303 -and $result.ServerHello) {
                            # keep reading until ServerHelloDone for full chain
                        }
                    }
                    # For TLS 1.3, everything after ServerHello is encrypted; stop once we have it.
                    if ($result.ServerHello -and $ReadUntil -eq 'ServerHello') { $done = $true }
                    if ($result.ServerHello -and $result.Version -eq 0x0304) { $done = $true }
                }
                0x14 { }  # change_cipher_spec (1.3 middlebox) -> ignore
                default { $result.Error = "Unexpected record type $ctype."; $done = $true }
            }
        }
        if ($KeepOpen -and $result.Connected -and -not ($Control -and $Control.Cancel)) {
            if ($StreamRef) { $StreamRef.Value = $stream }
            if ($ClientRef) { $ClientRef.Value = $client }
            return [pscustomobject]$result
        }
    } catch {
        $result.Error = $_.Exception.Message
    } finally {
        if (-not $KeepOpen) {
            if ($stream) { try { $stream.Dispose() } catch {} }
            try { $client.Close() } catch {}
        }
    }
    return [pscustomobject]$result
}

function Parse-PWServerHello {
    param([byte[]]$Body,[System.Collections.Specialized.OrderedDictionary]$Result)
    if ($Body.Length -lt 38) { return }
    $legacyVersion = ([int]$Body[0] -shl 8) -bor [int]$Body[1]
    $random = $Body[2..33]
    $isHRR = $true
    for ($i=0; $i -lt 32; $i++) { if ($random[$i] -ne $script:PWHRRRandom[$i]) { $isHRR = $false; break } }
    $p = 34
    $sidLen = $Body[$p]; $p += 1 + $sidLen
    if ($p + 3 -gt $Body.Length) { return }
    $cipher = ([int]$Body[$p] -shl 8) -bor [int]$Body[$p+1]; $p += 2
    $comp = [int]$Body[$p]; $p += 1
    $negVersion = $legacyVersion
    $exts = @{}
    if ($p + 2 -le $Body.Length) {
        $extTotal = ([int]$Body[$p] -shl 8) -bor [int]$Body[$p+1]; $p += 2
        $extEnd = $p + $extTotal
        while ($p + 4 -le $Body.Length -and $p + 4 -le $extEnd) {
            $etype = ([int]$Body[$p] -shl 8) -bor [int]$Body[$p+1]
            $elen = ([int]$Body[$p+2] -shl 8) -bor [int]$Body[$p+3]
            $p += 4
            if ($p + $elen -gt $Body.Length) { break }
            $edata = if ($elen -gt 0) { $Body[$p..($p+$elen-1)] } else { @() }
            $exts[$etype] = $edata
            if ($etype -eq 0x002b -and $elen -ge 2) { $negVersion = ([int]$edata[0] -shl 8) -bor [int]$edata[1] }
            if ($etype -eq 0x000f) { $Result.Heartbeat = $true }
            if ($etype -eq 0xff01) { $Result.RenegotiationInfo = $true }
            $p += $elen
        }
    }
    $Result.ServerHello = $true
    $Result.Version = $negVersion
    $Result.CipherId = $cipher
    $Result.CompressionMethod = $comp
    $Result.IsHRR = $isHRR
    $Result.Extensions = $exts
}

function Parse-PWCertificateMessage {
    # TLS 1.2 Certificate: 3-byte total len, then repeated (3-byte len + cert DER).
    param([byte[]]$Body)
    $certs = [Collections.Generic.List[byte[]]]::new()
    if ($Body.Length -lt 3) { return ,@() }
    $total = ([int]$Body[0] -shl 16) -bor ([int]$Body[1] -shl 8) -bor [int]$Body[2]
    $p = 3; $end = [Math]::Min($Body.Length, 3 + $total)
    while ($p + 3 -le $end) {
        $clen = ([int]$Body[$p] -shl 16) -bor ([int]$Body[$p+1] -shl 8) -bor [int]$Body[$p+2]
        $p += 3
        if ($clen -le 0 -or $p + $clen -gt $Body.Length) { break }
        $certs.Add($Body[$p..($p+$clen-1)])
        $p += $clen
    }
    return ,$certs.ToArray()
}

# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------
function Test-PWProtocolAndCiphers {
    param(
        [string]$TargetHost,[int]$Port,[string]$Sni,[int]$Version,[string]$VersionName,
        [switch]$Enumerate,[int]$TimeoutSeconds,[hashtable]$Control,[ref]$ConnCount,[int]$MaxConnections)
    $isTls13 = $Version -eq 0x0304
    $allIds = if ($isTls13) { @($script:PWCiphers.Values | Where-Object Tls13 | ForEach-Object Id) }
              else { @($script:PWCiphers.Values | Where-Object { -not $_.Tls13 } | ForEach-Object Id) }
    $remaining = [Collections.Generic.List[int]]::new(); $allIds | ForEach-Object { [void]$remaining.Add($_) }
    $accepted = [Collections.Generic.List[int]]::new()
    $supported = $false
    $rounds = 0
    while ($remaining.Count -gt 0) {
        if ($Control -and $Control.Cancel) { break }
        if ($ConnCount.Value -ge $MaxConnections) { break }
        $rounds++
        if ($rounds -gt 220) { break }
        $ch = New-PWClientHello -Version $Version -CipherIds $remaining.ToArray() -ServerName $Sni -Tls13:$isTls13 -IncludeScsvRenegotiation
        $ConnCount.Value++
        $r = Invoke-PWTlsHandshake -TargetHost $TargetHost -Port $Port -ClientHello $ch -ReadUntil 'ServerHello' -TimeoutSeconds $TimeoutSeconds -Control $Control
        if (-not $r.ServerHello) { break }
        # negotiated version must match the version we asked for
        $negOk = if ($isTls13) { $r.Version -eq 0x0304 -or ($r.Extensions.ContainsKey(0x002b)) } else { $r.Version -eq $Version }
        if (-not $negOk) { break }
        $supported = $true
        $cid = [int]$r.CipherId
        if ($remaining.Contains($cid)) { [void]$accepted.Add($cid); [void]$remaining.Remove($cid) }
        else { break }   # server picked something we did not offer (or a repeat) -> stop
        if (-not $Enumerate) { break }
        if ($r.IsHRR) {
            # HelloRetryRequest: 1.3 supported, but we cannot cheaply continue the
            # negotiation for full enumeration. Record the one suite and stop.
            break
        }
    }
    return [pscustomobject]@{
        Name=$VersionName; Version=$Version; Supported=$supported
        Ciphers=@($accepted | ForEach-Object { Get-PWCipherInfo $_ })
        CipherIds=@($accepted)
    }
}

function Test-PWCipherOrder {
    # Server cipher preference: offer a list and its reverse; if the pick is the
    # same suite, the server enforces its own order.
    param([string]$TargetHost,[int]$Port,[string]$Sni,[int]$Version,[int[]]$CipherIds,[int]$TimeoutSeconds,[hashtable]$Control,[ref]$ConnCount,[int]$MaxConnections)
    if ($CipherIds.Count -lt 2) { return $null }
    if ($ConnCount.Value + 2 -gt $MaxConnections) { return $null }
    $isTls13 = $Version -eq 0x0304
    $forward = $CipherIds
    $reverse = @($CipherIds[($CipherIds.Count-1)..0])
    $ch1 = New-PWClientHello -Version $Version -CipherIds $forward -ServerName $Sni -Tls13:$isTls13 -IncludeScsvRenegotiation
    $ch2 = New-PWClientHello -Version $Version -CipherIds $reverse -ServerName $Sni -Tls13:$isTls13 -IncludeScsvRenegotiation
    $ConnCount.Value++
    $r1 = Invoke-PWTlsHandshake -TargetHost $TargetHost -Port $Port -ClientHello $ch1 -TimeoutSeconds $TimeoutSeconds -Control $Control
    $ConnCount.Value++
    $r2 = Invoke-PWTlsHandshake -TargetHost $TargetHost -Port $Port -ClientHello $ch2 -TimeoutSeconds $TimeoutSeconds -Control $Control
    if (-not $r1.ServerHello -or -not $r2.ServerHello) { return $null }
    return ($r1.CipherId -eq $r2.CipherId)   # same pick regardless of order => server preference
}

# ---------------------------------------------------------------------------
# Certificate analysis
# ---------------------------------------------------------------------------
function Get-PWCertificateReport {
    param([byte[][]]$CertChain,[string]$TargetHost)
    if (-not $CertChain -or $CertChain.Count -eq 0) { return $null }
    try { $leaf = [Security.Cryptography.X509Certificates.X509Certificate2]::new($CertChain[0]) }
    catch { return [pscustomobject]@{ Error = 'Certificate could not be parsed: ' + $_.Exception.Message } }
    try {
        $now = [DateTime]::UtcNow
        $notBefore = $leaf.NotBefore.ToUniversalTime()
        $notAfter = $leaf.NotAfter.ToUniversalTime()
        $daysLeft = [Math]::Floor(($notAfter - $now).TotalDays)
        $keyAlg = $leaf.PublicKey.Oid.FriendlyName
        # KeySize getters throw "write-only" via the PowerShell adapter on some RSA/ECDsa
        # backends, so derive the bit length from the exported public parameters instead.
        $keySize = 0
        try { $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($leaf); if ($rsa) { $keySize = $rsa.ExportParameters($false).Modulus.Length * 8; $rsa.Dispose() } } catch {}
        if ($keySize -eq 0) { try { $ec = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($leaf); if ($ec) { $keySize = $ec.ExportParameters($false).Q.X.Length * 8; $ec.Dispose() } } catch {} }
        $sigAlg = $leaf.SignatureAlgorithm.FriendlyName
        $sans = @()
        foreach ($ext in $leaf.Extensions) {
            if ($ext.Oid.Value -eq '2.5.29.17') { $sans = @(($ext.Format($false) -split ',') | ForEach-Object { ($_ -replace '(?i)^\s*DNS Name=','' -replace '(?i)^\s*DNS=','').Trim() } | Where-Object { $_ }) }
        }
        $selfSigned = $leaf.Subject -eq $leaf.Issuer
        # Chain build for trust status
        $chainOk = $false; $chainStatus = @()
        try {
            $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
            $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            foreach ($der in $CertChain) { try { [void]$chain.ChainPolicy.ExtraStore.Add([Security.Cryptography.X509Certificates.X509Certificate2]::new($der)) } catch {} }
            $chainOk = $chain.Build($leaf)
            $chainStatus = @($chain.ChainStatus | ForEach-Object { $_.Status.ToString() }) | Where-Object { $_ -ne 'NoError' }
        } catch { $chainStatus = @('ChainBuildError: ' + $_.Exception.Message) }
        # Hostname match (CN + SAN, incl. simple wildcard)
        $hostMatch = $false
        $cn = ($leaf.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false))
        $names = @($sans); if ($cn) { $names += $cn }
        foreach ($n in $names) {
            if (-not $n) { continue }
            if ($n -ieq $TargetHost) { $hostMatch = $true; break }
            if ($n.StartsWith('*.')) { $suffix = $n.Substring(1); if ($TargetHost.ToLowerInvariant().EndsWith($suffix.ToLowerInvariant()) -and ($TargetHost.Split('.').Count -eq $n.Split('.').Count)) { $hostMatch = $true; break } }
        }
        return [pscustomobject]@{
            Subject=$leaf.Subject; Issuer=$leaf.Issuer; SerialNumber=$leaf.SerialNumber
            NotBeforeUtc=$notBefore.ToString('o'); NotAfterUtc=$notAfter.ToString('o'); DaysLeft=$daysLeft
            KeyAlgorithm=$keyAlg; KeySize=$keySize; SignatureAlgorithm=$sigAlg
            SubjectAltNames=$sans; SelfSigned=$selfSigned; ChainTrusted=$chainOk; ChainStatus=$chainStatus
            HostnameMatch=$hostMatch; ChainLength=$CertChain.Count
            Expired=($now -gt $notAfter); NotYetValid=($now -lt $notBefore)
            Thumbprint=$leaf.Thumbprint
        }
    } finally { $leaf.Dispose() }
}

function Get-PWCertificateViaSslStream {
    # Fallback certificate retrieval for TLS 1.3-only servers (cert is encrypted
    # in 1.3 so the raw Certificate message is not visible). Uses SslStream only to
    # obtain the presented chain; all analysis stays in Get-PWCertificateReport.
    param([string]$TargetHost,[int]$Port,[int]$TimeoutSeconds)
    $client = [Net.Sockets.TcpClient]::new()
    $client.ReceiveTimeout = $TimeoutSeconds*1000; $client.SendTimeout = $TimeoutSeconds*1000
    $ssl = $null
    try {
        $iar = $client.BeginConnect($TargetHost,$Port,$null,$null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutSeconds*1000)) { return $null }
        $client.EndConnect($iar)
        $cb = [Net.Security.RemoteCertificateValidationCallback]{ param($s,$c,$h,$e) $true }
        $ssl = [Net.Security.SslStream]::new($client.GetStream(),$false,$cb)
        $ssl.AuthenticateAsClient($TargetHost)
        $chainDer = [Collections.Generic.List[byte[]]]::new()
        $remote = $ssl.RemoteCertificate
        if ($remote) { [void]$chainDer.Add(([Security.Cryptography.X509Certificates.X509Certificate2]::new($remote)).RawData) }
        return ,$chainDer.ToArray()
    } catch { return $null }
    finally { if ($ssl) { try { $ssl.Dispose() } catch {} }; try { $client.Close() } catch {} }
}

# ---------------------------------------------------------------------------
# Active vulnerability probes (gated behind -AllowActiveVulnChecks)
# ---------------------------------------------------------------------------
function Test-PWHeartbleed {
    # CVE-2014-0160. Offer the heartbeat extension, drive the handshake to
    # ServerHelloDone, then send a malformed heartbeat (claimed length >> actual
    # payload). A response longer than the sent payload indicates the overread.
    # Any returned bytes are counted and discarded, never stored.
    param([string]$TargetHost,[int]$Port,[string]$Sni,[int]$TimeoutSeconds,[hashtable]$Control,[ref]$ConnCount)
    $ids = @($script:PWCiphers.Values | Where-Object { -not $_.Tls13 } | ForEach-Object Id)
    $ch = New-PWClientHello -Version 0x0303 -CipherIds $ids -ServerName $Sni -IncludeScsvRenegotiation -OfferHeartbeat
    $streamRef = [ref]$null; $clientRef = [ref]$null
    $ConnCount.Value++
    $r = Invoke-PWTlsHandshake -TargetHost $TargetHost -Port $Port -ClientHello $ch -ReadUntil 'ServerHelloDone' -TimeoutSeconds $TimeoutSeconds -Control $Control -KeepOpen -StreamRef $streamRef -ClientRef $clientRef
    $stream = $streamRef.Value; $client = $clientRef.Value
    try {
        if (-not $r.ServerHello) { return [pscustomobject]@{ Result='Untested'; Detail='No TLS handshake for the heartbeat probe.' } }
        if (-not $r.Heartbeat) { return [pscustomobject]@{ Result='Not vulnerable'; Detail='Server did not negotiate the heartbeat extension.' } }
        if (-not $stream) { return [pscustomobject]@{ Result='Untested'; Detail='Connection not available for the heartbeat probe.' } }
        # Heartbeat request: type=1, payload_length=0x4000, payload=1 byte, padding omitted.
        $hb = [Collections.Generic.List[byte]]::new()
        $hb.Add([byte]1); Add-PWUInt16 $hb 0x4000; $hb.Add([byte]0x50)
        $rec = [Collections.Generic.List[byte]]::new()
        $rec.Add([byte]0x18); Add-PWUInt16 $rec 0x0303; Add-PWUInt16 $rec $hb.Count; $rec.AddRange($hb)
        $bytes = $rec.ToArray()
        $stream.Write($bytes,0,$bytes.Length); $stream.Flush()
        $deadline = [DateTime]::UtcNow.AddSeconds([Math]::Min($TimeoutSeconds,8))
        $header = Read-PWExact $stream 5 $deadline $Control
        if ($null -eq $header) { return [pscustomobject]@{ Result='Not vulnerable'; Detail='No heartbeat response (server closed or ignored the request).' } }
        $ctype = $header[0]; $rlen = ([int]$header[3] -shl 8) -bor [int]$header[4]
        if ($ctype -eq 0x18 -and $rlen -gt 3) {
            # Overread: response record far larger than the single payload byte we sent.
            return [pscustomobject]@{ Result='Vulnerable'; Detail=("Heartbeat response of {0} bytes for a 1-byte payload request (memory over-read). Returned data was discarded." -f $rlen) }
        }
        if ($ctype -eq 0x15) { return [pscustomobject]@{ Result='Not vulnerable'; Detail='Server answered the malformed heartbeat with an alert.' } }
        return [pscustomobject]@{ Result='Not vulnerable'; Detail=("Heartbeat response record type {0}, {1} bytes; no over-read." -f $ctype,$rlen) }
    } finally { if ($stream) { try { $stream.Dispose() } catch {} }; if ($client) { try { $client.Close() } catch {} } }
}

function Test-PWCcsInjection {
    # CVE-2014-0224 (experimental). Send an early ChangeCipherSpec before the
    # ClientKeyExchange. A patched server rejects it with unexpected_message(10).
    # Acceptance is only a hint; confirm manually.
    param([string]$TargetHost,[int]$Port,[string]$Sni,[int]$TimeoutSeconds,[hashtable]$Control,[ref]$ConnCount)
    $ids = @($script:PWCiphers.Values | Where-Object { -not $_.Tls13 -and -not $_.Tls13 } | ForEach-Object Id)
    $ch = New-PWClientHello -Version 0x0303 -CipherIds $ids -ServerName $Sni -IncludeScsvRenegotiation
    $streamRef = [ref]$null; $clientRef = [ref]$null
    $ConnCount.Value++
    $r = Invoke-PWTlsHandshake -TargetHost $TargetHost -Port $Port -ClientHello $ch -ReadUntil 'ServerHelloDone' -TimeoutSeconds $TimeoutSeconds -Control $Control -KeepOpen -StreamRef $streamRef -ClientRef $clientRef
    $stream = $streamRef.Value; $client = $clientRef.Value
    try {
        if (-not $r.ServerHello) { return [pscustomobject]@{ Result='Untested'; Detail='No handshake for the CCS probe.' } }
        if ($r.Version -eq 0x0304) { return [pscustomobject]@{ Result='Not applicable'; Detail='TLS 1.3 does not use the affected CCS flow.' } }
        if (-not $stream) { return [pscustomobject]@{ Result='Untested'; Detail='Connection not available.' } }
        # early ChangeCipherSpec
        $ccs = [byte[]]@(0x14,0x03,0x03,0x00,0x01,0x01)
        $stream.Write($ccs,0,$ccs.Length); $stream.Flush()
        $deadline = [DateTime]::UtcNow.AddSeconds([Math]::Min($TimeoutSeconds,6))
        $header = Read-PWExact $stream 5 $deadline $Control
        if ($null -eq $header) { return [pscustomobject]@{ Result='Inconclusive'; Detail='No response to the early CCS; connection may have dropped.' } }
        $ctype = $header[0]; $rlen = ([int]$header[3] -shl 8) -bor [int]$header[4]
        if ($ctype -eq 0x15) {
            $al = Read-PWExact $stream $rlen $deadline $Control
            if ($al -and $al.Length -ge 2 -and $al[1] -eq 10) { return [pscustomobject]@{ Result='Not vulnerable'; Detail='Server rejected the early CCS with unexpected_message(10).' } }
            return [pscustomobject]@{ Result='Not vulnerable'; Detail=('Server answered the early CCS with an alert (desc {0}).' -f $(if($al -and $al.Length -ge 2){$al[1]}else{'?'})) }
        }
        return [pscustomobject]@{ Result='Potentially vulnerable'; Detail='Server accepted an early ChangeCipherSpec without an alert. Experimental result — confirm manually.' }
    } finally { if ($stream) { try { $stream.Dispose() } catch {} }; if ($client) { try { $client.Close() } catch {} } }
}

function Test-PWFallbackScsv {
    # RFC 7507. If more than one pre-1.3 protocol is supported, send a ClientHello
    # at the lower version carrying TLS_FALLBACK_SCSV; a protected server replies
    # inappropriate_fallback(86).
    param([string]$TargetHost,[int]$Port,[string]$Sni,[int]$LowVersion,[int]$TimeoutSeconds,[hashtable]$Control,[ref]$ConnCount)
    $ids = @($script:PWCiphers.Values | Where-Object { -not $_.Tls13 } | ForEach-Object Id)
    $ch = New-PWClientHello -Version $LowVersion -CipherIds $ids -ServerName $Sni -IncludeScsvRenegotiation -IncludeFallbackScsv
    $ConnCount.Value++
    $r = Invoke-PWTlsHandshake -TargetHost $TargetHost -Port $Port -ClientHello $ch -TimeoutSeconds $TimeoutSeconds -Control $Control
    if ($r.Alert -and $r.Alert.Desc -eq 86) { return [pscustomobject]@{ Result='Supported'; Detail='Server honours TLS_FALLBACK_SCSV (inappropriate_fallback alert).' } }
    if ($r.ServerHello) { return [pscustomobject]@{ Result='Not enforced'; Detail='Server completed a downgraded handshake carrying TLS_FALLBACK_SCSV.' } }
    return [pscustomobject]@{ Result='Inconclusive'; Detail='No clear fallback response.' }
}

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
function Get-PWTlsChecks {
    @(
        [pscustomobject]@{ Id='TLS-PROTO-SSL2'; Name='SSLv2 supported'; Kind='Derived' }
        [pscustomobject]@{ Id='TLS-PROTO-SSL3'; Name='SSLv3 supported (POODLE)'; Kind='Derived' }
        [pscustomobject]@{ Id='TLS-PROTO-10'; Name='TLS 1.0 supported (deprecated, BEAST)'; Kind='Derived' }
        [pscustomobject]@{ Id='TLS-PROTO-11'; Name='TLS 1.1 supported (deprecated)'; Kind='Derived' }
        [pscustomobject]@{ Id='TLS-PROTO-NO12'; Name='TLS 1.2 not supported'; Kind='Derived' }
        [pscustomobject]@{ Id='TLS-PROTO-NO13'; Name='TLS 1.3 not supported'; Kind='Derived' }
        [pscustomobject]@{ Id='TLS-CIPHER-NULL'; Name='NULL cipher offered'; Kind='Derived' }
        [pscustomobject]@{ Id='TLS-CIPHER-ANON'; Name='Anonymous cipher offered'; Kind='Derived' }
        [pscustomobject]@{ Id='TLS-CIPHER-EXPORT'; Name='EXPORT cipher offered (FREAK/LOGJAM)'; Kind='Derived' }
        [pscustomobject]@{ Id='TLS-CIPHER-RC4'; Name='RC4 cipher offered'; Kind='Derived' }
        [pscustomobject]@{ Id='TLS-CIPHER-DES'; Name='DES (56-bit) cipher offered'; Kind='Derived' }
        [pscustomobject]@{ Id='TLS-CIPHER-3DES'; Name='3DES cipher offered (SWEET32)'; Kind='Derived' }
        [pscustomobject]@{ Id='TLS-CIPHER-MD5'; Name='MD5-MAC cipher offered'; Kind='Derived' }
        [pscustomobject]@{ Id='TLS-CIPHER-NOPFS'; Name='No forward-secrecy cipher offered'; Kind='Derived' }
        [pscustomobject]@{ Id='TLS-COMPRESSION'; Name='TLS compression enabled (CRIME)'; Kind='Derived' }
        [pscustomobject]@{ Id='TLS-RENEG'; Name='Secure renegotiation not indicated'; Kind='Derived' }
        [pscustomobject]@{ Id='TLS-CERT-EXPIRED'; Name='Certificate expired / not yet valid'; Kind='Certificate' }
        [pscustomobject]@{ Id='TLS-CERT-EXPIRING'; Name='Certificate expires soon'; Kind='Certificate' }
        [pscustomobject]@{ Id='TLS-CERT-WEAKKEY'; Name='Weak certificate key size'; Kind='Certificate' }
        [pscustomobject]@{ Id='TLS-CERT-WEAKSIG'; Name='Weak certificate signature (SHA1/MD5)'; Kind='Certificate' }
        [pscustomobject]@{ Id='TLS-CERT-UNTRUSTED'; Name='Certificate chain not trusted / self-signed'; Kind='Certificate' }
        [pscustomobject]@{ Id='TLS-CERT-HOSTNAME'; Name='Certificate does not match hostname'; Kind='Certificate' }
        [pscustomobject]@{ Id='TLS-VULN-HEARTBLEED'; Name='Heartbleed (CVE-2014-0160)'; Kind='Active' }
        [pscustomobject]@{ Id='TLS-VULN-CCS'; Name='CCS injection (CVE-2014-0224)'; Kind='Active' }
        [pscustomobject]@{ Id='TLS-VULN-DROWN'; Name='DROWN (SSLv2)'; Kind='Derived' }
        [pscustomobject]@{ Id='TLS-FALLBACK'; Name='TLS_FALLBACK_SCSV enforcement'; Kind='Active' }
    )
}

function New-PWTlsFinding {
    param([string]$RuleId,[string]$Title,[string]$Risk,[string]$Url,[string]$Confidence,[string]$Evidence,[string]$Fix)
    $f = New-PWFinding -Title $Title -Risk $Risk -Url $Url -Evidence $Evidence -Fix $Fix -Source 'TLS engine'
    $f | Add-Member -NotePropertyName RegelId -NotePropertyValue $RuleId
    $f | Add-Member -NotePropertyName Sicherheit -NotePropertyValue $Confidence
    return $f
}

# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
function Invoke-PWTlsScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,           # host, host:port, or https URL
        [int]$Port=0,
        [switch]$EnumerateCiphers,
        [switch]$AllowActiveVulnChecks,
        [ValidateRange(1,60)][int]$TimeoutSeconds=15,
        [ValidateRange(4,600)][int]$MaxConnections=250,
        [hashtable]$Control)
    if (-not $Control) { $Control=[hashtable]::Synchronized(@{Cancel=$false;Request=$null;Message=''}) }
    # Parse target
    $targetHost=$Target.Trim(); $targetPort=$Port
    if ($targetHost -match '^[a-z]+://') {
        $u=[Uri]$targetHost; $targetHost=$u.Host; if ($targetPort -le 0) { $targetPort=$(if ($u.Port -gt 0) { $u.Port } else { 443 }) }
    } elseif ($targetHost -match '^(.+):(\d+)$' -and $targetHost -notmatch '::') {
        $targetHost=$Matches[1]; if ($targetPort -le 0) { $targetPort=[int]$Matches[2] }
    }
    if ($targetPort -le 0) { $targetPort=443 }
    if (-not $targetHost) { throw 'Provide a host name, host:port or https URL.' }
    $sni = if ($targetHost -match '^\d{1,3}(\.\d{1,3}){3}$' -or $targetHost.Contains(':')) { '' } else { $targetHost }
    $urlLabel = "https://${targetHost}:${targetPort}"

    $start=[DateTime]::UtcNow
    $findings=[Collections.Generic.List[object]]::new()
    $history=[Collections.Generic.List[object]]::new()
    $tests=[Collections.Generic.List[object]]::new()
    $connCount=[ref]0
    $enumerate=[bool]$EnumerateCiphers

    # --- Protocols + ciphers ---
    $protocols=[Collections.Generic.List[object]]::new()
    foreach ($name in $script:PWTlsVersions.Keys) {
        if ($Control.Cancel) { break }
        if ($name -eq 'SSLv3') {
            # SSLv3 with modern ciphers; supported means POODLE risk.
        }
        $Control.Message="TLS engine: probing $name"
        $ver=$script:PWTlsVersions[$name]
        $before=$connCount.Value
        $p=Test-PWProtocolAndCiphers -TargetHost $targetHost -Port $targetPort -Sni $sni -Version $ver -VersionName $name -Enumerate:$enumerate -TimeoutSeconds $TimeoutSeconds -Control $Control -ConnCount $connCount -MaxConnections $MaxConnections
        $protocols.Add($p)
        $history.Add([pscustomobject]@{ ZeitpunktUtc=[DateTime]::UtcNow.ToString('o'); Methode='TLS'; Url=("{0} {1}" -f $urlLabel,$name); Status=$(if($p.Supported){1}else{0}); DauerMs=($connCount.Value-$before); Typ='Protocol probe'; Fehler='' })
        $tests.Add([pscustomobject]@{ Pruefung=$name; Ergebnis=$(if($p.Supported){'Supported'}else{'Not supported'}); Detail=("{0} cipher(s) enumerated" -f $p.Ciphers.Count) })
    }

    # SSLv2 (legacy, best-effort): a working SSLv3+ path already tells us the port
    # speaks TLS. We probe SSLv2 with a minimal ClientHello.
    $ssl2 = if (-not $Control.Cancel) { Test-PWSslv2 -TargetHost $targetHost -Port $targetPort -TimeoutSeconds $TimeoutSeconds -Control $Control -ConnCount $connCount } else { [pscustomobject]@{ Supported=$false; Detail='Cancelled.' } }
    $tests.Add([pscustomobject]@{ Pruefung='SSLv2'; Ergebnis=$(if($ssl2.Supported){'Supported'}else{'Not supported'}); Detail=$ssl2.Detail })

    $anySupported = @($protocols | Where-Object Supported).Count -gt 0
    if (-not $anySupported -and -not $ssl2.Supported) {
        $status=if ($Control.Cancel) { 'Cancelled' } else { 'No TLS' }
        $summary=[pscustomobject]@{ Typ='TLS scan'; Version='4.0'; Host=$targetHost; Port=$targetPort; StartUtc=$start.ToString('o'); EndeUtc=[DateTime]::UtcNow.ToString('o'); Status=$status; Verbindungen=$connCount.Value; Hinweis='No TLS/SSL handshake succeeded on this host/port. Confirm the port speaks TLS and is reachable.' }
        return [pscustomobject]@{ Findings=@(); History=$history.ToArray(); Tests=$tests.ToArray(); Protocols=$protocols.ToArray(); Certificate=$null; Vulnerabilities=@(); Rating=$null; Summary=$summary }
    }

    # --- Aggregate ciphers across protocols ---
    $allCiphers=@(); foreach ($p in $protocols) { $allCiphers += $p.Ciphers }
    $uniqueCiphers=@($allCiphers | Sort-Object Id -Unique)

    # --- Certificate ---
    $Control.Message='TLS engine: certificate analysis'
    $chain=@()
    $tls12plus=@($protocols | Where-Object { $_.Supported -and $_.Version -ge 0x0301 -and $_.Version -le 0x0303 } | Select-Object -First 1)
    if ($tls12plus) {
        $ver=$tls12plus.Version
        $ids=@($tls12plus.CipherIds); if (-not $ids.Count) { $ids=@($script:PWCiphers.Values | Where-Object { -not $_.Tls13 } | ForEach-Object Id) }
        $ch=New-PWClientHello -Version $ver -CipherIds $ids -ServerName $sni -IncludeScsvRenegotiation
        $connCount.Value++
        $r=Invoke-PWTlsHandshake -TargetHost $targetHost -Port $targetPort -ClientHello $ch -ReadUntil 'ServerHelloDone' -TimeoutSeconds $TimeoutSeconds -Control $Control
        if ($r.CertChain.Count -gt 0) { $chain=$r.CertChain }
    }
    if (-not $chain -or $chain.Count -eq 0) {
        $chain=Get-PWCertificateViaSslStream -TargetHost $targetHost -Port $targetPort -TimeoutSeconds $TimeoutSeconds
        if ($chain) { $connCount.Value++ }
    }
    $cert = if ($chain -and $chain.Count) { Get-PWCertificateReport -CertChain $chain -TargetHost $targetHost } else { $null }

    # --- Compression + renegotiation (from a representative handshake) ---
    $compressionOn=$false; $renegoOk=$true
    $repr=@($protocols | Where-Object { $_.Supported -and $_.Version -le 0x0303 } | Select-Object -First 1)
    if ($repr) {
        $ids=@($repr.CipherIds); if (-not $ids.Count) { $ids=@($script:PWCiphers.Values | Where-Object { -not $_.Tls13 } | ForEach-Object Id) }
        $chC=New-PWClientHello -Version $repr.Version -CipherIds $ids -ServerName $sni -OfferCompression
        $connCount.Value++
        $rc=Invoke-PWTlsHandshake -TargetHost $targetHost -Port $targetPort -ClientHello $chC -TimeoutSeconds $TimeoutSeconds -Control $Control
        if ($rc.ServerHello -and $rc.CompressionMethod -ne $null -and $rc.CompressionMethod -ne 0) { $compressionOn=$true }
        $chR=New-PWClientHello -Version $repr.Version -CipherIds $ids -ServerName $sni
        $connCount.Value++
        $rr=Invoke-PWTlsHandshake -TargetHost $targetHost -Port $targetPort -ClientHello $chR -TimeoutSeconds $TimeoutSeconds -Control $Control
        if ($rr.ServerHello) { $renegoOk=[bool]$rr.RenegotiationInfo }
    }

    # --- Cipher order (server preference) on the highest supported pre-1.3 proto ---
    $serverPref=$null
    if ($enumerate -and $tls12plus -and @($tls12plus.CipherIds).Count -ge 2) {
        $serverPref=Test-PWCipherOrder -TargetHost $targetHost -Port $targetPort -Sni $sni -Version $tls12plus.Version -CipherIds @($tls12plus.CipherIds) -TimeoutSeconds $TimeoutSeconds -Control $Control -ConnCount $connCount -MaxConnections $MaxConnections
    }

    # --- Active vulnerability probes ---
    $vulns=[Collections.Generic.List[object]]::new()
    $heartbleed=$null; $ccs=$null; $fallback=$null
    if ($AllowActiveVulnChecks -and -not $Control.Cancel) {
        $Control.Message='TLS engine: active vulnerability probes'
        $heartbleed=Test-PWHeartbleed -TargetHost $targetHost -Port $targetPort -Sni $sni -TimeoutSeconds $TimeoutSeconds -Control $Control -ConnCount $connCount
        $vulns.Add([pscustomobject]@{ Name='Heartbleed (CVE-2014-0160)'; Ergebnis=$heartbleed.Result; Detail=$heartbleed.Detail; Aktiv=$true })
        $ccs=Test-PWCcsInjection -TargetHost $targetHost -Port $targetPort -Sni $sni -TimeoutSeconds $TimeoutSeconds -Control $Control -ConnCount $connCount
        $vulns.Add([pscustomobject]@{ Name='CCS injection (CVE-2014-0224)'; Ergebnis=$ccs.Result; Detail=$ccs.Detail; Aktiv=$true })
        $preList=@($protocols | Where-Object { $_.Supported -and $_.Version -le 0x0302 })
        if ($preList.Count -ge 1) {
            $low=($preList | Sort-Object Version | Select-Object -First 1).Version
            $fallback=Test-PWFallbackScsv -TargetHost $targetHost -Port $targetPort -Sni $sni -LowVersion $low -TimeoutSeconds $TimeoutSeconds -Control $Control -ConnCount $connCount
            $vulns.Add([pscustomobject]@{ Name='TLS_FALLBACK_SCSV'; Ergebnis=$fallback.Result; Detail=$fallback.Detail; Aktiv=$true })
        }
    }

    # --- Derived vulnerability summary rows (always) ---
    $ssl3=@($protocols | Where-Object { $_.Name -eq 'SSLv3' -and $_.Supported }).Count -gt 0
    $has3des=@($uniqueCiphers | Where-Object { $_.Flags -contains '3DES' }).Count -gt 0
    $hasRc4=@($uniqueCiphers | Where-Object { $_.Flags -contains 'RC4' }).Count -gt 0
    $hasExport=@($uniqueCiphers | Where-Object { $_.Flags -contains 'EXPORT' }).Count -gt 0
    $tls10=@($protocols | Where-Object { $_.Name -eq 'TLS 1.0' -and $_.Supported }).Count -gt 0
    $vulns.Add([pscustomobject]@{ Name='POODLE (SSLv3)'; Ergebnis=$(if($ssl3){'Vulnerable'}else{'Not vulnerable'}); Detail='Derived from SSLv3 support with CBC ciphers.'; Aktiv=$false })
    $vulns.Add([pscustomobject]@{ Name='SWEET32 (3DES)'; Ergebnis=$(if($has3des){'At risk'}else{'Not at risk'}); Detail='Derived from 3DES cipher availability.'; Aktiv=$false })
    $vulns.Add([pscustomobject]@{ Name='FREAK/LOGJAM (EXPORT)'; Ergebnis=$(if($hasExport){'Vulnerable'}else{'Not vulnerable'}); Detail='Derived from EXPORT-grade cipher availability.'; Aktiv=$false })
    $vulns.Add([pscustomobject]@{ Name='RC4'; Ergebnis=$(if($hasRc4){'At risk'}else{'Not at risk'}); Detail='Derived from RC4 cipher availability.'; Aktiv=$false })
    $vulns.Add([pscustomobject]@{ Name='BEAST (TLS 1.0 CBC)'; Ergebnis=$(if($tls10){'At risk'}else{'Not at risk'}); Detail='Derived from TLS 1.0 support; largely mitigated in modern clients.'; Aktiv=$false })
    $vulns.Add([pscustomobject]@{ Name='DROWN (SSLv2)'; Ergebnis=$(if($ssl2.Supported){'Vulnerable'}else{'Not vulnerable'}); Detail=$ssl2.Detail; Aktiv=$false })

    # --- Build findings ---
    foreach ($p in $protocols) {
        if (-not $p.Supported) { continue }
        switch ($p.Name) {
            'SSLv3'   { $findings.Add((New-PWTlsFinding 'TLS-PROTO-SSL3' 'SSLv3 is supported' 'High' $urlLabel 'High (handshake)' 'The server completed an SSLv3 handshake. SSLv3 is broken (POODLE) and deprecated.' 'Disable SSLv3 entirely.')) }
            'TLS 1.0' { $findings.Add((New-PWTlsFinding 'TLS-PROTO-10' 'TLS 1.0 is supported' 'Medium' $urlLabel 'High (handshake)' 'TLS 1.0 is deprecated (PCI DSS, browsers) and exposed to BEAST-class issues.' 'Disable TLS 1.0; require TLS 1.2 or higher.')) }
            'TLS 1.1' { $findings.Add((New-PWTlsFinding 'TLS-PROTO-11' 'TLS 1.1 is supported' 'Low' $urlLabel 'High (handshake)' 'TLS 1.1 is deprecated.' 'Disable TLS 1.1; require TLS 1.2 or higher.')) }
        }
    }
    if (@($protocols | Where-Object { $_.Name -eq 'TLS 1.2' -and $_.Supported }).Count -eq 0) {
        $findings.Add((New-PWTlsFinding 'TLS-PROTO-NO12' 'TLS 1.2 is not supported' 'Medium' $urlLabel 'High (handshake)' 'The server does not offer TLS 1.2, the current baseline for most clients.' 'Enable TLS 1.2 (and TLS 1.3).'))
    }
    if (@($protocols | Where-Object { $_.Name -eq 'TLS 1.3' -and $_.Supported }).Count -eq 0) {
        $findings.Add((New-PWTlsFinding 'TLS-PROTO-NO13' 'TLS 1.3 is not supported' 'Info' $urlLabel 'High (handshake)' 'TLS 1.3 is not offered. Not a flaw, but it improves security and performance.' 'Enable TLS 1.3 where the stack supports it.'))
    }
    # Cipher findings
    $nullC=@($uniqueCiphers | Where-Object { $_.Flags -contains 'NULL' })
    $anonC=@($uniqueCiphers | Where-Object { $_.Flags -contains 'ANON' })
    $desC=@($uniqueCiphers | Where-Object { $_.Flags -contains 'DES' -and $_.Flags -notcontains '3DES' -and $_.Flags -notcontains 'EXPORT' })
    $md5C=@($uniqueCiphers | Where-Object { $_.Flags -contains 'MD5' })
    if ($nullC.Count)   { $findings.Add((New-PWTlsFinding 'TLS-CIPHER-NULL' 'NULL-encryption cipher offered' 'Critical' $urlLabel 'High (enumeration)' ('No-encryption cipher(s) offered: ' + (($nullC|ForEach-Object Name) -join ', ')) 'Remove all NULL cipher suites.')) }
    if ($anonC.Count)   { $findings.Add((New-PWTlsFinding 'TLS-CIPHER-ANON' 'Anonymous (unauthenticated) cipher offered' 'Critical' $urlLabel 'High (enumeration)' ('Anonymous cipher(s) offered: ' + (($anonC|ForEach-Object Name) -join ', ')) 'Remove all anonymous (aNULL) cipher suites.')) }
    if ($hasExport)     { $findings.Add((New-PWTlsFinding 'TLS-CIPHER-EXPORT' 'EXPORT-grade cipher offered (FREAK/LOGJAM)' 'Critical' $urlLabel 'High (enumeration)' ('EXPORT cipher(s) offered: ' + ((@($uniqueCiphers|Where-Object {$_.Flags -contains 'EXPORT'})|ForEach-Object Name) -join ', ')) 'Remove all EXPORT cipher suites.')) }
    if ($hasRc4)        { $findings.Add((New-PWTlsFinding 'TLS-CIPHER-RC4' 'RC4 cipher offered' 'High' $urlLabel 'High (enumeration)' ('RC4 cipher(s) offered: ' + ((@($uniqueCiphers|Where-Object {$_.Flags -contains 'RC4'})|ForEach-Object Name) -join ', ')) 'Remove all RC4 cipher suites (RFC 7465).')) }
    if ($desC.Count)    { $findings.Add((New-PWTlsFinding 'TLS-CIPHER-DES' 'Single-DES (56-bit) cipher offered' 'High' $urlLabel 'High (enumeration)' ('DES cipher(s) offered: ' + (($desC|ForEach-Object Name) -join ', ')) 'Remove single-DES cipher suites.')) }
    if ($has3des)       { $findings.Add((New-PWTlsFinding 'TLS-CIPHER-3DES' '3DES cipher offered (SWEET32)' 'Medium' $urlLabel 'High (enumeration)' ('64-bit block cipher(s) offered: ' + ((@($uniqueCiphers|Where-Object {$_.Flags -contains '3DES'})|ForEach-Object Name) -join ', ')) 'Remove 3DES cipher suites.')) }
    if ($md5C.Count)    { $findings.Add((New-PWTlsFinding 'TLS-CIPHER-MD5' 'MD5-MAC cipher offered' 'Medium' $urlLabel 'High (enumeration)' ('MD5-MAC cipher(s) offered: ' + (($md5C|ForEach-Object Name) -join ', ')) 'Remove cipher suites using MD5.')) }
    $pfsC=@($uniqueCiphers | Where-Object { $_.PFS })
    if ($uniqueCiphers.Count -gt 0 -and $pfsC.Count -eq 0) {
        $findings.Add((New-PWTlsFinding 'TLS-CIPHER-NOPFS' 'No forward-secrecy cipher offered' 'Low' $urlLabel 'High (enumeration)' 'Only static-key-exchange ciphers were observed; no ECDHE/DHE.' 'Prefer ECDHE/DHE cipher suites for forward secrecy.'))
    }
    if ($compressionOn) { $findings.Add((New-PWTlsFinding 'TLS-COMPRESSION' 'TLS compression enabled (CRIME)' 'Medium' $urlLabel 'High (handshake)' 'The server selected a non-null TLS compression method.' 'Disable TLS-level compression.')) }
    if (-not $renegoOk -and $repr) { $findings.Add((New-PWTlsFinding 'TLS-RENEG' 'Secure renegotiation not indicated' 'Low' $urlLabel 'Medium (handshake)' 'The ServerHello did not carry the renegotiation_info extension.' 'Enable RFC 5746 secure renegotiation.')) }

    # Certificate findings
    if ($cert -and -not ($cert.PSObject.Properties.Name -contains 'Error')) {
        if ($cert.Expired -or $cert.NotYetValid) { $findings.Add((New-PWTlsFinding 'TLS-CERT-EXPIRED' $(if($cert.Expired){'Certificate has expired'}else{'Certificate is not yet valid'}) 'High' $urlLabel 'High (certificate)' ("Valid {0} .. {1}" -f $cert.NotBeforeUtc,$cert.NotAfterUtc) 'Install a currently valid certificate.')) }
        elseif ($cert.DaysLeft -lt 30) { $findings.Add((New-PWTlsFinding 'TLS-CERT-EXPIRING' 'Certificate expires soon' 'Medium' $urlLabel 'High (certificate)' ("{0} days left (until {1})" -f $cert.DaysLeft,$cert.NotAfterUtc) 'Renew the certificate and verify automatic renewal.')) }
        if ($cert.KeySize -gt 0 -and (($cert.KeyAlgorithm -match '(?i)rsa|dsa' -and $cert.KeySize -lt 2048) -or ($cert.KeyAlgorithm -match '(?i)ec' -and $cert.KeySize -lt 256))) {
            $findings.Add((New-PWTlsFinding 'TLS-CERT-WEAKKEY' 'Weak certificate key size' 'High' $urlLabel 'High (certificate)' ("{0} {1}-bit" -f $cert.KeyAlgorithm,$cert.KeySize) 'Use at least RSA 2048-bit or ECDSA 256-bit keys.'))
        }
        if ($cert.SignatureAlgorithm -match '(?i)sha1|md5|md2') { $findings.Add((New-PWTlsFinding 'TLS-CERT-WEAKSIG' 'Weak certificate signature algorithm' 'High' $urlLabel 'High (certificate)' ("Signature: {0}" -f $cert.SignatureAlgorithm) 'Reissue the certificate with a SHA-256 (or stronger) signature.')) }
        if (-not $cert.ChainTrusted -or $cert.SelfSigned) { $findings.Add((New-PWTlsFinding 'TLS-CERT-UNTRUSTED' $(if($cert.SelfSigned){'Self-signed certificate'}else{'Certificate chain not trusted'}) 'Medium' $urlLabel 'High (certificate)' ("Self-signed: {0}; chain status: {1}" -f $cert.SelfSigned,(($cert.ChainStatus) -join ', ')) 'Install a certificate from a trusted CA with a complete chain.')) }
        if (-not $cert.HostnameMatch) { $findings.Add((New-PWTlsFinding 'TLS-CERT-HOSTNAME' 'Certificate does not match the hostname' 'Medium' $urlLabel 'High (certificate)' ("Host {0} not in CN/SAN: {1}" -f $targetHost,(($cert.SubjectAltNames) -join ', ')) 'Issue a certificate whose SAN covers the served hostname.')) }
    }

    # Active vuln findings
    if ($heartbleed -and $heartbleed.Result -eq 'Vulnerable') { $findings.Add((New-PWTlsFinding 'TLS-VULN-HEARTBLEED' 'Heartbleed (CVE-2014-0160)' 'Critical' $urlLabel 'High (active probe)' $heartbleed.Detail 'Update OpenSSL and rotate any potentially exposed keys/secrets.')) }
    if ($ccs -and $ccs.Result -eq 'Potentially vulnerable') { $findings.Add((New-PWTlsFinding 'TLS-VULN-CCS' 'Possible CCS injection (CVE-2014-0224)' 'High' $urlLabel 'Low (experimental)' $ccs.Detail 'Update OpenSSL to a patched version; confirm the finding manually.')) }
    if ($ssl2.Supported) { $findings.Add((New-PWTlsFinding 'TLS-VULN-DROWN' 'SSLv2 supported (DROWN)' 'Critical' $urlLabel 'High (handshake)' $ssl2.Detail 'Disable SSLv2 completely on this and any host sharing the key.')) }
    if ($fallback -and $fallback.Result -eq 'Not enforced') { $findings.Add((New-PWTlsFinding 'TLS-FALLBACK' 'TLS_FALLBACK_SCSV not enforced' 'Low' $urlLabel 'Medium (active probe)' $fallback.Detail 'Honour TLS_FALLBACK_SCSV to prevent protocol downgrade.')) }

    # --- Rating ---
    $rating=Get-PWTlsRating -Protocols $protocols -Ciphers $uniqueCiphers -Cert $cert -Ssl2 $ssl2.Supported -Heartbleed $heartbleed -Compression $compressionOn

    $status=if ($Control.Cancel) { 'Cancelled' } elseif ($connCount.Value -ge $MaxConnections) { 'Connection limit reached' } else { 'Finished' }
    $summary=[pscustomobject]@{
        Typ='TLS scan'; Version='4.0'; Host=$targetHost; Port=$targetPort
        StartUtc=$start.ToString('o'); EndeUtc=[DateTime]::UtcNow.ToString('o'); Status=$status
        Verbindungen=$connCount.Value; MaxVerbindungen=$MaxConnections
        Protokolle=(@($protocols | Where-Object Supported | ForEach-Object Name) -join ', ')
        Ciphers=$uniqueCiphers.Count; Enumeriert=[bool]$enumerate; ServerPraeferenz=$serverPref; Rating=$rating
        AktiveChecks=[bool]$AllowActiveVulnChecks
        Hinweis='Raw ClientHello enumeration over TCP. Protocol/cipher support reflects what THIS host negotiates; certificate parsing via X509. TLS 1.3 certificate is read via a supplementary handshake. No proof of exploitability beyond the observed handshake behaviour. Only test authorized targets.'
    }
    return [pscustomobject]@{
        Findings=$findings.ToArray(); History=$history.ToArray(); Tests=$tests.ToArray()
        Protocols=$protocols.ToArray(); Certificate=$cert; Vulnerabilities=$vulns.ToArray(); Rating=$rating; Summary=$summary
    }
}

function Test-PWSslv2 {
    # Minimal SSLv2 ClientHello. SSLv2 uses a 2-byte record length with the high
    # bit set and its own message layout. A ServerHello (msg type 4) means SSLv2
    # is live. Most modern stacks refuse the connection outright.
    param([string]$TargetHost,[int]$Port,[int]$TimeoutSeconds,[hashtable]$Control,[ref]$ConnCount)
    $client=[Net.Sockets.TcpClient]::new(); $client.ReceiveTimeout=$TimeoutSeconds*1000; $client.SendTimeout=$TimeoutSeconds*1000
    $stream=$null
    try {
        $iar=$client.BeginConnect($TargetHost,$Port,$null,$null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutSeconds*1000)) { return [pscustomobject]@{ Supported=$false; Detail='Connection timed out.' } }
        $client.EndConnect($iar); $ConnCount.Value++
        $stream=$client.GetStream(); $stream.ReadTimeout=$TimeoutSeconds*1000; $stream.WriteTimeout=$TimeoutSeconds*1000
        # SSLv2 CLIENT-HELLO offering three classic SSLv2 ciphers.
        $ciphers=[byte[]]@(0x01,0x00,0x80, 0x07,0x00,0xC0, 0x06,0x00,0x40)  # RC4-128-MD5, DES-192-EDE3, DES-64
        $body=[Collections.Generic.List[byte]]::new()
        $body.Add([byte]0x01)               # MSG-CLIENT-HELLO
        $body.Add([byte]0x00); $body.Add([byte]0x02)  # version 0x0002
        Add-PWUInt16 $body $ciphers.Length  # cipher-spec length
        Add-PWUInt16 $body 0                # session-id length
        Add-PWUInt16 $body 16               # challenge length
        $body.AddRange($ciphers)
        $chal=New-Object byte[] 16; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($chal); $body.AddRange($chal)
        $rec=[Collections.Generic.List[byte]]::new()
        $rec.Add([byte](0x80 -bor (($body.Count -shr 8) -band 0x7F))); $rec.Add([byte]($body.Count -band 0xFF))
        $rec.AddRange($body)
        $bytes=$rec.ToArray(); $stream.Write($bytes,0,$bytes.Length); $stream.Flush()
        $deadline=[DateTime]::UtcNow.AddSeconds([Math]::Min($TimeoutSeconds,6))
        $hdr=Read-PWExact $stream 2 $deadline $Control
        if ($null -eq $hdr) { return [pscustomobject]@{ Supported=$false; Detail='No SSLv2 response.' } }
        if (($hdr[0] -band 0x80) -eq 0) { return [pscustomobject]@{ Supported=$false; Detail='Response is not an SSLv2 record.' } }
        $len=(([int]$hdr[0] -band 0x7F) -shl 8) -bor [int]$hdr[1]
        if ($len -lt 1) { return [pscustomobject]@{ Supported=$false; Detail='Empty SSLv2 record.' } }
        $payload=Read-PWExact $stream ([Math]::Min($len,64)) $deadline $Control
        if ($null -eq $payload -or $payload.Length -lt 1) { return [pscustomobject]@{ Supported=$false; Detail='Truncated SSLv2 response.' } }
        if ($payload[0] -eq 0x04) { return [pscustomobject]@{ Supported=$true; Detail='Server returned an SSLv2 SERVER-HELLO.' } }
        return [pscustomobject]@{ Supported=$false; Detail=('SSLv2 message type ' + $payload[0] + ' (not a SERVER-HELLO).') }
    } catch { return [pscustomobject]@{ Supported=$false; Detail=('SSLv2 probe: ' + $_.Exception.Message) } }
    finally { if ($stream) { try { $stream.Dispose() } catch {} }; try { $client.Close() } catch {} }
}

function Get-PWTlsRating {
    param($Protocols,$Ciphers,$Cert,[bool]$Ssl2,$Heartbleed,[bool]$Compression)
    $grade='A+'
    function Cap([string]$current,[string]$max) {
        $order=@('F','D','C','B','A','A+')
        if ($order.IndexOf($max) -lt $order.IndexOf($current)) { return $max } else { return $current }
    }
    if (@($Protocols | Where-Object { $_.Name -eq 'TLS 1.3' -and $_.Supported }).Count -eq 0) { $grade=Cap $grade 'A' }
    if (@($Protocols | Where-Object { $_.Name -eq 'TLS 1.1' -and $_.Supported }).Count -gt 0) { $grade=Cap $grade 'C' }
    if (@($Protocols | Where-Object { $_.Name -eq 'TLS 1.0' -and $_.Supported }).Count -gt 0) { $grade=Cap $grade 'C' }
    if (@($Ciphers | Where-Object { $_.Flags -contains '3DES' }).Count -gt 0) { $grade=Cap $grade 'C' }
    if ($Compression) { $grade=Cap $grade 'C' }
    if (@($Ciphers | Where-Object { $_.Flags -contains 'RC4' }).Count -gt 0) { $grade=Cap $grade 'F' }
    if (@($Ciphers | Where-Object { $_.Flags -contains 'EXPORT' }).Count -gt 0) { $grade=Cap $grade 'F' }
    if (@($Ciphers | Where-Object { $_.Flags -contains 'NULL' }).Count -gt 0) { $grade=Cap $grade 'F' }
    if (@($Ciphers | Where-Object { $_.Flags -contains 'ANON' }).Count -gt 0) { $grade=Cap $grade 'F' }
    if (@($Protocols | Where-Object { $_.Name -eq 'SSLv3' -and $_.Supported }).Count -gt 0) { $grade=Cap $grade 'F' }
    if ($Ssl2) { $grade=Cap $grade 'F' }
    if ($Heartbleed -and $Heartbleed.Result -eq 'Vulnerable') { $grade=Cap $grade 'F' }
    if ($Cert -and -not ($Cert.PSObject.Properties.Name -contains 'Error')) {
        if ($Cert.Expired -or $Cert.NotYetValid) { $grade=Cap $grade 'F' }
        if ($Cert.SignatureAlgorithm -match '(?i)sha1|md5') { $grade=Cap $grade 'C' }
        if (-not $Cert.ChainTrusted) { $grade=Cap $grade 'C' }
        if (-not $Cert.HostnameMatch) { $grade=Cap $grade 'C' }
        if ($Cert.KeySize -gt 0 -and $Cert.KeySize -lt 2048 -and $Cert.KeyAlgorithm -match '(?i)rsa|dsa') { $grade=Cap $grade 'F' }
    }
    return $grade
}

Export-ModuleMember -Function Invoke-PWTlsScan,Get-PWTlsChecks,Get-PWCipherCatalog,Get-PWCipherInfo,Test-PWSslv2
