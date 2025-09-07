[CmdletBinding()]
param(
  [string]$TargetHash,
  [string]$Arg1,
  [string]$LogPath = "$env:TEMP\KillProcessByHash-script.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

# Arg1 override preserved
if ($Arg1 -and -not $TargetHash) { $TargetHash = $Arg1 }

$ErrorActionPreference = 'Stop'
$HostName  = $env:COMPUTERNAME
$LogMaxKB  = 100
$LogKeep   = 5
$runStart  = Get-Date

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line="[$ts][$Level] $Message"
  switch($Level){
    'ERROR'{Write-Host $line -ForegroundColor Red}
    'WARN' {Write-Host $line -ForegroundColor Yellow}
    'DEBUG'{ if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { Write-Verbose $line } }
    default{Write-Host $line}
  }
  Add-Content -Path $LogPath -Value $line -Encoding utf8
}

function Rotate-Log {
  if(Test-Path $LogPath -PathType Leaf){
    if((Get-Item $LogPath).Length/1KB -gt $LogMaxKB){
      for($i=$LogKeep-1;$i -ge 0;$i--){
        $old="$LogPath.$i";$new="$LogPath."+($i+1)
        if(Test-Path $old){Rename-Item $old $new -Force}
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function To-ISO8601 {
  param($dt)
  if ($dt -and $dt -is [datetime] -and $dt.Year -gt 1900) { $dt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
}

function New-NdjsonLine { param([hashtable]$Data) ($Data | ConvertTo-Json -Compress -Depth 7) }

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp = Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
  $payload = ($JsonLines -join [Environment]::NewLine) + [Environment]::NewLine
  Set-Content -Path $tmp -Value $payload -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force } catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

function Get-FileHashSafe {
  param([string]$Path)
  try {
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
      return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
    }
  } catch {
    Write-Log ("Could not hash {0}: {1}" -f $Path, $_.Exception.Message) 'WARN'
  }
  return $null
}

Rotate-Log
Write-Log "=== SCRIPT START : Kill processes by SHA256 hash (host=$HostName) ==="

$lines = New-Object System.Collections.ArrayList
$tsNow = To-ISO8601 (Get-Date)
$target = if ($TargetHash) { $TargetHash.ToLower() } else { "" }

try {
  if (-not $target -or $target.Length -lt 16) {
    throw "TargetHash is required (pass -TargetHash or -Arg1) and should be at least 16 chars for safety."
  }

  # Source/verify metadata
  [void]$lines.Add( (New-NdjsonLine @{
    timestamp      = $tsNow
    host           = $HostName
    action         = 'kill_process_by_hash'
    copilot_action = $true
    item           = 'verify_source'
    description    = 'Processes enumerated via CIM Win32_Process; executable SHA256 via Get-FileHash'
    target_hash    = $target
  }) )

  $procList = Get-CimInstance Win32_Process -ErrorAction Stop |
              Select-Object ProcessId, Name, ExecutablePath
  $hashCache = @{}
  $matches   = @()
  $killed    = @()
  $failed    = @()

  foreach ($p in $procList) {
    $exe = $p.ExecutablePath
    if ([string]::IsNullOrWhiteSpace($exe)) { continue }

    if (-not $hashCache.ContainsKey($exe)) {
      $hashCache[$exe] = Get-FileHashSafe -Path $exe
    }
    $h = $hashCache[$exe]
    if ($null -ne $h -and $h -eq $target) {
      $matches += $p
      [void]$lines.Add( (New-NdjsonLine @{
        timestamp      = $tsNow
        host           = $HostName
        action         = 'kill_process_by_hash'
        copilot_action = $true
        item           = 'match'
        description    = "Matched target hash for process '$($p.Name)' (PID $($p.ProcessId))"
        pid            = $p.ProcessId
        process        = $p.Name
        path           = $p.ExecutablePath
        hash           = $target
      }) )
    }
  }

  foreach ($m in $matches) {
    try {
      Write-Log ("KILL attempt PID={0} ({1})" -f $m.ProcessId, $m.ExecutablePath) 'INFO'
      [void]$lines.Add( (New-NdjsonLine @{
        timestamp      = $tsNow
        host           = $HostName
        action         = 'kill_process_by_hash'
        copilot_action = $true
        item           = 'kill_attempt'
        description    = "Attempting Stop-Process -Id $($m.ProcessId) -Force"
        pid            = $m.ProcessId
        path           = $m.ExecutablePath
      }) )

      Stop-Process -Id $m.ProcessId -Force -ErrorAction Stop

      Start-Sleep -Milliseconds 150
      $stillThere = Get-Process -Id $m.ProcessId -ErrorAction SilentlyContinue
      $ok = -not [bool]$stillThere
      if ($ok) { $killed += $m }

      [void]$lines.Add( (New-NdjsonLine @{
        timestamp      = $tsNow
        host           = $HostName
        action         = 'kill_process_by_hash'
        copilot_action = $true
        item           = 'verify_kill'
        description    = "Verification after kill attempt (PID $($m.ProcessId))"
        pid            = $m.ProcessId
        path           = $m.ExecutablePath
        killed         = $ok
      }) )
    } catch {
      $failed += $m
      Write-Log ("Failed to kill PID={0}: {1}" -f $m.ProcessId, $_.Exception.Message) 'ERROR'
      [void]$lines.Add( (New-NdjsonLine @{
        timestamp      = $tsNow
        host           = $HostName
        action         = 'kill_process_by_hash'
        copilot_action = $true
        item           = 'kill_error'
        description    = "Kill attempt failed (PID $($m.ProcessId))"
        pid            = $m.ProcessId
        path           = $m.ExecutablePath
        error          = $_.Exception.Message
      }) )
    }
  }

  # Re-scan for survivors of same hash
  $survivors = @()
  $procList2 = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
               Select-Object ProcessId, Name, ExecutablePath
  foreach ($p2 in $procList2) {
    $exe2 = $p2.ExecutablePath
    if ([string]::IsNullOrWhiteSpace($exe2)) { continue }
    if (-not $hashCache.ContainsKey($exe2)) {
      $hashCache[$exe2] = Get-FileHashSafe -Path $exe2
    }
    $h2 = $hashCache[$exe2]
    if ($null -ne $h2 -and $h2 -eq $target) {
      $survivors += $p2
    }
  }

  [void]$lines.Add( (New-NdjsonLine @{
    timestamp      = $tsNow
    host           = $HostName
    action         = 'kill_process_by_hash'
    copilot_action = $true
    item           = 'verify_overall'
    description    = 'Overall verification after all kill attempts'
    target_hash    = $target
    matched        = $matches.Count
    killed         = $killed.Count
    failed         = $failed.Count
    survivors      = ($survivors | ForEach-Object { @{ pid=$_.ProcessId; process=$_.Name; path=$_.ExecutablePath } })
  }) )

  # Summary first
  $status =
    if ($killed.Count -gt 0 -and $survivors.Count -eq 0) { 'success' }
    elseif ($matches.Count -eq 0) { 'not_found' }
    elseif ($survivors.Count -gt 0) { 'partial' }
    else { 'unknown' }

  $summary = New-NdjsonLine @{
    timestamp      = $tsNow
    host           = $HostName
    action         = 'kill_process_by_hash'
    copilot_action = $true
    item           = 'summary'
    description    = 'Run summary and outcome'
    target_hash    = $target
    matched        = $matches.Count
    killed         = $killed.Count
    failed         = $failed.Count
    status         = $status
    duration_s     = [math]::Round(((Get-Date)-$runStart).TotalSeconds,1)
  }
  $lines = ,$summary + $lines

  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("NDJSON written to {0} ({1} lines)" -f $ARLog,$lines.Count) 'INFO'
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $err = New-NdjsonLine @{
    timestamp      = To-ISO8601 (Get-Date)
    host           = $HostName
    action         = 'kill_process_by_hash'
    copilot_action = $true
    item           = 'error'
    description    = 'Unhandled error'
    target_hash    = $target
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @($err) -Path $ARLog
  Write-Log "Error NDJSON written" 'INFO'
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
