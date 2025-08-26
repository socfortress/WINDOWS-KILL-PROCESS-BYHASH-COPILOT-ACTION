[CmdletBinding()]
param(
  [string]$TargetHash,
  [string]$Arg1,
  [string]$LogPath = "$env:TEMP\KillProcessByHash-script.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

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

function NowZ { (Get-Date).ToString('yyyy-MM-dd HH:mm:sszzz') }

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp=Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  Set-Content -Path $tmp -Value ($JsonLines -join [Environment]::NewLine) -Encoding ascii -Force
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
Write-Log "=== SCRIPT START : Kill processes by SHA256 hash ==="

$lines = @()
$ts    = NowZ
$target = if ($TargetHash) { $TargetHash.ToLower() } else { "" }

try {
  if (-not $target -or $target.Length -lt 16) {  
    throw "TargetHash is required (pass -TargetHash or -Arg1)."
  }

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
    }
  }
  foreach ($m in $matches) {
    $lines += ([pscustomobject]@{
      timestamp      = $ts
      host           = $HostName
      action         = 'kill_process_by_hash'
      copilot_action = $true
      type           = 'match'
      pid            = $m.ProcessId
      process        = $m.Name
      path           = $m.ExecutablePath
      hash           = $target
    } | ConvertTo-Json -Compress -Depth 5)
  }

  foreach ($m in $matches) {
    try {
      Write-Log ("KILL attempt PID={0} ({1})" -f $m.ProcessId, $m.ExecutablePath) 'INFO'
      Stop-Process -Id $m.ProcessId -Force -ErrorAction Stop
      $stillThere = Get-Process -Id $m.ProcessId -ErrorAction SilentlyContinue
      $ok = -not [bool]$stillThere

      $killed += $m
      $lines += ([pscustomobject]@{
        timestamp      = $ts
        host           = $HostName
        action         = 'kill_process_by_hash'
        copilot_action = $true
        type           = 'verify_kill'
        pid            = $m.ProcessId
        path           = $m.ExecutablePath
        killed         = $ok
      } | ConvertTo-Json -Compress -Depth 5)

    } catch {
      $failed += $m
      Write-Log ("Failed to kill PID={0}: {1}" -f $m.ProcessId, $_.Exception.Message) 'ERROR'
      $lines += ([pscustomobject]@{
        timestamp      = $ts
        host           = $HostName
        action         = 'kill_process_by_hash'
        copilot_action = $true
        type           = 'kill_error'
        pid            = $m.ProcessId
        path           = $m.ExecutablePath
        error          = $_.Exception.Message
      } | ConvertTo-Json -Compress -Depth 5)
    }
  }
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

  $lines += ([pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'kill_process_by_hash'
    copilot_action = $true
    type           = 'verify_overall'
    target_hash    = $target
    matched        = $matches.Count
    killed         = $killed.Count
    failed         = $failed.Count
    survivors      = ($survivors | ForEach-Object { @{ pid=$_.ProcessId; process=$_.Name; path=$_.ExecutablePath } })
  } | ConvertTo-Json -Compress -Depth 6)

  $summary = [pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'kill_process_by_hash'
    copilot_action = $true
    type           = 'summary'
    target_hash    = $target
    matched        = $matches.Count
    killed         = $killed.Count
    failed         = $failed.Count
    status         = if ($killed.Count -gt 0 -and $survivors.Count -eq 0) { 'success' }
                     elseif ($matches.Count -eq 0) { 'not_found' }
                     elseif ($survivors.Count -gt 0) { 'partial' }
                     else { 'unknown' }
    duration_s     = [math]::Round(((Get-Date)-$runStart).TotalSeconds,1)
  }

  $lines = @(( $summary | ConvertTo-Json -Compress -Depth 6 )) + $lines
  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("NDJSON written to {0} ({1} lines)" -f $ARLog,$lines.Count) 'INFO'
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $err = [pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'kill_process_by_hash'
    copilot_action = $true
    type           = 'error'
    target_hash    = $target
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @(( $err | ConvertTo-Json -Compress -Depth 5 )) -Path $ARLog
  Write-Log "Error NDJSON written" 'INFO'
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
