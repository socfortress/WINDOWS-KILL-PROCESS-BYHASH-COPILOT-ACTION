[CmdletBinding()]
param(
  [string]$TargetHash,
  [string]$LogPath = "$env:TEMP\KillProcessByHash-script.log",
  [string]$ARLog = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)
if ($Arg1 -and -not $TargetHash) { $TargetHash = $Arg1 }

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep = 5
$runStart = Get-Date

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line = "[$ts][$Level] $Message"
  switch ($Level) {
    'ERROR' { Write-Host $line -ForegroundColor Red }
    'WARN'  { Write-Host $line -ForegroundColor Yellow }
    'DEBUG' { if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { Write-Verbose $line } }
    default { Write-Host $line }
  }
  Add-Content -Path $LogPath -Value $line
}

function Rotate-Log {
  if (Test-Path $LogPath -PathType Leaf) {
    if ((Get-Item $LogPath).Length/1KB -gt $LogMaxKB) {
      for ($i = $LogKeep - 1; $i -ge 0; $i--) {
        $old = "$LogPath.$i"
        $new = "$LogPath." + ($i + 1)
        if (Test-Path $old) { Rename-Item $old $new -Force }
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function Get-FileHashSafe {
  param([string]$Path)
  try {
    if (Test-Path $Path -PathType Leaf) {
      return (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
    }
  } catch {
    Write-Log "Could not hash ${Path}: $_" 'WARN'
  }
  return $null
}

Rotate-Log
Write-Log "=== SCRIPT START : Kill processes by hash $TargetHash ==="

$killed = @()

try {
  $allProcs = Get-Process | ForEach-Object {
    $proc = $_
    $exe = $null
    try { $exe = $_.Path } catch {}
    if (-not $exe) { return }
    $hash = Get-FileHashSafe -Path $exe
    if ($hash -and ($hash -eq $TargetHash.ToLower())) {
      Write-Log "MATCH: Killing PID $($_.Id) ($exe)" 'INFO'
      try {
        Stop-Process -Id $_.Id -Force -ErrorAction Stop
        $killed += [PSCustomObject]@{
          pid = $_.Id
          process = $_.ProcessName
          path = $exe
          hash = $hash
        }
      } catch {
        Write-Log "Failed to kill PID $($_.Id): $_" 'ERROR'
      }
    }
  }

  $results = [PSCustomObject]@{
    timestamp = (Get-Date).ToString('o')
    host = $HostName
    action = 'kill_process_by_hash'
    target = $TargetHash
    killed = $killed
    status = if ($killed.Count -gt 0) { 'success' } else { 'not_found' }
  }
  $json = $results | ConvertTo-Json -Compress -Depth 3
  $tempFile = "$env:TEMP\arlog.tmp"
  Set-Content -Path $tempFile -Value $json -Encoding ascii -Force

  try {
    Move-Item -Path $tempFile -Destination $ARLog -Force
    Write-Log "Log file replaced at $ARLog" 'INFO'
  } catch {
    Move-Item -Path $tempFile -Destination "$ARLog.new" -Force
    Write-Log "Log locked, wrote results to $ARLog.new" 'WARN'
  }
} catch {
  Write-Log $_.Exception.Message 'ERROR'
  $errorObj = [PSCustomObject]@{
    timestamp = (Get-Date).ToString('o')
    host = $HostName
    action = 'kill_process_by_hash'
    status = 'error'
    error = $_.Exception.Message
  }
  $json = $errorObj | ConvertTo-Json -Compress -Depth 3
  $fallback = "$ARLog.new"
  Set-Content -Path $fallback -Value $json -Encoding ascii -Force
  Write-Log "Error logged to $fallback" 'WARN'
} finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
