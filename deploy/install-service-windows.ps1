<#
.SYNOPSIS
  Register Credential Airlock to start at logon for the CURRENT Windows user.

.DESCRIPTION
  DPAPI seals the vault to the account that runs the airlock, so it must run as
  the SAME user that uses the agents — NOT as SYSTEM. This registers a Scheduled
  Task that runs `airlock start` at logon, at LIMITED (non-elevated) integrity.

  Run in a normal (non-admin) PowerShell from either a source checkout after
  `npm run build`, or from the installed npm package:
    $pkg = Join-Path (npm root -g) 'credential-airlock'
    & (Join-Path $pkg 'deploy\install-service-windows.ps1')
  Remove with:
    Unregister-ScheduledTask -TaskName 'CredentialAirlock' -Confirm:$false
#>
[CmdletBinding()]
param(
  [string]$TaskName = 'CredentialAirlock'
)
$ErrorActionPreference = 'Stop'

$node = (Get-Command node -ErrorAction Stop).Source
$entry = (Resolve-Path (Join-Path $PSScriptRoot '..\dist\index.js')).Path
$workdir = Split-Path $entry -Parent

if (-not (Test-Path $entry)) { throw "dist\index.js not found. Install the npm package or run 'npm run build' in a source checkout first." }

$action = New-ScheduledTaskAction -Execute $node -Argument "`"$entry`" start" -WorkingDirectory $workdir
$trigger = New-ScheduledTaskTrigger -AtLogOn
# Least privilege: run as the current interactive user, NOT elevated.
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
  -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
  -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings -Force | Out-Null

Write-Host "Registered scheduled task '$TaskName'."
Write-Host "It runs 'airlock start' at logon as $env:USERNAME (non-elevated, DPAPI-sealed to this account)."
Write-Host "Start it now with:  Start-ScheduledTask -TaskName '$TaskName'"
