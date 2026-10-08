# AEGIS AI SOC - Foundation Setup
$ErrorActionPreference = "Stop"

Write-Host "=== AEGIS AI SOC - FOUNDATION SETUP ===" -ForegroundColor Cyan

function Test-CommandExists {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Refresh-Path {
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($machine -and $user) { $env:Path = "$machine;$user" }
}

function Ensure-WinGet {
    if (Test-CommandExists 'winget') {
        Write-Host "WinGet already available."
        return
    }

    Write-Host "WinGet is missing. Checking App Installer registration..." -ForegroundColor Yellow

    try {
        Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Refresh-Path
    } catch {
        # Registration can fail when App Installer is not installed; continue to download path.
    }

    if (Test-CommandExists 'winget') {
        Write-Host "WinGet registered successfully."
        return
    }

    Write-Host "App Installer/WinGet is not installed. Downloading Microsoft's App Installer package..." -ForegroundColor Yellow

    $tempDir = Join-Path $env:TEMP 'aegis-winget-bootstrap'
    New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
    $bundle = Join-Path $tempDir 'Microsoft.DesktopAppInstaller.msixbundle'

    try {
        Invoke-WebRequest -Uri 'https://aka.ms/getwinget' -OutFile $bundle -UseBasicParsing
    } catch {
        throw "Unable to download Microsoft App Installer/WinGet. Check network access and rerun setup. $($_.Exception.Message)"
    }

    try {
        Add-AppxPackage -Path $bundle -ErrorAction Stop
    } catch {
        throw "Microsoft App Installer installation failed. Windows may require an updated App Installer package, supported Windows build, or a reboot. $($_.Exception.Message)"
    }

    Start-Sleep -Seconds 3
    Refresh-Path

    if (-not (Test-CommandExists 'winget')) {
        $candidate = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
        if (Test-Path $candidate) {
            $env:Path = "$([System.IO.Path]::GetDirectoryName($candidate));$env:Path"
        }
    }

    if (-not (Test-CommandExists 'winget')) {
        throw "WinGet was installed/registered but is not available in this PowerShell session. Restart PowerShell and rerun setup."
    }

    Write-Host "WinGet ready."
}

function Install-With-WinGet {
    param(
        [Parameter(Mandatory=$true)][string]$Id,
        [Parameter(Mandatory=$true)][string]$Name
    )

    Write-Host "$Name is missing. Installing with WinGet..." -ForegroundColor Yellow
    winget install --id $Id --exact --source winget --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) {
        throw "$Name installation failed."
    }

    Refresh-Path
}

Write-Host "[1/7] Host resources"
$ramGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
$drive = Get-PSDrive -Name ($PWD.Path.Substring(0,1)) -ErrorAction SilentlyContinue
$freeGB = if ($drive) { [math]::Round($drive.Free / 1GB, 1) } else { $null }
Write-Host "RAM: $ramGB GB"
if ($freeGB -ne $null) { Write-Host "Free disk: $freeGB GB" }
if ($ramGB -lt 16) { throw "At least 16 GB RAM is recommended for the AEGIS foundation." }
if ($freeGB -ne $null -and $freeGB -lt 30) { throw "At least 30 GB free disk space is required for the foundation." }

Write-Host "[2/7] WinGet"
Ensure-WinGet
winget --version

Write-Host "[3/7] Git"
if (-not (Test-CommandExists 'git')) { Install-With-WinGet 'Git.Git' 'Git' }
git --version

Write-Host "[4/7] Python 3.11"
$pythonOk = Test-CommandExists 'python'
if ($pythonOk) {
    $pyVersion = (& python --version 2>&1)
    $pythonOk = $pyVersion -match 'Python 3\.11'
}
if (-not $pythonOk) {
    Install-With-WinGet 'Python.Python.3.11' 'Python 3.11'
}
Refresh-Path
$pyVersion = (& python --version 2>&1)
if ($pyVersion -notmatch 'Python 3\.11') { throw "Python 3.11 is required. Detected: $pyVersion" }
Write-Host $pyVersion
if (-not (Test-Path '.venv\Scripts\python.exe')) { python -m venv .venv }
Write-Host "Python virtual environment ready: .venv"

Write-Host "[5/7] Node.js 20 + npm"
$nodeOk = Test-CommandExists 'node'
if ($nodeOk) {
    $nodeVersion = node --version
    $nodeOk = $nodeVersion -match '^v20\.'
}
if (-not $nodeOk) { Install-With-WinGet 'OpenJS.NodeJS.LTS' 'Node.js 20 LTS' }
Refresh-Path
$nodeVersion = node --version
if ($nodeVersion -notmatch '^v20\.') { throw "Node.js 20 LTS is required. Detected: $nodeVersion" }
node --version
npm --version

Write-Host "[6/7] WSL 2"
$wslAvailable = Test-CommandExists 'wsl'
if (-not $wslAvailable) {
    Write-Host "WSL is missing. Installing WSL without a Linux distribution..." -ForegroundColor Yellow
    wsl --install --no-distribution
    if ($LASTEXITCODE -ne 0) { throw "WSL installation failed." }
    Write-Host "WSL installation requested. Windows may require a reboot before Docker can use WSL 2." -ForegroundColor Yellow
}
if (Test-CommandExists 'wsl') { wsl --status }

Write-Host "[7/7] Docker Desktop + Compose"
if (-not (Test-CommandExists 'docker')) {
    Install-With-WinGet 'Docker.DockerDesktop' 'Docker Desktop'
}
Refresh-Path
if (-not (Test-CommandExists 'docker')) {
    throw "Docker CLI is still unavailable after Docker Desktop installation. Restart PowerShell and rerun setup."
}
docker --version

$compose = docker compose version 2>&1
if ($LASTEXITCODE -ne 0) { throw "Docker Compose v2 is unavailable. Repair/update Docker Desktop." }
Write-Host $compose

Write-Host "Checking Docker daemon..."
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker Desktop is installed but the Docker daemon is not running." -ForegroundColor Yellow
    Write-Host "Start Docker Desktop, wait until it is running, then rerun this script."
    throw "Docker daemon is not reachable."
}
Write-Host "Docker daemon is running."

Write-Host ""
Write-Host "=== FOUNDATION SETUP PASSED ===" -ForegroundColor Green
Write-Host "No AEGIS application/infrastructure has been installed yet."
