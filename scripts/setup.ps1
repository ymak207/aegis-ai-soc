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
    # WinGet is normally delivered through Microsoft App Installer. Microsoft
    # also provides the supported PowerShell bootstrap/repair path through
    # Microsoft.WinGet.Client when App Installer/WinGet is absent or broken.
    if (Test-CommandExists 'winget') {
        try {
            $version = (& winget --version 2>$null)
            if ($LASTEXITCODE -eq 0 -and $version) {
                Write-Host "WinGet already available: $version"
                return
            }
        } catch {
            # Continue to the supported repair path below.
        }
    }

    Write-Host "WinGet is missing or not functioning. Bootstrapping WinGet using Microsoft's supported PowerShell repair path..." -ForegroundColor Yellow

    try {
        # Windows PowerShell 5.1 may need TLS 1.2 explicitly for PSGallery.
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
        if (-not $nuget) {
            Write-Host "Installing NuGet package provider..."
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
        }

        $module = Get-Module -ListAvailable -Name Microsoft.WinGet.Client | Select-Object -First 1
        if (-not $module) {
            Write-Host "Installing Microsoft.WinGet.Client from PowerShell Gallery..."
            Install-Module -Name Microsoft.WinGet.Client -Force -Repository PSGallery -AllowClobber -ErrorAction Stop
        } else {
            Write-Host "Microsoft.WinGet.Client module already available: $($module.Version)"
        }

        Import-Module Microsoft.WinGet.Client -Force -ErrorAction Stop
        Write-Host "Repairing/bootstrapping WinGet..."
        Repair-WinGetPackageManager -Force -Latest -ErrorAction Stop
    } catch {
        throw "WinGet bootstrap/repair failed. Windows must support App Installer/WinGet and the machine needs network access and administrator privileges. $($_.Exception.Message)"
    }

    Start-Sleep -Seconds 3
    Refresh-Path

    $wingetCandidates = @(
        (Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'),
        (Join-Path $env:ProgramFiles 'WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\winget.exe')
    )

    foreach ($candidate in $wingetCandidates) {
        if (Test-Path $candidate) {
            $candidateDir = Split-Path $candidate -Parent
            if ($env:Path -notlike "*$candidateDir*") {
                $env:Path = "$candidateDir;$env:Path"
            }
        }
    }

    if (-not (Test-CommandExists 'winget')) {
        throw "WinGet bootstrap completed but winget.exe is not available in this PowerShell session. Close PowerShell, open a new elevated PowerShell window, and rerun setup."
    }

    $version = (& winget --version 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $version) {
        throw "WinGet is present but not functioning. Rerun setup from a new elevated PowerShell session."
    }

    Write-Host "WinGet ready: $version"
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
