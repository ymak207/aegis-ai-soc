# AEGIS AI SOC - Foundation Verification
$ErrorActionPreference = "Continue"
$failed = 0

function Pass($msg) { Write-Host "[PASS] $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "[FAIL] $msg" -ForegroundColor Red; $script:failed++ }
function Check-Command($name, $label) {
    if (Get-Command $name -ErrorAction SilentlyContinue) { Pass $label; return $true }
    Fail "$label - command not found: $name"; return $false
}

Write-Host "=== AEGIS AI SOC - FOUNDATION VERIFICATION ===" -ForegroundColor Cyan

$ramGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
if ($ramGB -ge 16) { Pass "RAM >= 16 GB ($ramGB GB)" } else { Fail "RAM < 16 GB ($ramGB GB)" }

$drive = Get-PSDrive -Name ($PWD.Path.Substring(0,1)) -ErrorAction SilentlyContinue
if ($drive) {
    $freeGB = [math]::Round($drive.Free / 1GB, 1)
    if ($freeGB -ge 30) { Pass "Free disk >= 30 GB ($freeGB GB)" } else { Fail "Free disk < 30 GB ($freeGB GB)" }
} else { Fail "Could not determine free disk space" }

if (Check-Command 'winget' 'WinGet') { winget --version }

if (Check-Command 'git' 'Git') {
    if ((git rev-parse --is-inside-work-tree 2>$null) -eq 'true') { Pass 'Git repository' } else { Fail 'Git repository' }
    $branch = git branch --show-current 2>$null
    if ($branch -eq 'main') { Pass 'Git branch = main' } else { Fail "Git branch is '$branch', expected main" }
    if (git remote get-url origin 2>$null) { Pass 'GitHub origin configured' } else { Fail 'GitHub origin not configured' }
}

if (Check-Command 'python' 'Python') {
    $v = python --version 2>&1
    if ($v -match 'Python 3\.11') { Pass "Python 3.11 ($v)" } else { Fail "Python 3.11 required; detected $v" }
}
if (Test-Path '.venv\Scripts\python.exe') { Pass 'Python virtual environment (.venv)' } else { Fail 'Python virtual environment (.venv) missing' }

if (Check-Command 'node' 'Node.js') {
    $nv = node --version
    if ($nv -match '^v20\.') { Pass "Node.js 20 ($nv)" } else { Fail "Node.js 20 required; detected $nv" }
}
Check-Command 'npm' 'npm' | Out-Null

if (Check-Command 'wsl' 'WSL command') { Pass 'WSL command available' }

if (Check-Command 'docker' 'Docker CLI') {
    docker --version
    $compose = docker compose version 2>&1
    if ($LASTEXITCODE -eq 0) { Pass 'Docker Compose v2' } else { Fail 'Docker Compose v2 unavailable' }
    docker info *> $null
    if ($LASTEXITCODE -eq 0) { Pass 'Docker daemon running' } else { Fail 'Docker daemon not reachable' }
}

Write-Host ''
if ($failed -eq 0) {
    Write-Host '============================================' -ForegroundColor Green
    Write-Host 'FOUNDATION VERIFICATION PASSED' -ForegroundColor Green
    Write-Host '============================================' -ForegroundColor Green
    exit 0
}
Write-Host '============================================' -ForegroundColor Red
Write-Host "FOUNDATION VERIFICATION FAILED: $failed CHECK(S)" -ForegroundColor Red
Write-Host '============================================' -ForegroundColor Red
exit 1
