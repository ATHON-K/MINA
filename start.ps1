#Requires -Version 5.1
<#
.SYNOPSIS
    MINA System Startup Script — Portable, self-configuring
.DESCRIPTION
    Automatically finds Python/Node, bootstraps environment, checks ports, starts services.
.PARAMETER Mode
    dev | prod-lite | backend-only | frontend-only | test-only
.PARAMETER NoInstall
    Skip npm install and pip install steps
.PARAMETER Bootstrap
    Force-recreate venv and reinstall from scratch
.PARAMETER BackendPort
    Override backend port (default 8000)
.PARAMETER FrontendPort
    Override frontend port (default 3000)
#>
param(
    [ValidateSet("dev","prod-lite","backend-only","frontend-only","test-only")]
    [string]$Mode = "dev",
    [switch]$NoInstall,
    [switch]$Bootstrap,
    [int]$BackendPort  = 0,
    [int]$FrontendPort = 0
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Force UTF-8 mode for Python to avoid encoding errors on paths with non-ASCII chars
$env:PYTHONUTF8     = "1"
$env:PYTHONIOENCODING = "utf-8"

# Guard: do not inherit stale overrides from caller scope
$MINA_PYTHON        = "C:\Program Files\Python312\python.exe"
$MINA_NODE          = "C:\Program Files\nodejs\node.exe"
$MINA_BACKEND_PORT  = 8000
$MINA_FRONTEND_PORT = 3000

# ============================================================
# 1. LOAD LOCAL OVERRIDES  (toolchain.local.ps1)
# ============================================================
$LocalConfig = Join-Path $PSScriptRoot "toolchain.local.ps1"
if (Test-Path $LocalConfig) {
    Write-Host "  [cfg] Loading local overrides: toolchain.local.ps1" -ForegroundColor DarkCyan
    . $LocalConfig
}

# Non-ASCII path warning
if ($PSScriptRoot -match '[^\x00-\x7F]') {
    Write-Warn "Project path contains non-ASCII characters: $PSScriptRoot"
    Write-Warn "Some tools may fail. Consider moving to an ASCII-only path (e.g., C:\projects\mina)."
}

# ============================================================
# 2. HELPER FUNCTIONS
# ============================================================
function Write-Banner([string]$text, [string]$color = "Cyan") {
    Write-Host ""
    Write-Host ("  " + ("─" * 48)) -ForegroundColor $color
    Write-Host "   $text" -ForegroundColor $color
    Write-Host ("  " + ("─" * 48)) -ForegroundColor $color
    Write-Host ""
}

function Write-Step([string]$msg) {
    Write-Host "  >> $msg" -ForegroundColor Cyan
}

function Write-Ok([string]$msg) {
    Write-Host "  [OK] $msg" -ForegroundColor Green
}

function Write-Warn([string]$msg) {
    Write-Host "  [??] $msg" -ForegroundColor Yellow
}

function Write-Fail([string]$msg) {
    Write-Host "  [!!] $msg" -ForegroundColor Red
}

# ============================================================
# 3. RESOLVE PYTHON (priority chain)
# ============================================================
function Resolve-Python {
    # Build priority candidate list
    $candidates = [System.Collections.Generic.List[string]]::new()

    if ($env:MINA_PYTHON -and $env:MINA_PYTHON.Trim() -ne "") {
        $candidates.Add($env:MINA_PYTHON)
    }
    if ($MINA_PYTHON -and $MINA_PYTHON.Trim() -ne "") {
        $candidates.Add($MINA_PYTHON)
    }
    $candidates.Add((Join-Path $PSScriptRoot "backend\.venv\Scripts\python.exe"))
    $candidates.Add((Join-Path $PSScriptRoot "backend\venv\Scripts\python.exe"))
    $candidates.Add("py")
    $candidates.Add("python3.11")
    $candidates.Add("python3")
    $candidates.Add("python")

    foreach ($exe in $candidates) {
        if (-not $exe) { continue }
        try {
            $ver = & $exe --version 2>&1
            if ($LASTEXITCODE -eq 0 -and "$ver" -match "Python 3\.(\d+)") {
                $minor = [int]$Matches[1]
                if ($minor -ge 11) {
                    Write-Ok "Python: $exe  ($ver)"
                    return $exe
                }
            }
        } catch { continue }
    }

    Write-Fail "Python 3.11+ not found."
    Write-Host "  --> Download: https://www.python.org/downloads/" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"; exit 1
}

# ============================================================
# 4. RESOLVE NODE
# ============================================================
function Resolve-Node {
    $candidates = [System.Collections.Generic.List[string]]::new()

    if ($env:MINA_NODE -and $env:MINA_NODE.Trim() -ne "") {
        $candidates.Add($env:MINA_NODE)
    }
    if ($MINA_NODE -and $MINA_NODE.Trim() -ne "") {
        $candidates.Add($MINA_NODE)
    }
    $candidates.Add("node")

    foreach ($exe in $candidates) {
        if (-not $exe) { continue }
        try {
            $ver = & $exe --version 2>&1
            if ($LASTEXITCODE -eq 0 -and "$ver" -match "^v(\d+)") {
                $major = [int]$Matches[1]
                if ($major -ge 18) {
                    Write-Ok "Node.js: $exe  ($ver)"
                    return $exe
                } else {
                    Write-Warn "Node.js $ver found but requires v18+, skipping."
                }
            }
        } catch { continue }
    }

    Write-Fail "Node.js 18+ not found."
    Write-Host "  --> Download: https://nodejs.org/" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"; exit 1
}

# ============================================================
# 5. PORT CHECKING
# ============================================================
function Test-PortFree([int]$Port) {
    $listener = $null
    try {
        $addr = [System.Net.IPAddress]::Loopback
        $listener = [System.Net.Sockets.TcpListener]::new($addr, $Port)
        $listener.Start()
        return $true
    } catch {
        return $false
    } finally {
        if ($null -ne $listener) { try { $listener.Stop() } catch {} }
    }
}

function Get-FreePort([int]$Preferred) {
    if (Test-PortFree $Preferred) { return $Preferred }
    Write-Warn "Port $Preferred is in use. Scanning for free port..."
    for ($p = $Preferred + 1; $p -le ($Preferred + 20); $p++) {
        if (Test-PortFree $p) {
            Write-Warn "Using port $p instead."
            return $p
        }
    }
    Write-Fail "No free port found near $Preferred."
    Read-Host "Press Enter to exit"; exit 1
}

# ============================================================
# 6. ENV BOOTSTRAP
# ============================================================
function Initialize-Env {
    $envFile    = Join-Path $PSScriptRoot "backend\.env"
    $envExample = Join-Path $PSScriptRoot "backend\.env.example"

    if (-not (Test-Path $envFile)) {
        if (Test-Path $envExample) {
            Copy-Item $envExample $envFile -Force
            Write-Warn ".env created from .env.example. Fill in API keys before scanning!"
        } else {
            Write-Fail "Neither .env nor .env.example found in backend/."
            Read-Host "Press Enter to exit"; exit 1
        }
    } else {
        Write-Ok ".env found."
    }

    # Warn on placeholder keys
    $envContent = Get-Content $envFile -Raw -ErrorAction SilentlyContinue
    $placeholders = @(
        "YOUR_DEEPSEEK_API_KEY_HERE",
        "YOUR_SHODAN_API_KEY_HERE",
        "YOUR_VIRUSTOTAL_KEY_HERE"
    )
    foreach ($ph in $placeholders) {
        if ($envContent -and $envContent.Contains($ph)) {
            Write-Warn "  .env still has placeholder: $ph"
        }
    }
}

# ============================================================
# 7. VENV BOOTSTRAP
# ============================================================
function Initialize-Venv([string]$PythonExe) {
    $venvDir    = Join-Path $PSScriptRoot "backend\.venv"
    $venvPython = Join-Path $venvDir "Scripts\python.exe"

    if ($Bootstrap -or -not (Test-Path $venvPython)) {
        Write-Step "Creating virtual environment at backend\.venv ..."
        & $PythonExe -m venv $venvDir | Out-Host
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "venv creation failed."
            Read-Host "Press Enter to exit"; exit 1
        }
        Write-Ok "venv created."
    } else {
        Write-Ok "venv found: backend\.venv"
    }

    if (-not $NoInstall) {
        $reqFile = Join-Path $PSScriptRoot "backend\requirements.txt"
        if (Test-Path $reqFile) {
            Write-Step "Installing Python dependencies..."
            & $venvPython -m pip install -r $reqFile --no-color | Out-Host
            Write-Ok "Python packages ready."
        } else {
            Write-Warn "requirements.txt not found — skipping pip install."
        }
    }

    return $venvPython
}

# ============================================================
# 8. NODE MODULES INSTALL
# ============================================================
function Initialize-NodeModules([string]$NodeExe) {
    if ($NoInstall) { return }

    $frontendDir = Join-Path $PSScriptRoot "frontend"
    $nodeModules = Join-Path $frontendDir "node_modules"

    if (-not (Test-Path $nodeModules) -or $Bootstrap) {
        Write-Step "Running npm install in frontend/..."
        Push-Location $frontendDir
        try {
            npm install
            if ($LASTEXITCODE -ne 0) { throw "npm install failed (exit $LASTEXITCODE)" }
            Write-Ok "npm dependencies installed."
        } finally {
            Pop-Location
        }
    } else {
        Write-Ok "frontend/node_modules found."
    }
}

# ============================================================
# 9. LAUNCH BACKEND (new window)
# ============================================================
function Start-Backend([string]$PythonExe, [int]$Port) {
    $backendDir = Join-Path $PSScriptRoot "backend"
    $tmpScript = [System.IO.Path]::GetTempFileName() + ".ps1"
    @"
`$host.UI.RawUI.WindowTitle = 'MINA Backend :$Port'
Write-Host '  ================================================' -ForegroundColor DarkRed
Write-Host '   MINA BACKEND  -- http://localhost:$Port'        -ForegroundColor Red
Write-Host '   API docs      -- http://localhost:$Port/docs'   -ForegroundColor DarkYellow
Write-Host '  ================================================' -ForegroundColor DarkRed
Set-Location '$backendDir'
& '$PythonExe' -m uvicorn main:app --host 0.0.0.0 --port $Port --reload
if (`$LASTEXITCODE -ne 0) { Read-Host 'Backend exited. Press Enter to close' }
"@ | Out-File -FilePath $tmpScript -Encoding utf8
    Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-File", $tmpScript
    Write-Ok "Backend launched in new window (port $Port)."
}

# ============================================================
# 10. LAUNCH FRONTEND (new window)
# ============================================================
function Start-Frontend([string]$NodeExe, [int]$Port, [int]$ApiPort) {
    $frontendDir = Join-Path $PSScriptRoot "frontend"
    $tmpScript = [System.IO.Path]::GetTempFileName() + ".ps1"
    @"
`$host.UI.RawUI.WindowTitle = 'MINA Frontend :$Port'
Write-Host '  ================================================' -ForegroundColor DarkCyan
Write-Host '   MINA FRONTEND -- http://localhost:$Port'        -ForegroundColor Cyan
Write-Host '  ================================================' -ForegroundColor DarkCyan
Set-Location '$frontendDir'
`$env:VITE_API_URL = 'http://localhost:$ApiPort'
npm run dev -- --port $Port
if (`$LASTEXITCODE -ne 0) { Read-Host 'Frontend exited. Press Enter to close' }
"@ | Out-File -FilePath $tmpScript -Encoding utf8
    Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-File", $tmpScript
    Write-Ok "Frontend launched in new window (port $Port)."
}

# ============================================================
# 11. WAIT FOR BACKEND HEALTH
# ============================================================
function Wait-ForBackend([int]$Port, [int]$MaxWait = 30) {
    Write-Step "Waiting for backend to be ready..."
    $waited = 0
    while ($waited -lt $MaxWait) {
        Start-Sleep -Seconds 1
        $waited++
        try {
            $resp = Invoke-WebRequest -Uri "http://localhost:$Port/health" `
                                      -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
            if ($resp.StatusCode -eq 200) {
                Write-Ok "Backend ready after ${waited}s."
                return
            }
        } catch {}
        Write-Host "  . ($waited/$MaxWait)" -NoNewline
    }
    Write-Host ""
    Write-Warn "Backend did not respond after ${MaxWait}s — it may still be starting."
}

# ============================================================
# 12. MAIN ENTRY POINT
# ============================================================

Write-Banner "MINA — Multi Intelligence Network Agent  v2.0"

# Step A: Resolve tools
Write-Step "Resolving toolchain..."
$PythonExe = Resolve-Python
$NodeExe   = if ($Mode -ne "backend-only" -and $Mode -ne "test-only") {
    Resolve-Node
} else { $null }

# Step B: Bootstrap .env
Write-Step "Checking .env..."
Initialize-Env

# Step C: Bootstrap venv
Write-Step "Setting up Python virtual environment..."
$BackendPython = Initialize-Venv $PythonExe

# Step D: Resolve ports
$preferredBackend = if ($BackendPort -gt 0) { $BackendPort } `
    elseif ($MINA_BACKEND_PORT -gt 0) { $MINA_BACKEND_PORT } `
    else { 8000 }
$resolvedBackendPort = Get-FreePort ([int]$preferredBackend)

if ($Mode -notin @("backend-only","test-only")) {
    $preferredFrontend = if ($FrontendPort -gt 0) { $FrontendPort } `
        elseif ($MINA_FRONTEND_PORT -gt 0) { $MINA_FRONTEND_PORT } `
        else { 3000 }
    $resolvedFrontendPort = Get-FreePort ([int]$preferredFrontend)
} else {
    $resolvedFrontendPort = 0
}

# Print startup summary
$buildStamp = Get-Date -Format "yyyyMMdd-HHmmss"
try {
    $gitHash = git -C $PSScriptRoot rev-parse --short HEAD 2>$null
    if ($LASTEXITCODE -eq 0 -and $gitHash) { $buildStamp = "$buildStamp-$gitHash" }
} catch {}

Write-Host ""
Write-Host "  Startup configuration:" -ForegroundColor DarkGray
Write-Host ("  " + ("─" * 40)) -ForegroundColor DarkGray
Write-Host "  Build stamp   : $buildStamp"
Write-Host "  Root dir      : $PSScriptRoot"
Write-Host "  Backend dir   : $(Join-Path $PSScriptRoot 'backend')"
Write-Host "  Frontend dir  : $(Join-Path $PSScriptRoot 'frontend')"
Write-Host "  Python        : $BackendPython"
Write-Host "  Node          : $NodeExe"
Write-Host "  Mode          : $Mode"
Write-Host "  Backend port  : $resolvedBackendPort"
if ($resolvedFrontendPort -gt 0) {
Write-Host "  Frontend port : $resolvedFrontendPort" }
Write-Host ("  " + ("─" * 40)) -ForegroundColor DarkGray
Write-Host ""

# Step E: Execute mode
switch ($Mode) {

    "backend-only" {
        Write-Banner "Mode: backend-only" "DarkCyan"
        $env:PORT = "$resolvedBackendPort"
        Push-Location (Join-Path $PSScriptRoot "backend")
        try {
            & $BackendPython -m uvicorn main:app --host 0.0.0.0 --port $resolvedBackendPort --reload
        } finally { Pop-Location }
    }

    "frontend-only" {
        Write-Banner "Mode: frontend-only" "DarkCyan"
        if ($NodeExe) { Initialize-NodeModules $NodeExe }
        $env:VITE_API_URL = "http://localhost:$resolvedBackendPort"
        Push-Location (Join-Path $PSScriptRoot "frontend")
        try {
            & $NodeExe (Get-Command npm -ErrorAction Stop).Source run dev -- --port $resolvedFrontendPort
        } finally { Pop-Location }
    }

    "test-only" {
        Write-Banner "Mode: test-only" "DarkMagenta"
        Push-Location (Join-Path $PSScriptRoot "backend")
        try {
            & $BackendPython -m pytest tests/ -v --tb=short
        } finally { Pop-Location }
    }

    default {  # dev  |  prod-lite
        Write-Banner "Mode: $Mode" "Green"

        if ($NodeExe) { Initialize-NodeModules $NodeExe }

        # Launch backend in a new window
        Start-Backend $BackendPython $resolvedBackendPort

        # Wait until backend is up
        Wait-ForBackend $resolvedBackendPort

        # Launch frontend in a new window
        Start-Frontend $NodeExe $resolvedFrontendPort $resolvedBackendPort

        # Open browser
        Start-Sleep -Seconds 2
        Write-Step "Opening browser..."
        Start-Process "http://localhost:$resolvedFrontendPort"

        Write-Host ""
        Write-Host "  ================================================" -ForegroundColor Green
        Write-Host "   MINA is running!" -ForegroundColor Green
        Write-Host "   Frontend  :  http://localhost:$resolvedFrontendPort" -ForegroundColor Cyan
        Write-Host "   Backend   :  http://localhost:$resolvedBackendPort" -ForegroundColor Cyan
        Write-Host "   API docs  :  http://localhost:$resolvedBackendPort/docs" -ForegroundColor Cyan
        Write-Host "  ================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Close the backend/frontend PowerShell windows to stop services." -ForegroundColor DarkGray
        Write-Host ""
        Read-Host "Press Enter to close this window"
    }
}
