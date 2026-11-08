# VaultShare Verification Runner
# Runs pytest, audit log chain verification, and dependency vulnerability audit.
# Assumes the virtual environment is already active.

$ErrorActionPreference = "Continue"
$failed = $false

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "VaultShare Automated Verification Suite" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# 1. Run pytest suite
Write-Host "`n[1/3] Running pytest suite..." -ForegroundColor Cyan
python -m pytest -q
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Pytest test suite failed." -ForegroundColor Red
    $failed = $true
} else {
    Write-Host "[+] Pytest test suite passed." -ForegroundColor Green
}

# 2. Run Flask audit log chain verification
Write-Host "`n[2/3] Verifying audit log hash chain..." -ForegroundColor Cyan
try {
    flask verify-audit
} catch {
    python -m flask verify-audit
}
if ($LASTEXITCODE -ne 0) {
    python -m flask verify-audit
}
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Audit log verification failed." -ForegroundColor Red
    $failed = $true
} else {
    Write-Host "[+] Audit log verification passed." -ForegroundColor Green
}

# 3. Run pip-audit if installed
Write-Host "`n[3/3] Checking dependency security..." -ForegroundColor Cyan
$pipAuditCmd = Get-Command pip-audit -ErrorAction SilentlyContinue
$hasPipAuditModule = python -c "import pip_audit" 2>$null
if ($pipAuditCmd -or ($LASTEXITCODE -eq 0)) {
    Write-Host "Running pip-audit..." -ForegroundColor Cyan
    try {
        pip-audit
    } catch {
        python -m pip_audit
    }
    if ($LASTEXITCODE -ne 0) {
        python -m pip_audit
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[-] pip-audit detected security vulnerabilities." -ForegroundColor Red
        $failed = $true
    } else {
        Write-Host "[+] Dependency vulnerability check passed." -ForegroundColor Green
    }
} else {
    Write-Host "pip-audit is not installed. To run vulnerability audits, install it with:" -ForegroundColor Yellow
    Write-Host "    pip install pip-audit" -ForegroundColor Yellow
}

# Final PASS / FAIL verdict
Write-Host ""
if ($failed) {
    Write-Host "==================================================" -ForegroundColor Red
    Write-Host "CHECKS STATUS: FAIL" -ForegroundColor Red
    Write-Host "==================================================" -ForegroundColor Red
    exit 1
} else {
    Write-Host "==================================================" -ForegroundColor Green
    Write-Host "CHECKS STATUS: PASS" -ForegroundColor Green
    Write-Host "==================================================" -ForegroundColor Green
    exit 0
}
