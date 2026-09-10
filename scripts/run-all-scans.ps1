# =====================================================================
#  run-all-scans.ps1 - Execution locale des 4 controles de securite
#  Windows 11 + Docker Desktop
#  Usage :  powershell -ExecutionPolicy Bypass -File .\scripts\run-all-scans.ps1
# =====================================================================

$ErrorActionPreference = "Continue"
$ROOT = (Get-Location).Path
$REPORTS = "$ROOT\reports"
New-Item -ItemType Directory -Force -Path $REPORTS | Out-Null

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " PIPELINE DE SECURITE - OWASP JUICE SHOP"          -ForegroundColor Cyan
Write-Host " Demarrage : $(Get-Date)"                          -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# ---------------- 1. SCA : npm audit ----------------
Write-Host "`n[1/4] SCA - Analyse des dependances (npm audit)..." -ForegroundColor Yellow
npm install --legacy-peer-deps --ignore-scripts
npm audit --json | Out-File -Encoding utf8 "$REPORTS\sca-npm-audit.json"
npm audit        | Out-File -Encoding utf8 "$REPORTS\sca-npm-audit.txt"
Write-Host "  -> reports\sca-npm-audit.txt" -ForegroundColor Green

# ---------------- 2. Secret Detection : Gitleaks ----------------
Write-Host "`n[2/4] SECRETS - Detection de secrets (Gitleaks)..." -ForegroundColor Yellow
docker run --rm -v "${ROOT}:/repo" -w /repo zricethezav/gitleaks:latest detect `
    --source . --config .gitleaks.toml `
    --report-format json --report-path reports/secrets-gitleaks.json `
    --redact --no-git --exit-code 0 --verbose `
    2>&1 | Tee-Object -FilePath "$REPORTS\secrets-gitleaks.txt"
Write-Host "  -> reports\secrets-gitleaks.json" -ForegroundColor Green

# ---------------- 3. SAST : Semgrep ----------------
Write-Host "`n[3/4] SAST - Analyse statique du code (Semgrep)..." -ForegroundColor Yellow
docker run --rm -v "${ROOT}:/src" -w /src semgrep/semgrep:latest semgrep scan `
    --config security-config/semgrep-rules.yml `
    --config p/owasp-top-ten `
    --json --output reports/sast-semgrep.json `
    --metrics=off --no-git-ignore `
    routes lib models `
    2>&1 | Tee-Object -FilePath "$REPORTS\sast-semgrep.txt"
Write-Host "  -> reports\sast-semgrep.json" -ForegroundColor Green

# ---------------- 4. DAST : OWASP ZAP Baseline ----------------
Write-Host "`n[4/4] DAST - Scan dynamique (OWASP ZAP)..." -ForegroundColor Yellow
docker network create secnet 2>$null | Out-Null
docker rm -f juice-shop-dast 2>$null | Out-Null
docker run -d --name juice-shop-dast --network secnet -p 3000:3000 bkimminich/juice-shop | Out-Null
Write-Host "  Attente du demarrage de l'application (45 s)..."
Start-Sleep -Seconds 45

docker run --rm --network secnet -v "${ROOT}\reports:/zap/wrk:rw" `
    -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py `
    -t http://juice-shop-dast:3000 `
    -J dast-zap.json -r dast-zap.html -I -m 3 `
    2>&1 | Tee-Object -FilePath "$REPORTS\dast-zap.txt"
Write-Host "  -> reports\dast-zap.html" -ForegroundColor Green

# ---------------- Consolidation ----------------
Write-Host "`n=== CONSOLIDATION DES RESULTATS ===" -ForegroundColor Cyan
$summary = @"
===================================================
 RAPPORT DE SECURITE CONSOLIDE
 Projet : OWASP Juice Shop
 Date   : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
===================================================

[SCA]     Voir reports\sca-npm-audit.txt
[SECRETS] Voir reports\secrets-gitleaks.json
[SAST]    Voir reports\sast-semgrep.json
[DAST]    Voir reports\dast-zap.html

Decision de deploiement : voir le rapport final.
"@
$summary | Out-File -Encoding utf8 "$REPORTS\SUMMARY.txt"
Get-Content "$REPORTS\SUMMARY.txt"

Write-Host "`nTermine. Tous les rapports sont dans .\reports\" -ForegroundColor Green
