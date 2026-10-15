$ErrorActionPreference = 'Stop'
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectDir

Write-Host 'Vault Change Portal launcher - UPDATED BUILD' -ForegroundColor Cyan
Write-Host "Project folder: $ProjectDir" -ForegroundColor DarkGray
Write-Host 'The application mode is controlled by DRY_RUN in app.py.' -ForegroundColor Yellow

$Python = $null
if (Test-Path (Join-Path $ProjectDir '.venv\Scripts\python.exe')) {
    $Python = Join-Path $ProjectDir '.venv\Scripts\python.exe'
} else {
    $PyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($PyLauncher) {
        & py -3.11 -m venv (Join-Path $ProjectDir '.venv')
        if ($LASTEXITCODE -ne 0) { throw 'Could not create the Python 3.11 virtual environment. Install Python 3.11 and try again.' }
        $Python = Join-Path $ProjectDir '.venv\Scripts\python.exe'
    } else {
        $PythonCommand = Get-Command python -ErrorAction SilentlyContinue
        if (-not $PythonCommand) { throw 'Python 3.11+ was not found. Install Python and enable Add Python to PATH.' }
        & python -m venv (Join-Path $ProjectDir '.venv')
        if ($LASTEXITCODE -ne 0) { throw 'Could not create the Python virtual environment.' }
        $Python = Join-Path $ProjectDir '.venv\Scripts\python.exe'
    }
}

& $Python -m pip install --disable-pip-version-check -r (Join-Path $ProjectDir 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed. Check your internet/proxy and try again.' }

Start-Sleep -Seconds 2
Start-Process 'http://127.0.0.1:5001'
Write-Host 'Portal URL: http://127.0.0.1:5001' -ForegroundColor Green
Write-Host 'This updated build uses port 5001 so an older app on port 5000 will not mask it.' -ForegroundColor Yellow
& $Python (Join-Path $ProjectDir 'app.py')
if ($LASTEXITCODE -ne 0) { Write-Host 'The portal exited with an error.' -ForegroundColor Red }
Read-Host 'Press Enter to close this window'
