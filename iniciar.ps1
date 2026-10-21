# Execute pelo PowerShell a partir desta pasta: .\iniciar.ps1
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
try {
    $versao = & node --version
    if ($LASTEXITCODE -ne 0) { throw 'Node.js não encontrado. Instale Node.js 22.13 ou superior.' }
    Write-Host "Node.js $versao" -ForegroundColor Cyan
    if (-not (Test-Path '.\data\qualigest.sqlite')) {
        $senhaSegura = Read-Host 'Crie a senha inicial do administrador (mínimo 12 caracteres)' -AsSecureString
        $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($senhaSegura)
        try { $env:ADMIN_INITIAL_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
        if ($env:ADMIN_INITIAL_PASSWORD.Length -lt 12 -or $env:ADMIN_INITIAL_PASSWORD -cnotmatch '[A-Z]' -or $env:ADMIN_INITIAL_PASSWORD -cnotmatch '[a-z]' -or $env:ADMIN_INITIAL_PASSWORD -notmatch '[0-9]' -or $env:ADMIN_INITIAL_PASSWORD -notmatch '[^a-zA-Z0-9]') { throw 'Senha: mínimo 12 caracteres com maiúscula, minúscula, número e símbolo.' }
    }
    Write-Host 'Abrir http://localhost:3000 no navegador após a inicialização.' -ForegroundColor Green
    & node server.js
}
finally {
    Remove-Item Env:ADMIN_INITIAL_PASSWORD -ErrorAction SilentlyContinue
}
