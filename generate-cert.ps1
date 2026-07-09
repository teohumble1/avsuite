# Generate self-signed code-signing certificate for AvSuite driver
# WARNING: For testing/portfolio purposes only. Use EV certificate for production.

param(
    [Parameter(Mandatory=$false)]
    [string]$CertName = "AvSuite Driver",

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "avsuite_cert.pfx"
)

Write-Host "Generating self-signed code-signing certificate..."
Write-Host "⚠️  WARNING: This is for testing/portfolio only"
Write-Host ""

# Create self-signed certificate
$cert = New-SelfSignedCertificate `
    -CertStoreLocation Cert:\CurrentUser\My `
    -Subject "CN=$CertName" `
    -Type CodeSigningCert `
    -KeyUsage DigitalSignature `
    -KeySpec Signature `
    -KeyLength 2048 `
    -NotAfter (Get-Date).AddYears(10) `
    -FriendlyName $CertName

Write-Host "✓ Certificate created"
Write-Host "  Subject: $($cert.Subject)"
Write-Host "  Thumbprint: $($cert.Thumbprint)"
Write-Host "  Valid: $($(Get-Date).ToString('yyyy-MM-dd')) to $($cert.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host ""

# Generate secure password for PFX
Write-Host "Generating PFX file..."
$password = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
$bytes = [byte[]]::new(32)
$password.GetBytes($bytes)
$securePassword = [System.Convert]::ToBase64String($bytes) | ConvertTo-SecureString -AsPlainText -Force

# Export to PFX
Export-PfxCertificate -Cert $cert -FilePath $OutputPath -Password $securePassword -Force | Out-Null

Write-Host "✓ Certificate exported to: $OutputPath"
Write-Host ""
Write-Host "⚠️  IMPORTANT:"
Write-Host "  - This certificate is self-signed (not from a trusted CA)"
Write-Host "  - Use ONLY for isolated testing VMs"
Write-Host "  - Production deployments require EV certificate from trusted CA"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Run: powershell -File install-cert.ps1 (as Administrator, VM only)"
Write-Host "  2. Run: signtool sign /f $OutputPath /fd sha256 driver.sys"
Write-Host ""
