Add-Type -AssemblyName System.Windows.Forms

# Get current user profile
$currentProfile = $env:USERPROFILE

# Browse for old profile
$folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
$folderBrowser.Description = "Select old user profile folder to copy to: $currentProfile"
$folderBrowser.RootFolder = "MyComputer"
$folderBrowser.ShowNewFolderButton = $false

if ($folderBrowser.ShowDialog() -ne "OK") {
    Write-Host "Cancelled." -ForegroundColor Yellow
    exit
}

$sourceProfile = $folderBrowser.SelectedPath

Write-Host "`nSource: $sourceProfile" -ForegroundColor Cyan
Write-Host "Destination: $currentProfile`n" -ForegroundColor Cyan

# Grant read access to old profile using icacls
Write-Host "Granting read access to source profile..." -ForegroundColor Yellow
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls $sourceProfile /grant "${currentUser}:(OI)(CI)RX" /T /C /Q 2>$null

# Folders to exclude (temp, caches, app packages - NOT legacy junction names)
$excludeDirs = @(
    'AppData\Local\Temp'
    'AppData\Local\Microsoft\Windows\INetCache'
    'AppData\Local\Microsoft\Windows\WebCache'
    'AppData\Local\Microsoft\Windows\Explorer'
    'AppData\Local\Microsoft\Windows\Caches'
    'AppData\Local\Microsoft\Windows\WER'
    'AppData\Local\Microsoft\WindowsApps'
    'AppData\Local\Packages'
    'AppData\Local\CrashDumps'
    'AppData\Local\D3DSCache'
    'AppData\Local\PeerDistRepub'
    'AppData\Local\ConnectedDevicesPlatform'
    'AppData\LocalLow\Microsoft'
    'MicrosoftEdgeBackups'
    'IntelGraphicsProfiles'
)

# Files to exclude (registry hives, lock files)
$excludeFiles = @(
    'NTUSER.DAT'
    'NTUSER.DAT.LOG*'
    'ntuser.dat.LOG*'
    'ntuser.ini'
    'ntuser.pol'
    'UsrClass.dat'
    'UsrClass.dat.LOG*'
    '*.tmp'
    '*.lock'
    'desktop.ini'
    'Thumbs.db'
    'IconCache.db'
)

# Build robocopy exclude arguments
$xdArgs = ($excludeDirs | ForEach-Object { "`"$sourceProfile\$_`"" }) -join ' '
$xfArgs = ($excludeFiles | ForEach-Object { "`"$_`"" }) -join ' '

# Run robocopy
$robocopyCmd = "robocopy `"$sourceProfile`" `"$currentProfile`" /E /XJ /XA:SH /R:1 /W:1 /NFL /NDL /NP /XD $xdArgs /XF $xfArgs"

Write-Host "Starting robocopy..." -ForegroundColor Green
Write-Host $robocopyCmd -ForegroundColor DarkGray
Write-Host ""

cmd /c $robocopyCmd

$exitCode = $LASTEXITCODE
Write-Host ""
if ($exitCode -lt 8) {
    Write-Host "Profile copy completed successfully. Exit code: $exitCode" -ForegroundColor Green
} else {
    Write-Host "Profile copy completed with errors. Exit code: $exitCode" -ForegroundColor Red
}

[System.Windows.Forms.MessageBox]::Show("Profile migration complete.`n`nSource: $sourceProfile`nDestination: $currentProfile`n`nRobocopy exit code: $exitCode", "Complete", "OK", "Information")