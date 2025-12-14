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

# Folder names to exclude anywhere in tree (caches, temp, junk)
$excludeDirNames = @(
    'Cache'
    'Caches'
    'CacheStorage'
    'CachedData'
    'CachedExtensions'
    'CachedExtensionVSIXs'
    'Code Cache'
    'GPUCache'
    'ShaderCache'
    'D3DSCache'
    'Temp'
    'Tmp'
    'Logs'
    'CrashDumps'
    'WebCache'
    'INetCache'
    'IconCache'
    'thumbnails'
    'Crash Reports'
    'ElevatedDiagnostics'
    'PerfLogs'
    '$Recycle.Bin'
    '$RECYCLE.BIN'
    'Recycle'
    'Recycler'
)

# Full paths to exclude
$excludeDirPaths = @(
    "$sourceProfile\AppData\Local\Microsoft\Windows\Explorer"
    "$sourceProfile\AppData\Local\Microsoft\Windows\WER"
    "$sourceProfile\AppData\Local\Microsoft\WindowsApps"
    "$sourceProfile\AppData\Local\Packages"
    "$sourceProfile\AppData\Local\PeerDistRepub"
    "$sourceProfile\AppData\Local\ConnectedDevicesPlatform"
    "$sourceProfile\AppData\LocalLow\Microsoft"
    "$sourceProfile\MicrosoftEdgeBackups"
    "$sourceProfile\IntelGraphicsProfiles"
)

# Files to exclude (registry hives, lock files, temp files)
$excludeFiles = @(
    'NTUSER.DAT'
    'NTUSER.DAT.LOG*'
    'ntuser.dat.LOG*'
    'ntuser.ini'
    'ntuser.pol'
    'UsrClass.dat'
    'UsrClass.dat.LOG*'
    '*.tmp'
    '*.temp'
    '*.lock'
    '*.log'
    'desktop.ini'
    'Thumbs.db'
    'IconCache.db'
    '*.etl'
)

# Build robocopy exclude arguments
$xdArgs = (($excludeDirNames | ForEach-Object { "`"$_`"" }) + ($excludeDirPaths | ForEach-Object { "`"$_`"" })) -join ' '
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
