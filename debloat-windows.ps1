# Check if running as Administrator, if not, relaunch with elevated privileges
if (-not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    $scriptPath = "`"$PSCommandPath`""
    Start-Process -FilePath "powershell" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File $scriptPath" -Verb RunAs
    exit
}


Write-Host "Starting Windows Debloat and Privacy Hardening..." -ForegroundColor Green

# --- 1️ Remove ALL Bloatware ---
$packages = @(
    # Microsoft Bloat
    "Microsoft.3DBuilder",
    "Microsoft.BingNews",
    "Microsoft.BingSearch",
    "Microsoft.BingWeather",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.GamingApp",
    "Microsoft.Microsoft3DViewer",
    "Microsoft.MicrosoftEdge.Stable",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.MicrosoftStickyNotes",
    "Microsoft.MixedReality.Portal",
    "Microsoft.NotePad",
    "Microsoft.Office.OneNote",
    "Microsoft.OneDrive",
	"Microsoft.MSPaint",
    "Microsoft.OutlookForWindows",
    "Microsoft.Paint",
    "Microsoft.People",
    "Microsoft.PowerAutomateDesktop",
    "Microsoft.SkypeApp",
    "Microsoft.Todos",
    "Microsoft.Wallet",
    "Microsoft.Whiteboard",
    "Microsoft.WindowsAlarms",
    "Microsoft.WindowsCamera",
    "Microsoft.Windows.DevHome",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.WindowsMaps",
    "Microsoft.WindowsSoundRecorder",
    "Microsoft.YourPhone",
    
    # System Apps that May Need Force Removal
    "Microsoft.AAD.BrokerPlugin",
	"Microsoft.Advertising.Xaml",
	"Microsoft.Cortana",
    "Microsoft.Services.Store.Engagement",
	"Microsoft.Windows.Cortana",
    "Microsoft.Win32WebViewHost",
	"Microsoft.WindowsCommunicationsApps",
    "Microsoft.Windows.ContentDeliveryManager",
    "Microsoft.Windows.NarratorQuickStart",
    "Microsoft.Windows.ParentalControls",
    "Microsoft.Windows.PeopleExperienceHost",
    "Microsoft.Windows.PinningConfirmationDialog",
    "Microsoft.Windows.SecureAssessmentBrowser",
    "Microsoft.Windows.XGpuEjectDialog",
    
    # OOBE (Out of Box Experience)
    "Microsoft.Windows.OOBENetworkCaptivePortal",
    "Microsoft.Windows.OOBENetworkConnectionFlow"
)


# Remove standard AppxPackages
foreach ($package in $packages) {
    Get-AppxPackage -AllUsers | Where-Object { $_.Name -like $package } | Remove-AppxPackage -AllUsers -Confirm:$false
}

# Force remove system apps using DISM
foreach ($package in $packages) {
    $packageName = (Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $package }).PackageName
    if ($packageName) {
        Write-Host "Force removing $packageName ..."
        dism.exe /Online /Remove-ProvisionedAppxPackage /PackageName:$packageName
    }
}

# --- 2️ Remove & Block Microsoft Edge ---
Write-Host "Stopping all Microsoft Edge processes..." -ForegroundColor Cyan

# Kill all Edge-related processes
$EdgeProcesses = @("msedge", "edgeupdate", "edgewebview2", "edgecore")

foreach ($process in $EdgeProcesses) {
    $proc = Get-Process -Name $process -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Host "Stopping process: $process" -ForegroundColor Yellow
        Stop-Process -Name $process -Force -ErrorAction SilentlyContinue
    }
}

Start-Sleep -Seconds 2

# Ensure all Edge-related processes are fully stopped before proceeding
foreach ($process in $EdgeProcesses) {
    $proc = Get-Process -Name $process -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Host "Warning: $process is still running. Retrying termination..." -ForegroundColor Red
        Stop-Process -Name $process -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "Deleting Microsoft Edge folders..." -ForegroundColor Cyan

# List of Edge-related folders to delete
$EdgeFolders = @(
    "C:\Program Files (x86)\Microsoft\Edge",
    "C:\Program Files (x86)\Microsoft\EdgeUpdate",
    "C:\Program Files (x86)\Microsoft\EdgeWebView",
    "C:\Program Files (x86)\Microsoft\EdgeCore",
    "C:\Program Files\Microsoft\Edge",
    "C:\Program Files\Microsoft\EdgeUpdate",
    "$env:LOCALAPPDATA\Microsoft\Edge",
    "$env:PROGRAMDATA\Microsoft\Edge"
)

# Loop through each folder and attempt to delete it
foreach ($folder in $EdgeFolders) {
    if (Test-Path $folder) {
        Write-Host "Taking ownership of: $folder" -ForegroundColor Yellow
        takeown /f $folder /r /d Y | Out-Null
        icacls $folder /grant Administrators:F /t /c /l /q | Out-Null

        Write-Host "Deleting: $folder" -ForegroundColor Yellow
        Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "Not found: $folder" -ForegroundColor Green
    }
}

# Block Edge from reinstalling
Write-Host "Blocking Edge Reinstallation..." -ForegroundColor Cyan

# Block Edge updates via Registry
New-Item "HKLM:\SOFTWARE\Microsoft\EdgeUpdate" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\EdgeUpdate" -Name "DoNotUpdateToEdgeWithChromium" -Value 1 -PropertyType DWord -Force | Out-Null

# Disable Edge Update Services
Write-Host "Disabling Edge Update Services..." -ForegroundColor Cyan
$EdgeServices = @("edgeupdate", "edgeupdatem")
foreach ($service in $EdgeServices) {
    Get-Service -Name $service -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
}

# Disable Edge Update Scheduled Tasks
Write-Host "Disabling Edge Update Scheduled Tasks..." -ForegroundColor Cyan
$EdgeTasks = @("\Microsoft\EdgeUpdate\EdgeUpdateTaskMachineCore", "\Microsoft\EdgeUpdate\EdgeUpdateTaskMachineUA")
foreach ($task in $EdgeTasks) {
    schtasks /Change /TN $task /Disable 2>$null
}

# Prevent Edge from being reinstalled via Windows Update
Write-Host "Blocking Edge in Windows Update..." -ForegroundColor Cyan
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "InstallDefault" -Value 0 -PropertyType DWord -Force | Out-Null

Write-Host "Microsoft Edge should now be removed and blocked!" -ForegroundColor Green


# --- 3️ Disable Telemetry & Tracking Services ---
Write-Host "Disabling Windows Telemetry & Tracking..." -ForegroundColor Yellow
$services = @(
    "DiagTrack", "dmwappushservice", "Wecsvc", "RemoteRegistry"
)
foreach ($service in $services) {
    Stop-Service $service -Force -ErrorAction SilentlyContinue
    Set-Service $service -StartupType Disabled
}

# Disable Windows Data Collection
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f

# --- 4️ Disable Cortana & Background Apps ---
Write-Host "Disabling Cortana and Background Apps..." -ForegroundColor Yellow
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f

# Disable background apps
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f

# --- 5️ Disable Ads, Tips, and Unwanted Notifications & Suggestions ---
Write-Host "Disabling Windows Ads, Tips, and Suggestions..." -ForegroundColor Yellow
# Disabling General Ads & Suggestions
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /t REG_DWORD /d 0 /f
# Blocks manufacturer-specific apps from reinstalling
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f
# Disabling Pre-Installed Windows Apps
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f
# Stopping Silent App Installations
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
# Start menu suggestions
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /t REG_DWORD /d 0 /f
# Disable lock screen ads
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f

# --- 6️ Restart Explorer & End Script ---
Write-Host "Debloat & Privacy Hardening Complete! Restarting Explorer..." -ForegroundColor Green
Stop-Process -Name explorer -Force
Start-Process explorer
Write-Host "Done! Please restart your computer for all changes to take effect." -ForegroundColor Green

# Keep PowerShell open to review any errors/messages
Write-Host "Script execution completed. Review the output and close this window manually when ready." -ForegroundColor Cyan
while ($true) { Start-Sleep -Seconds 1 }

