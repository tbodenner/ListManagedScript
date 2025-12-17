#Requires -RunAsAdministrator

# parameters
param ([Parameter(Mandatory=$true)][PSCredential]$Creds)

# lynx version
$LynxInstallerVersion = '10.4.25.0'

# install lynx
function Install-Lynx {
    # lynx service name
    $LynxServiceName = 'LynxClientService'
    # lynx service name
    $LynxUiProcessName = 'LynxClientUICore'
    # get the lynx service
    $LynxService = Get-Service $LynxServiceName -ErrorAction Ignore -WarningAction Ignore
    # save the lynx service startup type
    $LynxStartType = $null
    # check if lynx service exists
    if ($null -ne $LynxService) {
        # set our startup type
        $LynxStartType = $LynxService.StartType
    }
    # system folder
    $SystemFolder = 'C:\Windows\System32'
    # executable location
    $MsiexecExe = "$($SystemFolder)\msiexec.exe"
    # lynx folder
    $LynxFolder = '\\VHAPREFPC4.v18.med.va.gov\1.Desktop Icon\ScriptInstalls\Installers\Lynx'
    # Install file
    $LynxInstaller = "LynxClient_v$($LynxInstallerVersion).msi"
    # temp folder
    $TempFolder = 'C:\Temp'
    # check if the temp directory exists
    if ((Test-Path -Path $TempFolder) -eq $false) {
        # if not found, create it
        New-Item -Path $TempFolder -ItemType Directory
    }
    # map drive
    $MapDriveLetter = 'V'
    New-PSDrive -Name $MapDriveLetter -Root $LynxFolder -Persist -PSProvider 'FileSystem' -Credential $Creds
    # copy installer to temp
    Copy-Item -Path "$($MapDriveLetter):\$($LynxInstaller)" -Destination $TempFolder -Force -Recurse
    # remove mapped drive
    Remove-PSDrive $MapDriveLetter
    # sleep for 10 seconds to avoid file in use errors
    Start-Sleep -Seconds 10
    # change to our temp folder
    Set-Location $TempFolder
    # lynx install parameters
    $Msi = "$($TempFolder)\$($LynxInstaller)"
    $MArg = '/quiet /norestart HOSTNAME=vhapreapplynx PROFILE=PanicButton'
    # create our msiexec arguments
    $CommandString = "$($MsiexecExe) /i `"$($Msi)`" $($MArg)"
    # install lynx
    cmd.exe /c $CommandString
    # wait 10 seconds after the install finishes
    Start-Sleep -Seconds 10

    # check if we should disable lynx
    if ($LynxStartType -eq 'Disabled') {
        Set-Service -Name $LynxServiceName -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service $LynxServiceName -ErrorAction SilentlyContinue
        Stop-Process -Name $LynxUiProcessName -Force -ErrorAction SilentlyContinue
    }
}

# check if lynx is installed
function Get-LynxInstall {
    # software name and version we are looking for
    $SoftwareName = 'LynxClient'
    $SoftwareVersion = $LynxInstallerVersion
    # commands to look for the software
    $SoftwareCheck = {
        $Path32 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $Path64 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $InstalledSoftware = Get-ItemProperty -Path $Path32, $Path64
        $InstalledSoftware | Where-Object { $_.DisplayName -like "$($SoftwareName)*" -and $_.DisplayVersion -like "$($SoftwareVersion)*" } | ForEach-Object { $_.DisplayName; $_.DisplayVersion }
    }
    # run the command
    $Installed = & $SoftwareCheck
    # check if our return is null
    if ($null -eq $Installed)
    {
        # if null, software was not found
        return [System.Tuple]::Create($false, "Not Installed")
    }
    else {
        # otherwise, get the version and name from the check
        $InstalledName = $Installed[0]
        $InstalledVersion = $Installed[1]
        # check if the version and name match
        if (($InstalledName -eq $SoftwareName) -and ($InstalledVersion -eq $SoftwareVersion)) {
            # correct version of software is installed
            return [System.Tuple]::Create($true, "Lynx Found")
        }
        else {
            # wrong version of software is installed
            return [System.Tuple]::Create($false, "Version Mismatch")
        }
    }
    # return our tuple
    return $ReturnTuple
}

# the temp folder
$TempFolder = 'C:\Temp'

# check if the temp folder exists
if ((Test-Path -Path $TempFolder) -eq $false) {
    # folder doesn't exist, so create the folder
    New-Item -Path $TempFolder -ItemType Directory -ErrorAction Ignore -WarningAction Ignore
}

# transcript file
$TranscriptFile = Join-Path -Path $TempFolder -ChildPath 'Install-Lynx-Transcript.txt'

# start the transcript
Start-Transcript -Path $TranscriptFile -ErrorAction Ignore -WarningAction Ignore

# check for our lynx install
$ResultTuple = Get-LynxInstall
# check our result
if ($ResultTuple.Item1 -eq $true) {
    # lynx is installed
    return $ResultTuple
}
else {
    # clear the errors
    $Error.Clear()
    # lynx is not installed, so install lynx
    $InstallResultTuple = Install-Lynx
    # check if we had any errors
    if ($Error.Count -gt 0) {
        # write the error
        Write-Host $Error[0]
        # if there was an error, write a message
        Write-Host "Error on computer: $($env:COMPUTERNAME)" -ForegroundColor Red
        # return our error from the install
        return $InstallResultTuple
    }
    # check for our lynx install, again
    $ResultTuple = Get-LynxInstall
    # check our install again
    if ($ResultTuple.Item1 -eq $true) {
        # lynx was installed, so create a new tuple
        return [System.Tuple]::Create($true, "Lynx Installed")
    }
    else {
        # write the computer name so the computer can be checked and/or diagnosed
        Write-Host "$($env:COMPUTERNAME): Install FAILED" -ForegroundColor Magenta
        # otherwise, the install failed, co create a new tuple
        return [System.Tuple]::Create($false, "Install FAILED")
    }
    # return our new tuple
    return $ReturnTuple
}
