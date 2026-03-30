#Requires -RunAsAdministrator

# parameters
param ([Parameter(Mandatory=$true)][PSCredential]$Creds)

# public desktop
$PublicDesktopPath = 'C:\Users\Public\Desktop\'
# our shortcut's path
$PrinterShortcutFileName = 'Printers.lnk'
# create our icon path
$PrinterShortcutPath = Join-Path -Path $PublicDesktopPath -ChildPath $PrinterShortcutFileName
# old server name
$OldServerName = 'VHAPREPRT22'
# our update bool
$DoUpdate = $false

# check if the shortcut doesn't exist
if ((Test-Path -Path $PrinterShortcutPath) -eq $false) {
    # update the shortcut
    $DoUpdate = $true
}
else {
    # search the shortcut's raw data for our old server name
    if (((Get-Content -Path $PrinterShortcutPath -Tail 1) -match $OldServerName).Count -gt 0) {
        # update the shortcut
        $DoUpdate = $true
    }
}

# check if we are updating the shortcut
if ($DoUpdate -eq $true) {
    # our mapped drive letter
    $MapDriveLetter = 'V'
    # our shared folder
    $MapDriveFolder = '\\VHAPREPRT22.VA.GOV\3.PostImageSetup'
    # our path to our shortcut in the shared folder
    $IconPartialPath = '\ScriptFiles\Files\Icons\Printers.lnk'
    # try to copy the shortcut
    try {
        # map our drive
        New-PSDrive -Name $MapDriveLetter -Root $MapDriveFolder -Persist -PSProvider "FileSystem" -Credential $Creds | Out-Null
        # pause for a second
        Start-Sleep -Seconds 1
        # copy our shortcut
        Copy-Item -Path "$($MapDriveLetter):$($IconPartialPath)" -Destination $PublicDesktopPath | Out-Null
        # pause for a second
        Start-Sleep -Seconds 1
        # remove our mapped drive
        Remove-PSDrive -Name $MapDriveLetter -Force | Out-Null
        # create our result tuple
        $ReturnTuple = [System.Tuple]::Create($true, "Updated")
    }
    catch {
        # create our result tuple
        $ReturnTuple = [System.Tuple]::Create($false, "Error")
    }
}
else {
    # create our result tuple
    $ReturnTuple = [System.Tuple]::Create($true, "No Change")
}

# return our result tuple
$ReturnTuple