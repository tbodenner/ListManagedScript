#Requires -RunAsAdministrator

# public desktop
$PublicDesktopPath = 'C:\Users\Public\Desktop\'
# our shortcut file names
$PrinterShortcutFileNames = @('Printers.lnk','Network Printers.lnk')
# create our shortcut paths
$PrinterShortcutPaths = @()
foreach ($FileName in $PrinterShortcutFileNames) {
    $PrinterShortcutPaths += Join-Path -Path $PublicDesktopPath -ChildPath $FileName
}

# result booleans
$RemovedShortcut = $false
$ShortcutError = $false
$NoShortcut = $false

# our return tuple
$ReturnTuple = $null

# try to remove the shortcuts
foreach ($PrinterShortcutPath in $PrinterShortcutPaths) {
    # check if the shortcut is found
    if ((Test-Path -Path $PrinterShortcutPath) -eq $true) {
        # try to remove the shortcut
        try {
            # remove the shortcut
            Remove-Item -Path $PrinterShortcutPath -Force
            # this shortcut was removed
            $RemovedShortcut = $true
        }
        catch {
            # an error occurred while trying to remove the shortcut
            $ShortcutError = $true
        }
    }
    else {
        # a shortcut was not found
        $NoShortcut = $true
    }
}

# check if we had an error
if ($ShortcutError -eq $true) {
    # create our shortcut error result tuple
    $ReturnTuple = [System.Tuple]::Create($false, "Shortcut Error")
}
else {
    # return our result tuple based on the result
    if ($RemovedShortcut -eq $true) {
        # create our removed shortcut result tuple
        $ReturnTuple = [System.Tuple]::Create($true, "Removed Shortcut")
    }
    elseif ($NoShortcut -eq $true) {
        # create our result tuple for no shortcut found
        $ReturnTuple = [System.Tuple]::Create($true, "No Shortcut")
    }
}

# if our return tuple is still null, create an unknown error result tuple
if ($null -eq $ReturnTuple) {
        # create our unknown error result tuple
        $ReturnTuple = [System.Tuple]::Create($false, "Unknown Error")
}

# return our result tuple
$ReturnTuple