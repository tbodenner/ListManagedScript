#Requires -RunAsAdministrator

# public desktop
$PublicDesktopPath = 'C:\Users\Public\Desktop\'
# our shortcut file
$PrinterShortcutFileName = 'Printers.lnk'
# create our shortcut path
$PrinterShortcutPath = Join-Path -Path $PublicDesktopPath -ChildPath $PrinterShortcutFileName

# check if the shortcut is found
if ((Test-Path -Path $PrinterShortcutPath) -eq $true) {
    # try to remove the shortcut
    try {
        # remove the shortcut
        Remove-Item -Path $PrinterShortcutPath -Force
        # create our result tuple
        $ReturnTuple = [System.Tuple]::Create($true, "Removed Shortcut")
    }
    catch {
        # create our result tuple
        $ReturnTuple = [System.Tuple]::Create($false, "Shortcut Error")
    }
}
else {
    # create our result tuple
    $ReturnTuple = [System.Tuple]::Create($true, "No Shortcut")
}

# return our result tuple
$ReturnTuple