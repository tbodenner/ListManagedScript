param (
    # array of computer names or partial names to match
    [Parameter(Mandatory=$true)][string[]]$Filter,
    # array of OUs to check
    [Parameter(Mandatory=$true)][string[]]$RootOU,
    # the file to save the computer list
    [string]$OutFile = '.\ComputerList.txt',
    # only include the computers after this date
    [datetime]$AfterDate,
    # switch to append to a file instead of overwriting it
    [switch]$Append
)

# check for our required module
$RequiredModuleName = 'LDAP-ADTools'
if($null -eq (Get-Module -Name $RequiredModuleName -ListAvailable)) {
    # the module was not found, write a message and exit
    Write-Host "Required module '$($RequiredModuleName)' not found" -ForegroundColor Red
    Write-Host "`nModule can be found at https://github.com/tbodenner/PowerShell-Modules" -ForegroundColor Yellow
    Write-Host "Update the PSModulePath: `$env:PSModulePath += `";<path to module>`"" -ForegroundColor Yellow
    Write-Host "`nExiting" -ForegroundColor Red
    exit
}
# import our module only for this script
Import-Module $RequiredModuleName -Scope Local

# get our computer from AD using LDAP
$ADComputers = Get-LDAPComputer -RootOU $RootOU -Computers $Filter -Properties 'name','useraccountcontrol','whencreated'

# our hashtable to get a unique list of computers
$ComputersHashtable = @{}

# add our computer names to our ordered hashtable
foreach ($Key in $ADComputers.Keys) {
    # check if we are using our after date variable
    if ($null -ne $AfterDate) {
        # get the computer's creation time
        $ComputerDate = [datetime]::Parse($ADComputers[$Key]['whencreated'])
        # check if this time is after our specified date
        if ($ComputerDate -lt $AfterDate) {
            # skip this computer
            continue
        }
    }
    # add the computer to our hashtable
    $ComputersHashtable[$ADComputers[$Key]['name']] = $ADComputers[$Key]['useraccountcontrol']
}

# check if we are appending a file
if ($Append -eq $false) {
    # write the array to a file
    $ComputersHashtable.Keys | Sort-Object | Out-File -FilePath $OutFile -Force
}
else {
    # append the array to a file
    $ComputersHashtable.Keys | Sort-Object | Out-File -FilePath $OutFile -Force -Append
}
