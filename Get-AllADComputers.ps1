param (
    # the domains to get computers from
    [string[]]$Domains = @('v18.med.va.gov', 'va.gov'),
    # the filter to apply when selecting computers
    [string]$Filter = 'Name -like "PRE-WS*" -or Name -like "PRE-LT*" -or Name -like "PRE-MA*"',
    # the file to save the computer list
    [string]$OutFile = '.\ComputerList.txt'
)

# our ordered hashtable to get a unique list of computers
$ComputersHashtable = [ordered]@{}
# get filtered computers from all domains
foreach ($Domain in $Domains) {
    # get the computers from the current domain server
    $Computers = (Get-ADComputer -Filter $Filter -Server (Get-ADDomainController -Discover -DomainName $Domain)).Name
    # if we didn't get any computers, then continue
    if ($null -eq $Computers) { continue }
    # loop through our computers array
    foreach ($Computer in $Computers) {
        # check if our computer is null or empty, and skip it
        if (($null -eq $Computer) -or ($Computer -eq '')) { continue }
        # and add the computer to our hashtable
        $ComputersHashtable[$Computer] = ''
    }
}
# write the array to a file
$ComputersHashtable.Keys | Out-File -FilePath $OutFile -Force
