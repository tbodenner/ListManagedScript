param (
    # the domains to get computers from
    [string[]]$Domains = @('v18.med.va.gov', 'va.gov'),
    # the filter to apply when selecting computers
    [string]$Filter = 'Name -like "PRE-WS*" -or Name -like "PRE-LT*" -or Name -like "PRE-MA*"',
    # the file to save the computer list
    [string]$OutFile = '.\ComputerList.txt'
)

# output array
$Computers = @()
# get filtered computers from all domains
foreach ($Domain in $Domains) {
    $Computers += (Get-ADComputer -Filter $Filter -Server (Get-ADDomainController -Discover -DomainName $Domain)).Name
}
# write the array to a file
$Computers | Out-File -FilePath $OutFile -Force
