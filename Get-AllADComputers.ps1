$Filter = 'Name -like "PRE-WS*" -or Name -like "PRE-LT*" -or Name -like "PRE-MA*"'
$Domains = @('v18.med.va.gov', 'va.gov')
$Computers = @()
foreach ($Domain in $Domains) {
    $Computers += (Get-ADComputer -Filter $Filter -Server (Get-ADDomainController -Discover -DomainName $Domain)).Name
}

$Computers | Out-File -FilePath '.\ComputerList.txt' -Force
