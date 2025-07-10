param (
    # the domains to get computers from
    [string[]]$Domains = @('v18.med.va.gov', 'va.gov'),
    # the filter to apply when selecting computers
    [string]$Filter = 'SamAccountName -like "VHAPRE*" -or SamAccountName -like "OITPRE*"',
    # the file to save the computer list
    [string]$OutFile = '.\UserList.csv'
)

# our ordered hashtable to get a unique list of users
$UserHashtable = [ordered]@{}
# get filtered users from all domains
foreach ($Domain in $Domains) {
    # get the users from the current domain server
    $Users = Get-ADUser -Filter $Filter -Server (Get-ADDomainController -Discover -DomainName $Domain) -Properties *
    # if we didn't get any users, then continue
    if ($null -eq $Users) { continue }
    # loop through our users array
    foreach ($User in $Users) {
        # check if our user is null or empty, and skip it
        if (($null -eq $User) -or ($User -eq '')) { continue }
        # and add the computer to our hashtable
        $UserHashtable[$User.SamAccountName] = "$($User.SamAccountName),$($User.GivenName),$($User.Surname),$($User.UserPrincipalName),$($User.LastLogonDate),$($User.Description)"
    }
}
# write our header
"AccountName,First,Last,EMail,LogOn,Description" | Out-File -FilePath $OutFile -Force
# write the array to a file
$UserHashtable.Values | Out-File -FilePath $OutFile -Force -Append
