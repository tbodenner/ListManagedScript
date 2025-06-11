# parameters
param (
    # script that will be run on each computer
    [Parameter(Mandatory)][string]$ScriptFile,
    # arguments to pass to script
    [psobject[]]$ScriptArguments = $null,
    # file for our list of computers
    [string]$ListFile = '.\ComputerList.txt',
    # filter applied to Get-ADComputer
    [string]$ADFilter = 'Name -like "PRE-*"',
    # credentials to pass to script
    [pscredential]$Credentials = $null,
    # script file does not require administrator
    [switch]$NoAdmin,
    # if set, the input list will not be updated
    [switch]$DoNotUpdateList
)

function Get-IsAdmin {
    # get current user's identity
    $CurrentIdentity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    # admin role
    $AdminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
    # return the result
    return ($CurrentIdentity).IsInRole($AdminRole)
}

function Get-HostFromDns {
    param ([Parameter(Mandatory)][string]$Ip)
    # get our dns data from our ip
    $DnsResult = (Resolve-DnsName -Name $Ip -ErrorAction SilentlyContinue)
    # if out result is null, return null
    if ($null -eq $DnsResult) { return $null }
    # if our result has no host, return null
    if ($null -eq $DnsResult.NameHost) { return $null }
    # get the computer name for this ip and return it
    return $DnsResult.NameHost.Split('.')[0]
}

# if the computer list file is missing, create it
if ((Test-Path -Path $ListFile) -eq $false) {
    New-Item -ItemType File $ListFile | Out-Null
}

# skip admin check if admin is not required for the script
if ($NoAdmin -eq $false) {
    # check if the current user is an admin
    if ((Get-IsAdmin) -eq $false) {
        # if switch is not set and user is not an admin, write the error and exit
        Write-Host "Scripts must be run by an administrator unless -NoAdmin switch is set." -ForegroundColor Red
        exit
    }
}

# get list of computers
$Computers = Get-Content -Path $ListFile

# get our domain servers
$DomainServers = @(
    (Get-ADDomainController -Discover),
    (Get-ADDomainController -Discover -DomainName 'va.gov')
)
# create an empty array for our ad computers
$ADComputers = @()
# get our ad computers from all our domains
foreach ($Server in $DomainServers) {
    $ADComputers += (Get-ADComputer -Filter $ADFilter -Server $Server | Where-Object { $_.Enabled -eq $true }).Name
}

# cerate a list for our output computers
$OutputComputers = [System.Collections.Generic.List[string]]::new()

# check if our array has any items in it
if ($Computers.Length -le 0) {
    # fill our computer array
    $Computers = $ADComputers.Clone()
    # write our list to our file
    $ADComputers | Out-File -FilePath $ListFile -Force
}

# add all our items to our output list
foreach ($Item in $Computers) {
    $OutputComputers.Add($Item)
}

# foreach computer
foreach ($Computer in $Computers) {
    # skip any null or empty computers
    if (($null -eq $Computer) -or ($Computer -eq '')) { continue }
    # the current computer we are working on
    Write-Host "$($Computer): " -NoNewline
    # check if the computer is not in AD
    if ($Computer -notin $ADComputers) {
        # remove the good result from our output array
        [void]$OutputComputers.Remove($Computer)
        # computer was not found in the ad computer array
        Write-Host 'Not in AD or Disabled' -ForegroundColor Red
        # move to the next computer
        continue
    }
    # ping the computer
    if ((Test-Connection -TargetName $Computer -Ping -Count 1 -TimeoutSeconds 1 -Quiet) -eq $True) {
        # try to get dns data
        try {
            # get our computer's name from it's dns ip address
            $IpAddress = (Resolve-DnsName -Name $Computer -ErrorAction SilentlyContinue).IPAddress
            # check if our ip address is null
            if ($null -eq $IpAddress) {
                # no ip address returned from the dns request
                Write-Host 'IP Not Found' -ForegroundColor Red
                # move to the next computer
                continue
            }
            # check if we got multiple ips
            if ($IpAddress.Count -gt 1) {
                # check each ip for a computer name
                foreach ($Ip in $IpAddress) {
                    # get the computer name for this ip
                    $ComputerDns = Get-HostFromDns -Ip $Ip
                    # no computer name was returned for the ip
                    if ($null -eq $ComputerDns) {
                        # this ip did not return a name
                        continue
                    }
                    # if the computer name matches our computer, stop the loop
                    if ($ComputerDns.ToLower() -eq $Computer.ToLower()) { break }
                }
            }
            else {
                # otherwise, get the computer name for the ip
                $ComputerDns =  Get-HostFromDns -Ip $IpAddress
            }
        }
        catch  {
            # write our dns error
            Write-Host 'DNS Error' -ForegroundColor Red
            Write-Host ($_ | Out-String)
            # move to the next computer
            continue
        }

        # try to run a script on the remote computer
        try {
            # check if our dns name is null
            if ($null -eq $ComputerDns) {
                # dns entry not found, so move to the next computer
                Write-Host 'DNS Not Found' -ForegroundColor Red
                continue
            }
            # check if the name from dns matches our name
            if ($ComputerDns.ToLower() -eq $Computer.ToLower()) {
                # change our default settings for our remote session used by invoke-command
                $PssOptions = New-PSSessionOption -MaxConnectionRetryCount 0 -OpenTimeout 30000 -OperationTimeout 30000
                # invoke command options
                $Parameters = @{
                    ComputerName  = $Computer
                    FilePath      = $ScriptFile
                    ArgumentList  = $ScriptArguments
                    SessionOption = $PssOptions
                    ErrorAction   = "SilentlyContinue"
                }
                # add our credentials if they are not null
                if ($null -ne $Credentials) {
                    $Parameters.Add('Credential', $Credentials)
                }
                # run the script as a job
                $CommandResult = Invoke-Command @Parameters -AsJob
                # check if our result was null
                if ($null -eq $CommandResult) {
                    Write-Host 'Job Start Failed' -ForegroundColor Red
                }
                else {
                    Write-Host 'Job Started' -ForegroundColor DarkCyan
                }
            }
            else {
                # issue with dns, wrong computer was returned
                Write-Host 'DNS Mismatch' -ForegroundColor Red
            }
        }
        catch {
            # command failed for an unknown reason
            Write-Host 'Command Error' -ForegroundColor Red
            # write the error
            Write-Host ($_ | Out-String)
        }
    }
    else {
        # target computer could not be pinged
        Write-Host 'Offline'
    }
}

# start collecting jobs
Write-Host 'Getting Jobs...' -ForegroundColor Yellow

# store our jobs
$AllJobs = 'JOBS'
# continue checking for new jobs until none are found
while ($Null -ne $AllJobs) {
    # get all the current jobs
    $AllJobs = Get-Job
    # get each job's status
    foreach ($Job in $AllJobs) {
        # get the computer name from the job
        $Computer = $Job.Location
        # take action based on the job state
        switch ($Job.State) {
            'Failed' {
                Write-Host "$($Computer): Job Failed" -ForegroundColor Red
                Remove-Job -Job $Job -ErrorAction SilentlyContinue
            }
            {$_ -in ('Completed','Stopped')} {
                # get the job data
                $CommandResult = Receive-Job -Job $Job
                # check if our result was null
                if ($null -eq $CommandResult) {
                    # our command returned no results, move onto the next computer
                    Write-Host "$($Computer): Null Result" -ForegroundColor Red
                    continue
                }
                # check our result
                if ($CommandResult -eq $true) {
                    # remove the successful result from our output array
                    [void]$OutputComputers.Remove($Computer)
                    # command returned true and was successful
                    Write-Host "$($Computer): Success" -ForegroundColor Green
                }
                else {
                    # command returned false and has failed
                    Write-Host "$($Computer): Failed" -ForegroundColor Red
                }
                # remove the job
                Remove-Job -Job $Job -ErrorAction SilentlyContinue
            }
            {$_ -in ('Blocked', 'Suspended', 'Disconnected')} {
                # job stopped for an unknown reason
                Write-Host "$($Computer): Failed" -ForegroundColor Red
                # stop the job
                Stop-Job -Job $Job -ErrorAction SilentlyContinue
            }
            default { continue }
        }
    }
}

# only update our list if the switch is not set
if ($DoNotUpdateList -eq $false) {
    # try to write our array to file
    try {
        # write our update computer list
        $OutputComputers | Out-File -FilePath $ListFile -Force
        # file was written
        Write-Host "Wrote updated computer list '$($ListFile)'" -ForegroundColor Yellow
    }
    catch {
        # any errors
        Write-Host "Unable to write file '$($ListFile)'" -ForegroundColor Red
    }
}

# script has completed
Write-Host 'Finished' -ForegroundColor DarkCyan
