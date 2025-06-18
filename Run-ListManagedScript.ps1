# parameters
param (
    # script that will be run on each computer
    [Parameter(Mandatory)][string]$ScriptFile,
    # arguments to pass to the script
    [psobject[]]$ScriptArguments = $null,
    # file for our list of computers
    [string]$ListFile = '.\ComputerList.txt',
    # filter applied to Get-ADComputer
    [string]$ADFilter = 'Name -like "PRE-*"',
    # credentials to pass to the script
    [pscredential]$Credentials = $null,
    # script file does not require administrator
    [switch]$NoAdmin,
    # if set, the input list will not be updated
    [switch]$DoNotUpdateList,
    # send our credentials to the script as an argument
    [switch]$SendCredentialsToScript
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

enum ConnectionState {
    DNSError
    DNSMismatch
    DNSNotFound
    IPNotFound
    NameNotFound
    Offline
    Online
}

function Test-ComputerConnection {
    param (
        # name of the computer to ping
        [Parameter(Mandatory)][string]$Computer
    )
    # ping the computer
    if ((Test-Connection -TargetName $Computer -Ping -Count 1 -TimeoutSeconds 1 -Quiet) -eq $True) {
        # try to get dns data
        try {
            # get our computer's name from it's dns ip address
            $IpAddress = (Resolve-DnsName -Name $Computer -ErrorAction SilentlyContinue).IPAddress
            # check if our ip address is null
            if ($null -eq $IpAddress) {
                # no ip address returned from the dns request
                return [ConnectionState]::IPNotFound
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
                        return [ConnectionState]::NameNotFound
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
            Write-Host ($_ | Out-String)
            # move to the next computer
            return [ConnectionState]::DNSError
        }

        # check if our dns name is null
        if ($null -eq $ComputerDns) {
            # dns entry not found, so move to the next computer
            return [ConnectionState]::DNSNotFound
        }

        # check if the name from dns matches our name
        if ($ComputerDns.ToLower() -eq $Computer.ToLower()) {
            # no issue, computer is online
            return [ConnectionState]::Online
        }
        else {
            # issue with dns, wrong computer was returned
            return [ConnectionState]::DNSMismatch
        }
    }
    else {
        # target computer could not be pinged
        return [ConnectionState]::Offline
    }
}

function Start-RemoteCommandJob {
    param (
        # name of the remote computer
        [Parameter(Mandatory)][string]$Computer,
        # script that will be run on each computer
        [Parameter(Mandatory)][string]$ScriptFile,
        # arguments to pass to the script
        [psobject[]]$ScriptArguments = $null,
        # credentials to pass to the script
        [pscredential]$Credentials = $null
    )
    # try to run a script on the remote computer
    try {
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
            Write-Host "$($Computer): Job Start Failed" -ForegroundColor Red
        }
    }
    catch {
        # command failed for an unknown reason
        Write-Host "$($Computer): Command Error" -ForegroundColor Red
        # write the error
        Write-Host ($_ | Out-String)
    }
}

function Get-ScriptJobs {
    param (
        [Parameter(Mandatory)][System.Collections.Generic.List[string]]$ComputerList,
        [Parameter(Mandatory=$true)][int]$TotalJobs
    )
    # start collecting our finished job
    Write-Host 'Getting Script Results' -ForegroundColor Yellow
    # store our jobs
    $AllJobs = 'JOBS'
    # job counter
    $JobCount = 0
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
                    # get the result
                    $JobResult = Receive-Job -Job $Job
                    # write our message
                    Write-Host "$($Computer): Job Failed" -ForegroundColor Red
                    # remove the job
                    Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue
                    # update our count
                    $JobCount += 1
                }
                'Completed' {
                    # get the job data
                    $CommandResultTuple = Receive-Job -Job $Job
                    
                    # return tuple = (boolean, string)
                    # first item in a result tuple should be true/false
                    $Result = $CommandResultTuple.Item1
                    # second item should be a success or fail message
                    $Message = $CommandResultTuple.Item2

                    # check our result tuple
                    if ($Result -eq $true) {
                        # command returned true and was successful
                        Write-Host "$($Computer): $($Message)" -ForegroundColor Green
                    }
                    else {
                        # remove the failed result from our computer list
                        [void]$ComputerList.Remove($Computer)
                        # command returned false and has failed
                        Write-Host "$($Computer): $($Message)" -ForegroundColor Red
                    }
                    # remove the job
                    Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue
                    # update our count
                    $JobCount += 1
                }
                {$_ -in ('Stopped', 'Blocked', 'Suspended', 'Disconnected')} {
                    # get the result
                    $JobResult = Receive-Job -Job $Job
                    # write our message, job stopped for an unknown reason
                    Write-Host "$($Computer): Job Issue: $($JobResult)" -ForegroundColor Magenta
                    # stop the job
                    Stop-Job -Job $Job -ErrorAction SilentlyContinue
                    # remove the job
                    Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue
                    # update our count
                    $JobCount += 1
                }
                default { continue }
            }
        }
        # update our progress
        Update-Progress -Count $JobCount -Total $TotalJobs -Activity 'Script Results'
        # pause for a short time
        Start-Sleep -Milliseconds 500
    }
    # complete our progress
    Update-Progress -Count 0 -Total 0 -Activity 'Done' -IsDone
    # return the updated list
    return $ComputerList
}

function Get-TestConnectionJobs {
    param (
        [Parameter(Mandatory=$true)][int]$TotalJobs
    )
    # list of our online computers
    $OnlineComputers = [System.Collections.Generic.List[string]]::new()

    # start collecting our finished job
    Write-Host 'Getting Connection Results' -ForegroundColor Yellow
    # store our jobs
    $AllJobs = 'JOBS'
    # job counter
    $JobCount = 0
    # continue checking for new jobs until none are found
    while ($null -ne $AllJobs) {
        # get all the current jobs
        $AllJobs = Get-Job
        # get each job's status
        foreach ($Job in $AllJobs) {
            # get the computer name from the job
            $Computer = $Job.Name
            # take action based on the job state
            switch ($Job.State) {
                'Failed' {
                    # remove the failed job
                    Remove-Job -Job $Job -ErrorAction SilentlyContinue
                    # update our count
                    $JobCount += 1
                }
                'Completed' {
                    # get the job data
                    $CommandResult = Receive-Job -Job $Job
                    # our state
                    $State = $null
                    # check if our result was not null
                    if ($null -ne $CommandResult) {
                        # convert our result
                        $State = [ConnectionState]$CommandResult
                        # check if our state is online
                        if ($State -eq [ConnectionState]::Online) {
                            # add our computer to our list
                            $OnlineComputers.Add($Computer)
                        }
                    }
                    # remove the job
                    Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue
                    # update our count
                    $JobCount += 1
                }
                {$_ -in ('Stopped', 'Blocked', 'Suspended', 'Disconnected')} {
                    # stop the job
                    Stop-Job -Job $Job -ErrorAction SilentlyContinue
                    # remove the job
                    Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue
                    # update our count
                    $JobCount += 1
                }
                default { continue }
            }
            # update our progress
            Update-Progress -Count $JobCount -Total $TotalJobs -Activity 'Connection Results'
            # pause for a short time
            Start-Sleep -Milliseconds 500
        }
    }
    # complete our progress
    Update-Progress -Count 0 -Total 0 -Activity 'Done' -IsDone
    # return the updated list
    return $OnlineComputers
}

function Update-Progress {
    param (
        [Parameter(Mandatory=$true)][int]$Count,
        [Parameter(Mandatory=$true)][int]$Total,
        [Parameter(Mandatory=$true)][string]$Activity,
        [switch]$IsDone
    )
    # check if our total is zero
    if ($Total -eq 0) {
        # to avoid a divide by zero error, set the percentage to zero
        $PComplete = 0
    }
    else {
        # otherwise, do the math to calculate our percentage
        $PComplete = ($Count / $Total) * 100
    }
    # if our percentage is above 100 percent, set it to 100 percent
    if ($PComplete -gt 100) { $PComplete = 100 }
    # if our percentage is below zero percent, set it to zero percent
    if ($PComplete -lt 0) { $PComplete = 0 }
    # set our status message to out counts
    $Status = "$($Count)/$($Total) Complete"
    # check if we are done
    if ($IsDone -eq $true) {
        # complete our progress
        Write-Progress -Id 0 -Activity $Activity -Status $Status -PercentComplete $PComplete -Completed
    }
    else {
        # otherwise, update our progress
        Write-Progress -Id 0 -Activity $Activity -Status $Status -PercentComplete $PComplete
    }
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

# check if our credentials should be passed to our script
if ($SendCredentialsToScript -eq $true) {
    # check if we have credentials
    if ($null -eq $Credentials) {
        # get the user running the script
        $ScriptUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        # get the user's credentials
        $Credentials = Get-Credential -UserName $ScriptUser
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

# create a list for our output computers
$OutputComputers = [System.Collections.Generic.List[string]]::new()

# check if our array has any items in it
if ($Computers.Length -le 0) {
    # fill our computer array
    $Computers = $ADComputers.Clone()
    # write our list to our file
    $ADComputers | Out-File -FilePath $ListFile -Force
}

# write our computer counts
Write-Host "  AD Computers: $($ADComputers.Length)" -ForegroundColor DarkCyan
Write-Host "List Computers: $($Computers.Length)" -ForegroundColor DarkCyan

# add all our items to our output list
foreach ($Item in $Computers) {
    $OutputComputers.Add($Item)
}

# scriptblock for our test connection job
$ScriptBlockTestConnection = {
    param ([string]$Computer)

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

    enum ConnectionState {
        DNSError
        DNSMismatch
        DNSNotFound
        IPNotFound
        NameNotFound
        Offline
        Online
    }

    function Test-ComputerConnection {
        param (
            # name of the computer to ping
            [Parameter(Mandatory)][string]$Computer
        )
        # ping the computer
        if ((Test-Connection -TargetName $Computer -Ping -Count 1 -TimeoutSeconds 1 -Quiet) -eq $True) {
            # try to get dns data
            try {
                # get our computer's name from it's dns ip address
                $IpAddress = (Resolve-DnsName -Name $Computer -ErrorAction SilentlyContinue).IPAddress
                # check if our ip address is null
                if ($null -eq $IpAddress) {
                    # no ip address returned from the dns request
                    return [ConnectionState]::IPNotFound
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
                            return [ConnectionState]::NameNotFound
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
                Write-Host ($_ | Out-String)
                # move to the next computer
                return [ConnectionState]::DNSError
            }

            # check if our dns name is null
            if ($null -eq $ComputerDns) {
                # dns entry not found, so move to the next computer
                return [ConnectionState]::DNSNotFound
            }

            # check if the name from dns matches our name
            if ($ComputerDns.ToLower() -eq $Computer.ToLower()) {
                # no issue, computer is online
                return [ConnectionState]::Online
            }
            else {
                # issue with dns, wrong computer was returned
                return [ConnectionState]::DNSMismatch
            }
        }
        else {
            # target computer could not be pinged
            return [ConnectionState]::Offline
        }
    }

    # return our computer's state
    return (Test-ComputerConnection -Computer $Computer)
}

# checking if computers can be seen on the network
Write-Host "Testing Computer Connections" -ForegroundColor Yellow
# our counter
$TestConnJobCount = 0
# check if our computers are in AD and test if they computer can be seen on the network
foreach ($Computer in $Computers) {
    # skip any null or empty computers
    if (($null -eq $Computer) -or ($Computer -eq '')) { continue }
    # skip the computer running this script
    if ($env:COMPUTERNAME.ToLower() -eq $Computer.ToLower()) { continue }

    # check if the computer is not in AD
    if ($Computer -notin $ADComputers) {
        # remove the good result from our output array
        [void]$OutputComputers.Remove($Computer)
        # computer was not found in the ad computer array
        Write-Progress -ParentId 0 -Id 1 -Status "$($Computer) Not in AD or Disabled" -Activity 'Computer' -PercentComplete 0
    }
    else {
        # parameters for our start job
        $JobParameters = @{
            Name         = $Computer
            ScriptBlock  = $ScriptBlockTestConnection
            ArgumentList = $Computer
        } 
        # create a job to get our computer's connection state
        Start-Job @JobParameters | Out-Null
    }
    # update our count
    $TestConnJobCount += 1
    # update our progress
    Update-Progress -Count $TestConnJobCount -Total $Computers.Length -Activity 'Creating Test Jobs'
}
# complete our progress
Update-Progress -Count 0 -Total 0 -Activity 'Done' -IsDone
# complete our child progress
Write-Progress -ParentId 0 -Id 1 -Activity 'Done' -Completed

# a list of computers that were online when checked
$OnlineComputers = Get-TestConnectionJobs -TotalJobs $TestConnJobCount

# number of jobs started for our script
$ScriptJobCount = 0
# run our script on each online computer
foreach ($Computer in $OnlineComputers) {
    # parameters for our remote job
    $ScriptParameters = @{
        Computer = $Computer
        ScriptFile = $ScriptFile
        ScriptArguments = @($ScriptArguments)
        Credentials = $Credentials
    }
    # if this switch is set
    if ($SendCredentialsToScript -eq $true) {
        # add our credentials to our script's arguments
        $ScriptParameters['ScriptArguments'] += $Credentials
    }
    # run our script as a remote job
    Start-RemoteCommandJob @ScriptParameters
    # update our count
    $ScriptJobCount += 1
    # update our progress
    Update-Progress -Count $ScriptJobCount -Total $OnlineComputers.Length -Activity 'Creating Script Jobs'
}
# complete our progress
Update-Progress -Count 0 -Total 0 -Activity 'Done' -IsDone

# check if our list is not null
if ($null -ne $OnlineComputers) {
    # update our list from our jobs
    $FailedComputers = Get-ScriptJobs -ComputerList $OnlineComputers -TotalJobs $ScriptJobCount

    # removed the successful computers from our output list
    foreach ($Computer in $FailedComputers) {
        [void]$OutputComputers.Remove($Computer)
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
