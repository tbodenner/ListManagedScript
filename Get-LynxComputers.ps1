param (
    # switch to get all computers
    [switch]$All
)
# check our switch
if ($All -eq $true) {
    .\Get-AllADComputers.ps1 -OutFile .\Lynx\ComputerList.txt -Filter $Global:MyComputerFilter -RootOU $Global:MyRootOU
    Write-Host "List created with all computers." -ForegroundColor Cyan
}
else {
    # check if today is monday
    if ((Get-Date).DayOfWeek -eq 'Monday') {
        # otherwise, get any computers added in the last seven days
        $Date = (Get-Date).AddDays(-7)
        Write-Host "Appending list with computers added in last SEVEN days." -ForegroundColor Cyan
    }
    else {
        # otherwise, get any computers added in the last two days
        $Date = (Get-Date).AddDays(-2)
        Write-Host "Appending list with computers added in last TWO days." -ForegroundColor Cyan
    }
    # update our computer list using our date
    .\Get-AllADComputers.ps1 -OutFile .\Lynx\ComputerList.txt `
                        -Filter $Global:MyComputerFilter `
                        -RootOU $Global:MyRootOU `
                        -AfterDate $Date `
                        -Append
    Write-Host "Computer list appended." -ForegroundColor Green
}
