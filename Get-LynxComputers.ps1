# check if today is monday
if ((Get-Date).DayOfWeek -eq 'Monday') {
    # if it is monday, get all computers
    .\Get-AllADComputers.ps1 -OutFile .\Lynx\ComputerList.txt -Filter $Global:MyComputerFilter -RootOU $Global:MyRootOU
    Write-Host "List created with all computers." -ForegroundColor Cyan
}
else {
    # otherwise, get any computers added in the last two days
    $Date = (Get-Date).AddDays(-2)
    .\Get-AllADComputers.ps1 -OutFile .\Lynx\ComputerList.txt `
                             -Filter $Global:MyComputerFilter `
                             -RootOU $Global:MyRootOU `
                             -AfterDate $Date `
                             -Append
    Write-Host "Computer list appended." -ForegroundColor Green
}
