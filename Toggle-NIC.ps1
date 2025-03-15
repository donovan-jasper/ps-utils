param(
    [string]$AdapterName = "Ethernet",
    [int]$IntervalSeconds = 5
)

# Infinite loop that toggles the network adapter
while ($true) {
    Write-Host "Disabling adapter '$AdapterName'..."
    Disable-NetAdapter -Name $AdapterName -Confirm:$false
    Start-Sleep -Seconds $IntervalSeconds

    Write-Host "Enabling adapter '$AdapterName'..."
    Enable-NetAdapter -Name $AdapterName -Confirm:$false
    Start-Sleep -Seconds $IntervalSeconds
}
