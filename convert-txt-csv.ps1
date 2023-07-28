# Set the input and output file paths
$inputFilePath = "C:\source\temp\hardwarelist-example.txt"
$outputFilePath = "C:\source\temp\hardwarelist.csv"

function Get-RegEx-Value {
    param (
        [string]$record,
        [string]$pattern
    )
    $match = [regex]::Match($record, $pattern)
    if ($match.Success) {
        return $match.Value
    }
}


$splitText = (Get-Content $inputFilePath | Out-String) -split "(?=vd root/0)"  
$splitText = $splitText | Where-Object { $_.Trim() -ne "" }  

# Define an array to hold the device objects
$devices = @()

# Enumerate the splitText array and extract the device properties
foreach ($record in $splitText) {
    $macAddress = Get-RegEx-Value -record $record -pattern "(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"
    $ipAddress = Get-RegEx-Value -record $record -pattern "\b(?:\d{1,3}\.){3}\d{1,3}\b"
    $hardwareVendor = Get-RegEx-Value -record $record -pattern "(?<=hardware vendor ')[^']+"
    $type = Get-RegEx-Value -record $record -pattern "(?<=type ')[^']+"
    $family = Get-RegEx-Value -record $record -pattern "(?<=family ')[^']+"
    $os = Get-RegEx-Value -record $record -pattern "(?<=os ')[^']+"
    $hardwareVersion = Get-RegEx-Value -record $record -pattern "(?<=hardware version ')[^']+"
    $softwareVersion = Get-RegEx-Value -record $record -pattern "(?<=software version ')[^']+"
    $hostName = Get-RegEx-Value -record $record -pattern "(?<=host ')[^']+"
    $req = Get-RegEx-Value -record $record -pattern "(?<=req\s)[\w/]+"
    $created = Get-RegEx-Value -record $record -pattern "(?<=created\s+)\d+(?=s\s+gen\s+\d+\s+seen\s+\d+s\s+idrac31\s+gen\s+\d+)"
    $seen = Get-RegEx-Value -record $record -pattern "(?<=seen\s)\d+s"

    # Create a new device object and add it to the array
    $device = [PSCustomObject]@{
        "MAC Address" = $macAddress
        "IP Address" = $ipAddress
        "Hardware Vendor" = $hardwareVendor
        "Type" = $type
        "Family" = $family
        "OS" = $os
        "Hardware Version" = $hardwareVersion
        "Software Version" = $softwareVersion
        "Host Name" = $hostName
        "Req" = $req
        "Created" = $created
        "Seen" = $seen
    }
    $devices += $device
}

# Output the devices as a CSV file
$devices | Export-Csv $outputFilePath -NoTypeInformation