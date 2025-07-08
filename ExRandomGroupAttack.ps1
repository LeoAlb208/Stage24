# Load the Invoke-AtomicRedTeam module
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1

# Define the path for the CSV log file
$csvLogPath = "C:\Users\fravm\Documents\attackLog.csv"

# Function to log attack details to CSV
function Log-AttackDetails {
    param (
        [string]$AttackCode,
        [int]$TestNumber,
        [datetime]$StartTime,
        [datetime]$EndTime,
        [int]$ExitCode
    )
    
    $logEntry = [PSCustomObject]@{
        "Codice attacco"     = $AttackCode
        "Test Number"        = $TestNumber
        "Data inizio attacco" = $StartTime.ToString("yyyy-MM-ddTHH:mm:sszzz")
        "Data fine attacco"  = $EndTime.ToString("yyyy-MM-ddTHH:mm:sszzz")
        "Exit code"          = $ExitCode
    }

    $logEntryString = $logEntry | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1 | % {$_ -replace '"', ''}
    Add-Content -Path $csvLogPath -Value $logEntryString
}

# Initialize the CSV file with headers if it doesn't exist
if (-Not (Test-Path $csvLogPath)) {
    $headers = "Codice attacco,Test Number,Data inizio attacco,Data fine attacco,Exit code"
    Add-Content -Path $csvLogPath -Value $headers
}

# Function to log messages
function Log-Message {
    param (
        [string]$Message,
        [string]$LogFile = "Z:\attackLog.log"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $Message"
    Add-Content -Path $LogFile -Value $logEntry
}

# Function to start transcript for logging
function Start-Logging {
    param (
        [string]$TranscriptPath = "C:\Users\fravm\Documents\AtomicRedTeamPromptLog.txt"
    )
    if (Test-Path $TranscriptPath) {
        Remove-Item $TranscriptPath
    }
    Start-Transcript -Path $TranscriptPath
}

# Function to stop transcript for logging
function Stop-Logging {
    Stop-Transcript
}

# Function to execute atomic tests
function Execute-AtomicTests {
    param (
        [string[]]$TechniqueIDs = @("All"),
        [string]$ExecutionLogPath = "C:\Temp\mylog.csv",
        [switch]$PromptForInputArgs = $false
    )

    $techniques = gci C:\AtomicRedTeam\atomics\* -Recurse -Include T*.yaml | Get-AtomicTechnique

    if ($TechniqueIDs -ne @("All")) {
        $techniques = $techniques | Where-Object { $TechniqueIDs -contains $_.attack_technique }
    }

    # Randomize the order of techniques
    $techniques = $techniques | Sort-Object { Get-Random }

    foreach ($technique in $techniques) {
        $testNumber = 0
        foreach ($atomic in $technique.atomic_tests) {
            if ($atomic.supported_platforms.contains("windows") -and ($atomic.executor -ne "manual")) {
                $attackCode = $technique.attack_technique + " - "
                $testNumber++
                # Genera un numero casuale di secondi tra 1 e 60
                $randomSeconds = Get-Random -Minimum 1 -Maximum 60
                Write-Output "Inizio WAIT di $randomSeconds secondi"
                # Metti in pausa per la durata casuale
                Start-Sleep -Duration $randomDuration
                Write-Output "Fine WAIT di $randomSeconds secondi"
                
                $startTime = Get-Date

                # Invoke the test with execution logging
                $testResult = Invoke-AtomicTest $technique.attack_technique -TestGuids $atomic.auto_generated_guid -ExecutionLogPath $ExecutionLogPath
                $endTime = Get-Date

                # Read the execution log
                $executionLog = Import-Csv -Path $ExecutionLogPath | Select-Object -Last 1

                # Capture the exit code and command output from the test result
                $exitCode = $executionLog.ExitCode

                # Log the attack details
                Log-AttackDetails -AttackCode $attackCode -TestNumber $testNumber -StartTime $startTime -EndTime $endTime -ExitCode $exitCode

                # Sleep then cleanup
                Start-Sleep 2
                $cleanupResult = Invoke-AtomicTest $technique.attack_technique -TestGuids $atomic.auto_generated_guid -Cleanup
            }
        }
    }
}

# Main script logic
$logFilePath = "C:\attackLog.log"

# Ensure the log directory exists
if (-not (Test-Path -Path "C:\Users\fravm\Documents\Logs")) {
    New-Item -ItemType Directory -Path "C:\Users\fravm\Documents\Logs"
}

# Clear previous log file
if (Test-Path -Path $logFilePath) {
    Remove-Item -Path $logFilePath
}

# Start logging the prompt output
Start-Logging -TranscriptPath "C:\Users\fravm\Documents\AtomicRedTeamPromptLog.txt"

# Execute tests for each technique, example usage: @("T1003", "T1059")
$techniqueIdsToTest = @("T1059", "T1610", "T1203", "T1559", "T1106", "T1053", "T1648", "T1129", "T1072", "T1569", "T1024", "T1047", "T1098", "T1547", "T1037", "T1543", "T1546", "T1574", "T1556", "T1137", "T1542", "T1053", "T1548", "T1134", "T1547", "T1037", "T1543", "T1484", "T1546", "T1068", "T1574", "T1055", "T1053", "T1078", "T1557", "T1110", "T1555", "T1212", "T1187", "T1606", "T1056", "T1556", "T1111", "T1621", "T1003", "T1558", "T1552", "T1001", "T1587", "T1588", "T1608")
Execute-AtomicTests -TechniqueIDs $techniqueIdsToTest

# Stop logging the prompt output
Stop-Logging

Log-Message "Atomic test execution completed."
