Param(
   [Parameter(Position=1)]
   [string]$Source,
  
   [Parameter(Position=2)]
   [string]$Destination,
   [Parameter(Position=3)]
   [string]$LogPath,
   [Parameter(Position=3)]
   [string]$ExtensionFile
)

#Custom Log function
function Write-LogEntry ([String] $message) {
    $timestamp = "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    "$timestamp - $message" >> $logfile
}

#Check if specified paramters are valid directories
If ( -Not (Test-Path -Path $Destination) -or -Not (Test-Path -Path $Source) -or -Not (Test-Path -Path $ExtensionFile))
{
    Write-Host "Source or/and Destination directories not found. Exiting..."
    Exit
}

#Create Log directory if not exists
If ( -Not (Test-Path -Path "$LogPath\script_log" ) )
{
    New-Item -Path "$LogPath\script_log" -ItemType "directory" | Out-Null
}

#Create Log file 
$today = Get-Date
$logFilename = $today.ToString("yyyyMMddHHmmss")
$global:logfile = "$LogPath\script_log\Log_$logFilename.log"

New-Item -Path $logfile -ItemType "file" | Out-Null
Write-LogEntry "Specified Source and Destination directories are present. "
Write-Host "Specified Source and Destination directories are present. "
Write-LogEntry "Searching through files in Source directory.."

#Search for all files in Source directory recursively
$files = Get-ChildItem -Path $Source -Recurse -Force | Where-Object {!$_.PSIsContainer }
$filesCount = $files.Count
$cleanCount = 0
[string[]]$extensions = Get-Content -Path $ExtensionFile

Write-Host "Found $filesCount files total in Source directory."
Write-Host "Starting searching and copying clean files now.."
Foreach ( $file in $files )
{
    $filename = $file.FullName    
    if ($extensions.Contains($file.Extension.ToLower()) -or $file.Extension -eq "")
    {
        if ( $file.Name -ne "RECOVER-FILES.txt" )
        {
            try 
            {       
                #Execute robocopy with /S to copy the directory structure of the Source directory. Log to own file                        
                robocopy $Source $Destination $file.Name /E /A-:SH | Out-File -Append "$LogPath\script_log\RC_$logFilename.log"          
                Write-Host "File: $filename has been copied."    
                Write-LogEntry "File: $filename has been copied."
                $cleanCount++
            }
            catch 
            {
                Write-LogEntry "Error during copying $file. Message: $_"
            }
        }     
    }
    else
    {
        Write-LogEntry "File: $filename has been marked infected."
    }   
}

Write-Host "Total files found: $filesCount, Total files copied: $cleanCount"
Write-LogEntry "Total files found: $filesCount, Total files copied: $cleanCount"
Write-LogEntry "Script has finished"
Write-Host "Script has finished. View Log to view the files marked as 'infected'."