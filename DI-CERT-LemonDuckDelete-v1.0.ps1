# Permitted to be displayed by DI as a reference
# LemonDuck cleanup by Digital Investigation v1.3

# Get host info
$HostName = "$env:COMPUTERNAME"
$IPAddress = (Test-Connection -ComputerName $env:computername -count 1).IPV4Address.ipaddressTOstring
$OSVersion = (get-itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName

# Set log settings
$Date = Get-Date -Format "dd-MM-yyyy"
$LogPath = "C:\Install\DI-CERT\" 
$FileName = "$HostName" + "_$Date"
$LogFileOutput = $LogPath + $FileName + "_delete" + ".log"

# Custom logging function 
function Write-LogEntry ([String] $message) {
    $timestamp = "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    "$timestamp - $Hostname - $message" >> $LogFileOutput
}

# Write host info to logfile
Write-LogEntry "Date: $Date"
Write-LogEntry "Hostname: $HostName"
Write-LogEntry "IP: $IPAddress"
Write-LogEntry "OS: $OSVersion"

# Array of IoC's file paths found during the investigation in november 2020 (refering to IR report)
$files = @("C:\Windows\Temp\nable55108366.log",
"C:\Windows\Temp\RemoteExecStub.EXE",
"C:\Windows\Temp\jscript.dll_reset.cmd",
"C:\Windows\Temp\RemoteExecStub.EXE",
"C:\Windows\Temp\jscript.dll_reset.cmd",
"C:\Windows\Temp\nable55108366.log",
"C:\Windows\Temp\RemoteExecStub.EXE",
"C:\Users\**\Microsoft\Windows\Start Menu\Programs\Startup\run.bat",
"C:\Users\administrator.xxx\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\run.bat",
"C:\Users\MonAdmin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\run.bat",
"C:\Users\Sofon.Admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\run.bat",
"C:\Users\Sofon.Admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\run.bat",
"C:\Users\Sysop\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\run.bat",
"C:\Windows\BETO",
"C:\Windows\kSleXMvU.exe",
"C:\Windows\rzqAWbSl.exe",
"C:\Windows\iHbtAYcg.exe",
"C:\Windows\Temp\tmp.vbs",
"C:\Windows\Temp\hash.txt",
"C:\Windows\qHHOkEs.exe",
"C:\Windows\jXMQUpOe.exe",
"C:\Windows\System32\WindowsPowerShell\v1.0\dRV8JDh.exe",
"C:\Windows\Temp\m6.bin.ori",
"C:\Windows\Temp\m6.bin.exe",
"C:\Windows\Temp\_MEI205802\Crypto\Cipher\_ARC4.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Cipher\_Salsa20.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Cipher\_chacha20.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Cipher\_raw_aes.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Cipher\_raw_aesni.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Cipher\_raw_arc2.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Cipher\_raw_blowfish.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Cipher\_raw_cast.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Cipher\_raw_cbc.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Cipher\_raw_cfb.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Cipher\_raw_ctr.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Cipher\_raw_des.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Cipher\_raw_des3.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Cipher\_raw_ecb.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Cipher\_raw_eksblowfish.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Cipher\_raw_ocb.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Cipher\_raw_ofb.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Hash\_BLAKE2b.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Hash\_BLAKE2s.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Hash\_MD2.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Hash\_MD4.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Hash\_MD5.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Hash\_RIPEMD160.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Hash\_SHA1.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Hash\_SHA224.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Hash\_SHA256.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Hash\_SHA384.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Hash\_SHA512.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Hash\_ghash_clmul.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Hash\_ghash_portable.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Hash\_keccak.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Hash\_poly1305.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Cipher",
"C:\Windows\Temp\_MEI205802\Crypto\Hash",
"C:\Windows\Temp\_MEI205802\Crypto",
"C:\Windows\Temp\_MEI205802",
"C:\Windows\Temp\_MEI205802\Crypto\Math\_modexp.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Protocol\_scrypt.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\PublicKey\_ec_ws.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Math",
"C:\Windows\Temp\_MEI205802\Crypto\Protocol",
"C:\Windows\Temp\_MEI205802\Crypto\PublicKey",
"C:\Windows\Temp\_MEI205802\Crypto\Util",
"C:\Windows\Temp\_MEI205802\Crypto\Util\_cpuid_c.pyd",
"C:\Windows\Temp\_MEI205802\Crypto\Util\_strxor.pyd",
"C:\Windows\Temp\_MEI205802\Microsoft.VC90.CRT.manifest",
"C:\Windows\Temp\_MEI205802\_ctypes.pyd",
"C:\Windows\Temp\_MEI205802\_hashlib.pyd",
"C:\Windows\Temp\_MEI205802\_multiprocessing.pyd",
"C:\Windows\Temp\_MEI205802\_socket.pyd",
"C:\Windows\Temp\_MEI205802\_ssl.pyd",
"C:\Windows\Temp\_MEI205802\bz2.pyd",
"C:\Windows\Temp\_MEI205802\i_new.exe.manifest",
"C:\Windows\Temp\_MEI205802\msvcm90.dll",
"C:\Windows\Temp\_MEI205802\pyexpat.pyd",
"C:\Windows\Temp\_MEI205802\python27.dll",
"C:\Windows\Temp\_MEI205802\pywintypes27.dll",
"C:\Windows\Temp\_MEI205802\select.pyd",
"C:\Windows\Temp\_MEI205802\unicodedata.pyd",
"C:\Windows\Temp\_MEI205802\win32api.pyd",
"C:\Windows\Temp\_MEI205802\win32event.pyd",
"C:\Windows\Temp\_MEI205802\win32pipe.pyd",
"C:\Windows\lOwFVXxi.exe",
"C:\Windows\Temp\admin.txt",
"C:\Windows\m2.ps1",
"C:\Windows\mkatz.ini",
"C:\Windows\OxUjPJgX.exe",
"C:\Windows\TTcEuhW.exe",
"C:\Windows\OxUjPJgX.exe",
"C:\Windows\gKNiStWb.exe",
"C:\Windows\FDgduKDX.exe",
"C:\Windows\HkbR.exe",
"C:\Windows\ymVOIP.exe",
"C:\Windows\gKNiStWb.exe",
"C:\Windows\FDgduKDX.exe",
"C:\Windows\PZGjShvo.exe",
"C:\Windows\rzqAWbSl.exe",
"C:\Windows\PqEtEsVH.exe",
"C:\Windows\System32\Tasks\blackball")

# Check presence of IoC files & delete such files

foreach ($file in $files){
    try
    {        
        if(Test-Path $file){

            Remove-Item -Path $file -Recurse
        }        
    }
    catch
    {
       Write-LogEntry "Failed to delete file: $file"   
    }
}

# Find copies of Powershell.exe and check if they're present in the Defender Exclusions
try {   
    Get-Childitem -Path "C:\Windows\System32\WindowsPowerShell\v1.0\*.exe" | ForEach-Object {
        $Name = $_.Name 
        $OriginalFilename = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).OriginalFilename
        if ($OriginalFilename -notmatch "MUI") {
            if ($Name -notmatch $OriginalFilename) { 
                try 
                {
                    Remove-Item -Path "C:\Windows\System32\WindowsPowerShell\v1.0\$Name"
                    
                    if (!(Test-Path "C:\Windows\System32\WindowsPowerShell\v1.0\$Name"))
                    {                        
                        Write-LogEntry "Succesfully deleted Powershell copy: $Name"
                    }
                    else
                    {
                        Write-LogEntry "Failed to delete Powershell kopie: $Name"
                    }                    
                }
                catch 
                {
                    $ErrorMessage = $_.Exception.Message    
                    Write-LogEntry "Error deleting Powershell Copy $Name - $ErrorMessage"
                }   
            }
        }
    }   
}
catch {
    $ErrorMessage = $_.Exception.Message  
    Write-LogEntry "Error while deleting powershell copy: $ErrorMessage"
}


# Check Scheduled Task Cache
try
{ 
    $taskcache = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks\**")
    foreach ($task in $taskcache){
        $action =  [System.Text.Encoding]::ASCII.GetString($task.Actions)
            if ($action -match '.2.m.W.o.1.7.u.X.v.G.1.B.X.p.m.d.g.v.8.v./.3.N.T.m.n.N.u.b.H.t.V.6.2.f.W.r.k.4.j.P.F.I.9.w.M.3.N.N.2.v.z.T.z.t.i.c.I.Y.H.l.m.7.K.3.r.2.m') { 
                $fullpath = 'C:\Windows\System32\Tasks' + $task.Path   
                $registry_path = $task.PSPath             
                try {
                    Remove-Item $registry_path
                    if (!(Test-Path $registry_path))
                    {
                        Write-LogEntry "Succesfully deleted task in task cache: $registry_path"
                    }
                    else {

                        Write-LogEntry "Failed to delete: $registry_path"
                    }
                }
                catch
                {
                    $ErrorMessage = $_.Exception.Message
                    Write-LogEntry "Error during removing tasks from taskcache: $ErrorMessage"             
                }                
            }
        }   
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-LogEntry "Error on taskscache: $ErrorMessage"    
}


#Check Scheduled Tasks files
try {
    $tasks = (Get-ChildItem -Path 'C:\Windows\System32\Tasks\' -Recurse -Force | Where-Object {$_.CreationTime -ge '11/09/2020' -and $_.CreationTime -le '11/11/2020' } )
    if($tasks) {
        foreach ($task in $tasks) {      
            $filename = $task.FullName   
            Remove-Item -Path $filename
            if (Test-Path $filename)
            {
                Write-LogEntry "Failed to delete Scheduled Task: $filename"                
            }
            else
            {
                Write-LogEntry "Scheduled Task $filename is succesfully deleted"
            }
    }
    # else 
    # {    
    #     Write-LogEntry "No LemonDuck scheduled tasks found"
    # }    
    }
}
catch {
    $ErrorMessage = $_.Exception.Message   
    Write-LogEntry "Error while deleting scheduled tasks: $ErrorMessage"
}
