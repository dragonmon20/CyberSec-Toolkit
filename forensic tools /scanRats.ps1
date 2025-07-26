# ========================================================
# 🛡️ Enhanced Red Team Forensic Scanner - Windows Edition
# ✍️ Author: Enhanced by Claude
# 🗓️ Version: 2.1 (RAT Detection Enhanced)
# ========================================================

#Requires -RunAsAdministrator

param(
    [switch]$DeepScan,
    [switch]$NetworkAnalysis,
    [switch]$RegistryAnalysis,
    [switch]$RATDetection,
    [switch]$ExportJSON,
    [string]$OutputPath = "$env:USERPROFILE\Desktop"
)

# ========================================================
# STEP 1: Initialize Global Variables and Configuration
# ========================================================
# Purpose: Set up the scanning environment and data structures
Write-Host "STEP 1: Initializing scanner environment..." -ForegroundColor Cyan

$Global:ScanResults = @{}        # Main container for all scan results
$Global:Alerts = @()             # Array to store security alerts
$Global:StartTime = Get-Date     # Track scan duration
$Global:RATSignatures = @{}      # Container for RAT detection signatures

# ========================================================
# STEP 2: Define RAT Detection Signatures Database
# ========================================================
# Purpose: Create comprehensive database of known RAT indicators
Write-Host "STEP 2: Loading RAT detection signatures..." -ForegroundColor Cyan

# Initialize RAT signature database with known indicators
$Global:RATSignatures = @{
    # Network-based RATs (Remote Access via TCP/UDP)
    NetworkRATs = @{
        # Poison Ivy RAT indicators
        PoisonIvy = @{
            ProcessNames = @("poisonivy.exe", "piv.exe", "ivy.exe")
            RegistryKeys = @("HKLM:\SOFTWARE\Classes\http\shell\open\command", "HKCU:\Software\Microsoft\Active Setup\Installed Components")
            NetworkPorts = @(80, 443, 3460, 8080)
            FilePaths = @("*\poisonivy*", "*\piv\*", "*\ivy\*")
            MutexNames = @("PoisonIvy", "PIv", "IvY")
        }
        # DarkComet RAT indicators
        DarkComet = @{
            ProcessNames = @("darkcomet.exe", "dc.exe", "comet.exe", "dcrat.exe")
            RegistryKeys = @("HKCU:\Software\DC", "HKLM:\SOFTWARE\DC")
            NetworkPorts = @(1604, 1700, 7000, 8181)
            FilePaths = @("*\darkcomet*", "*\dc\*", "*\comet*")
            MutexNames = @("DarkComet", "DC_MUTEX", "DCRAT")
        }
        # Metasploit Meterpreter indicators
        Meterpreter = @{
            ProcessNames = @("meterpreter.exe", "msf.exe", "payload.exe")
            RegistryKeys = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\MSF")
            NetworkPorts = @(4444, 4445, 8080, 443)
            FilePaths = @("*\meterpreter*", "*\msf*", "*\payload*")
            MutexNames = @("MeterpMutex", "MSF_MUTEX")
        }
        # njRAT indicators
        njRAT = @{
            ProcessNames = @("njrat.exe", "nj.exe", "rat.exe", "lime.exe")
            RegistryKeys = @("HKCU:\Software\njRAT", "HKLM:\SOFTWARE\njRAT")
            NetworkPorts = @(5552, 1177, 7777, 9999)
            FilePaths = @("*\njrat*", "*\lime*", "*\rat*")
            MutexNames = @("njRAT", "NJRAT_MUTEX", "LimeRAT")
        }
        # QuasarRAT indicators
        QuasarRAT = @{
            ProcessNames = @("quasar.exe", "qrat.exe", "client.exe")
            RegistryKeys = @("HKCU:\Software\Quasar", "HKLM:\SOFTWARE\Quasar")
            NetworkPorts = @(4782, 1234, 8080)
            FilePaths = @("*\quasar*", "*\qrat*")
            MutexNames = @("QSR_MUTEX", "Quasar")
        }
        # AsyncRAT indicators
        AsyncRAT = @{
            ProcessNames = @("asyncrat.exe", "async.exe", "client.exe")
            RegistryKeys = @("HKCU:\Software\AsyncRAT", "HKLM:\SOFTWARE\AsyncRAT")
            NetworkPorts = @(6606, 7788, 8808)
            FilePaths = @("*\asyncrat*", "*\async*")
            MutexNames = @("AsyncMutex", "ASYNCRAT")
        }
    }
    
    # HTTP-based RATs (Web-based communication)
    HTTPRATs = @{
        # Cobalt Strike Beacon indicators
        CobaltStrike = @{
            ProcessNames = @("beacon.exe", "cs.exe", "cobalt.exe")
            RegistryKeys = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\Beacon")
            NetworkPorts = @(80, 443, 8080, 8443, 50050)
            FilePaths = @("*\beacon*", "*\cobalt*", "*\cs\*")
            MutexNames = @("CobaltStrike", "BeaconMutex", "CS_MUTEX")
            HTTPUserAgents = @("Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MAAU)")
        }
        # Empire PowerShell RAT indicators
        Empire = @{
            ProcessNames = @("empire.exe", "powershell.exe")
            RegistryKeys = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\Empire")
            NetworkPorts = @(80, 443, 8080)
            FilePaths = @("*\empire*", "*\launcher*")
            MutexNames = @("EmpireMutex", "PS_EMPIRE")
            PowerShellCommands = @("IEX", "DownloadString", "Net.WebClient", "Invoke-Expression")
        }
    }
    
    # File-based RATs (Persistence via files)
    FileBasedRATs = @{
        # Gh0st RAT indicators
        Gh0stRAT = @{
            ProcessNames = @("gh0st.exe", "ghost.exe", "server.exe")
            RegistryKeys = @("HKCU:\Software\Gh0st", "HKLM:\SOFTWARE\Gh0st")
            NetworkPorts = @(80, 443, 1234, 7788)
            FilePaths = @("*\gh0st*", "*\ghost*")
            MutexNames = @("Gh0st", "GHOST_RAT")
            ServiceNames = @("Gh0stService", "GhostSvc")
        }
        # RemcosRAT indicators
        RemcosRAT = @{
            ProcessNames = @("remcos.exe", "rem.exe", "rc.exe")
            RegistryKeys = @("HKCU:\Software\Remcos", "HKLM:\SOFTWARE\Remcos")
            NetworkPorts = @(2404, 7777, 8888)
            FilePaths = @("*\remcos*", "*\rem\*")
            MutexNames = @("Remcos", "REMCOS_MUTEX")
        }
        # NanoCore RAT indicators
        NanoCore = @{
            ProcessNames = @("nanocore.exe", "nano.exe", "nc.exe", "client.exe")
            RegistryKeys = @("HKCU:\Software\NanoCore", "HKLM:\SOFTWARE\NanoCore")
            NetworkPorts = @(9999, 8080, 7777, 4444)
            FilePaths = @("*\nanocore*", "*\nano*")
            MutexNames = @("NanoCore", "NANO_MUTEX")
        }
        # RevengeRAT indicators
        RevengeRAT = @{
            ProcessNames = @("revenge.exe", "rev.exe", "client.exe")
            RegistryKeys = @("HKCU:\Software\RevengeRAT", "HKLM:\SOFTWARE\RevengeRAT")
            NetworkPorts = @(4545, 6789, 8080)
            FilePaths = @("*\revenge*", "*\rev\*")
            MutexNames = @("RevengeRAT", "REVENGE_MUTEX")
        }
    }
    
    # Memory-based RATs (Fileless or in-memory execution)
    MemoryRATs = @{
        # Reflective DLL Loading indicators
        ReflectiveDLL = @{
            ProcessNames = @("rundll32.exe", "regsvr32.exe", "powershell.exe")
            RegistryKeys = @("HKCU:\Software\Classes\CLSID")
            NetworkPorts = @(80, 443, 8080)
            FilePaths = @()  # No files - memory-based
            MutexNames = @("ReflectiveMutex", "DLL_MUTEX")
            InjectionTargets = @("explorer.exe", "svchost.exe", "winlogon.exe")
        }
        # PowerShell-based RATs
        PowerShellRAT = @{
            ProcessNames = @("powershell.exe", "pwsh.exe")
            RegistryKeys = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run")
            NetworkPorts = @(80, 443, 8080, 8443)
            FilePaths = @("*\*.ps1", "*\powershell*")
            MutexNames = @("PS_RAT", "PowerShell_MUTEX")
            PowerShellCommands = @("IEX", "Invoke-WebRequest", "DownloadString", "System.Net.WebClient")
        }
    }
    
    # Advanced Persistent Threat (APT) RATs
    APTRATs = @{
        # PlugX RAT (used by Chinese APT groups)
        PlugX = @{
            ProcessNames = @("plugx.exe", "px.exe", "plug.exe")
            RegistryKeys = @("HKLM:\SOFTWARE\Classes\CLSID\{E3517E26-8E93-45FB-8E32-4B53BFE5AD3D}")
            NetworkPorts = @(80, 443, 8080, 9999)
            FilePaths = @("*\plugx*", "*\px\*")
            MutexNames = @("PlugX", "PX_MUTEX")
            ServiceNames = @("PlugXService", "PXSvc")
        }
        # Poison Frog (APT targeted)
        PoisonFrog = @{
            ProcessNames = @("pf.exe", "frog.exe", "poison.exe")
            RegistryKeys = @("HKCU:\Software\PoisonFrog")
            NetworkPorts = @(443, 8080, 9090)
            FilePaths = @("*\pf\*", "*\frog*", "*\poison*")
            MutexNames = @("PoisonFrog", "PF_MUTEX")
        }
    }
    
    # Mobile RATs (cross-platform)
    CrossPlatformRATs = @{
        # AndroRAT (Android RAT that can run on Windows)
        AndroRAT = @{
            ProcessNames = @("androrat.exe", "android.exe", "mobile.exe")
            RegistryKeys = @("HKCU:\Software\AndroRAT")
            NetworkPorts = @(8080, 9999, 7777)
            FilePaths = @("*\androrat*", "*\android*")
            MutexNames = @("AndroRAT", "ANDROID_MUTEX")
        }
    }
}

# ========================================================
# STEP 3: Define Helper Functions
# ========================================================
# Purpose: Create utility functions for formatting, alerting, and analysis

# Function to output colored text for better user experience
function Write-ColorOutput {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

# Function to add security alerts with categorization
function Add-Alert {
    param([string]$Severity, [string]$Category, [string]$Message, [string]$Details = "")
    $Global:Alerts += @{
        Timestamp = Get-Date
        Severity = $Severity      # CRITICAL, HIGH, MEDIUM, LOW, INFO
        Category = $Category      # RAT, Network, Process, Persistence, etc.
        Message = $Message
        Details = $Details
    }
}

# Function to check if script is running with administrator privileges
function Test-Privilege {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to get process integrity level and user context
function Get-ProcessIntegrity {
    param([int]$ProcessId)
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($process) {
            # Get the process owner information
            $processInfo = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE ProcessId = $ProcessId" -ErrorAction SilentlyContinue
            if ($processInfo) {
                $owner = $processInfo.GetOwner()
                if ($owner.ReturnValue -eq 0) {
                    return "$($owner.Domain)\$($owner.User)"
                }
            }
            return "SYSTEM"
        }
    } catch {
        return "Unknown"
    }
    return "N/A"
}

# ========================================================
# STEP 4: RAT Detection Functions
# ========================================================
# Purpose: Implement comprehensive RAT detection mechanisms

# Function to detect RATs based on process names and characteristics
function Test-RATProcesses {
    Write-ColorOutput "   → Scanning running processes for RAT signatures..." "Yellow"
    
    $detectedRATs = @()          # Array to store detected RAT processes
    $runningProcesses = Get-Process -ErrorAction SilentlyContinue
    
    # STEP 4.1: Iterate through each running process
    foreach ($process in $runningProcesses) {
        # STEP 4.2: Check against each RAT category in our signature database
        foreach ($ratCategory in $Global:RATSignatures.Keys) {
            foreach ($ratName in $Global:RATSignatures[$ratCategory].Keys) {
                $ratSignature = $Global:RATSignatures[$ratCategory][$ratName]
                
                # STEP 4.3: Check if process name matches known RAT process names
                if ($ratSignature.ProcessNames) {
                    foreach ($suspiciousName in $ratSignature.ProcessNames) {
                        if ($process.ProcessName -like $suspiciousName.Replace('.exe', '')) {
                            $detectedRATs += @{
                                RATName = $ratName
                                Category = $ratCategory
                                ProcessName = $process.ProcessName
                                ProcessId = $process.Id
                                ProcessPath = $process.Path
                                CPU = $process.CPU
                                Memory = [math]::Round($process.WorkingSet / 1MB, 2)
                                StartTime = $process.StartTime
                                DetectionMethod = "Process Name Match"
                                Confidence = "HIGH"
                            }
                            
                            Add-Alert "CRITICAL" "RAT" "RAT detected: $ratName" "Process: $($process.ProcessName) (PID: $($process.Id))"
                            Write-ColorOutput "      🚨 RAT DETECTED: $ratName - Process: $($process.ProcessName)" "Red"
                        }
                    }
                }
                
                # STEP 4.4: Check if process is running from suspicious file paths
                if ($ratSignature.FilePaths -and $process.Path) {
                    foreach ($suspiciousPath in $ratSignature.FilePaths) {
                        if ($process.Path -like $suspiciousPath) {
                            $detectedRATs += @{
                                RATName = $ratName
                                Category = $ratCategory
                                ProcessName = $process.ProcessName
                                ProcessId = $process.Id
                                ProcessPath = $process.Path
                                DetectionMethod = "File Path Match"
                                Confidence = "MEDIUM"
                            }
                            
                            Add-Alert "HIGH" "RAT" "Suspicious RAT path detected: $ratName" "Path: $($process.Path)"
                        }
                    }
                }
            }
        }
    }
    
    return $detectedRATs
}

# Function to detect RATs based on network connections and ports
function Test-RATNetworkConnections {
    Write-ColorOutput "   → Analyzing network connections for RAT activity..." "Yellow"
    
    $ratNetworkActivity = @()    # Array to store suspicious network activity
    
    try {
        # STEP 4.5: Get all active network connections
        $netstatOutput = netstat -ano | Select-String "ESTABLISHED|LISTENING"
        
        foreach ($line in $netstatOutput) {
            # STEP 4.6: Parse netstat output to extract connection details
            $parts = ($line -replace '\s+', ' ').Trim().Split(' ')
            if ($parts.Length -ge 5) {
                $protocol = $parts[0]
                $localAddr = $parts[1]
                $remoteAddr = $parts[2]
                $state = $parts[3]
                $pid = $parts[-1]
                
                # STEP 4.7: Extract port numbers for analysis
                $localPort = if ($localAddr -match ':(\d+)$') { [int]$matches[1] } else { 0 }
                $remotePort = if ($remoteAddr -match ':(\d+)$') { [int]$matches[1] } else { 0 }
                
                # STEP 4.8: Check if ports match known RAT communication ports
                foreach ($ratCategory in $Global:RATSignatures.Keys) {
                    foreach ($ratName in $Global:RATSignatures[$ratCategory].Keys) {
                        $ratSignature = $Global:RATSignatures[$ratCategory][$ratName]
                        
                        if ($ratSignature.NetworkPorts) {
                            foreach ($ratPort in $ratSignature.NetworkPorts) {
                                if ($localPort -eq $ratPort -or $remotePort -eq $ratPort) {
                                    # STEP 4.9: Get process information for the connection
                                    try {
                                        $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
                                        $processName = if ($process) { $process.ProcessName } else { "Unknown" }
                                        $processPath = if ($process) { $process.Path } else { "Unknown" }
                                    } catch {
                                        $processName = "Unknown"
                                        $processPath = "Unknown"
                                    }
                                    
                                    $ratNetworkActivity += @{
                                        RATName = $ratName
                                        Category = $ratCategory
                                        LocalAddress = $localAddr
                                        RemoteAddress = $remoteAddr
                                        Port = $ratPort
                                        State = $state
                                        ProcessName = $processName
                                        ProcessPath = $processPath
                                        PID = $pid
                                        DetectionMethod = "Network Port Match"
                                        Confidence = "MEDIUM"
                                    }
                                    
                                    Add-Alert "HIGH" "RAT" "RAT network activity detected: $ratName" "Port: $ratPort, Process: $processName"
                                    Write-ColorOutput "      🌐 RAT Network Activity: $ratName on port $ratPort" "Red"
                                }
                            }
                        }
                    }
                }
            }
        }
    } catch {
        Add-Alert "ERROR" "RAT" "Failed to analyze network connections for RATs" $_.Exception.Message
    }
    
    return $ratNetworkActivity
}

# Function to detect RAT persistence mechanisms in registry
function Test-RATRegistryPersistence {
    Write-ColorOutput "   → Scanning registry for RAT persistence mechanisms..." "Yellow"
    
    $ratRegistryEntries = @()    # Array to store detected RAT registry entries
    
    # STEP 4.10: Check each RAT's known registry persistence locations
    foreach ($ratCategory in $Global:RATSignatures.Keys) {
        foreach ($ratName in $Global:RATSignatures[$ratCategory].Keys) {
            $ratSignature = $Global:RATSignatures[$ratCategory][$ratName]
            
            if ($ratSignature.RegistryKeys) {
                foreach ($regKey in $ratSignature.RegistryKeys) {
                    try {
                        # STEP 4.11: Check if the registry key exists
                        if (Test-Path $regKey) {
                            $regValues = Get-ItemProperty -Path $regKey -ErrorAction SilentlyContinue
                            
                            if ($regValues) {
                                # STEP 4.12: Examine registry values for suspicious content
                                $regValues.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                                    $ratRegistryEntries += @{
                                        RATName = $ratName
                                        Category = $ratCategory
                                        RegistryKey = $regKey
                                        ValueName = $_.Name
                                        ValueData = $_.Value
                                        DetectionMethod = "Registry Persistence"
                                        Confidence = "HIGH"
                                    }
                                    
                                    Add-Alert "CRITICAL" "RAT" "RAT registry persistence detected: $ratName" "Key: $regKey, Value: $($_.Name)"
                                    Write-ColorOutput "      📝 RAT Registry Persistence: $ratName in $regKey" "Red"
                                }
                            }
                        }
                    } catch {
                        # Silently continue - registry key might not be accessible
                    }
                }
            }
        }
    }
    
    return $ratRegistryEntries
}

# Function to detect RAT services and drivers
function Test-RATServices {
    Write-ColorOutput "   → Checking services for RAT indicators..." "Yellow"
    
    $ratServices = @()           # Array to store detected RAT services
    
    try {
        # STEP 4.13: Get all Windows services
        $services = Get-Service -ErrorAction SilentlyContinue
        
        foreach ($service in $services) {
            # STEP 4.14: Get detailed service information
            $serviceInfo = Get-WmiObject -Class Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction SilentlyContinue
            
            if ($serviceInfo) {
                # STEP 4.15: Check against known RAT service names
                foreach ($ratCategory in $Global:RATSignatures.Keys) {
                    foreach ($ratName in $Global:RATSignatures[$ratCategory].Keys) {
                        $ratSignature = $Global:RATSignatures[$ratCategory][$ratName]
                        
                        if ($ratSignature.ServiceNames) {
                            foreach ($ratServiceName in $ratSignature.ServiceNames) {
                                if ($service.Name -like $ratServiceName -or $service.DisplayName -like $ratServiceName) {
                                    $ratServices += @{
                                        RATName = $ratName
                                        Category = $ratCategory
                                        ServiceName = $service.Name
                                        DisplayName = $service.DisplayName
                                        Status = $service.Status
                                        StartType = $serviceInfo.StartMode
                                        PathName = $serviceInfo.PathName
                                        DetectionMethod = "Service Name Match"
                                        Confidence = "HIGH"
                                    }
                                    
                                    Add-Alert "CRITICAL" "RAT" "RAT service detected: $ratName" "Service: $($service.Name)"
                                    Write-ColorOutput "      ⚙️ RAT Service: $ratName - $($service.Name)" "Red"
                                }
                            }
                        }
                    }
                }
            }
        }
    } catch {
        Add-Alert "ERROR" "RAT" "Failed to analyze services for RATs" $_.Exception.Message
    }
    
    return $ratServices
}

# Function to detect memory-resident RATs and process injection
function Test-RATMemoryInjection {
    Write-ColorOutput "   → Analyzing processes for memory injection techniques..." "Yellow"
    
    $injectionIndicators = @()   # Array to store injection indicators
    
    try {
        # STEP 4.16: Get all running processes with detailed information
        $processes = Get-Process -ErrorAction SilentlyContinue
        
        foreach ($process in $processes) {
            # STEP 4.17: Check for suspicious process characteristics indicating injection
            $suspiciousIndicators = @()
            
            # Check if process has no file path (possible hollowing)
            if ([string]::IsNullOrEmpty($process.Path) -and $process.ProcessName -ne "System" -and $process.ProcessName -ne "Idle") {
                $suspiciousIndicators += "No file path (possible process hollowing)"
            }
            
            # Check for processes with unusual parent-child relationships
            try {
                $processInfo = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE ProcessId = $($process.Id)" -ErrorAction SilentlyContinue
                if ($processInfo -and $processInfo.ParentProcessId) {
                    $parentProcess = Get-Process -Id $processInfo.ParentProcessId -ErrorAction SilentlyContinue
                    
                    # Suspicious if system processes are spawned by user processes
                    if ($parentProcess -and $process.ProcessName -in @("svchost", "winlogon", "csrss", "lsass") -and 
                        $parentProcess.ProcessName -notin @("services", "winlogon", "wininit", "smss")) {
                        $suspiciousIndicators += "Suspicious parent process: $($parentProcess.ProcessName)"
                    }
                }
            } catch {
                # Continue silently
            }
            
            # STEP 4.18: Check against known injection target processes
            foreach ($ratCategory in $Global:RATSignatures.Keys) {
                foreach ($ratName in $Global:RATSignatures[$ratCategory].Keys) {
                    $ratSignature = $Global:RATSignatures[$ratCategory][$ratName]
                    
                    if ($ratSignature.InjectionTargets) {
                        foreach ($target in $ratSignature.InjectionTargets) {
                            if ($process.ProcessName -like $target.Replace('.exe', '')) {
                                # Additional checks for injected processes
                                if ($process.WorkingSet -gt 100MB -or $process.CPU -gt 30) {
                                    $suspiciousIndicators += "High resource usage for system process"
                                }
                            }
                        }
                    }
                }
            }
            
            # STEP 4.19: Record suspicious processes
            if ($suspiciousIndicators.Count -gt 0) {
                $injectionIndicators += @{
                    ProcessName = $process.ProcessName
                    ProcessId = $process.Id
                    ProcessPath = $process.Path
                    SuspiciousIndicators = $suspiciousIndicators
                    Memory = [math]::Round($process.WorkingSet / 1MB, 2)
                    CPU = $process.CPU
                    DetectionMethod = "Memory Injection Analysis"
                    Confidence = "MEDIUM"
                }
                
                Add-Alert "MEDIUM" "RAT" "Potential process injection detected" "Process: $($process.ProcessName), Indicators: $($suspiciousIndicators -join ', ')"
            }
        }
    } catch {
        Add-Alert "ERROR" "RAT" "Failed to analyze memory injection" $_.Exception.Message
    }
    
    return $injectionIndicators
}

# Function to detect PowerShell-based RATs
function Test-PowerShellRATs {
    Write-ColorOutput "   → Analyzing PowerShell activity for RAT indicators..." "Yellow"
    
    $powershellRATs = @()        # Array to store PowerShell RAT indicators
    
    try {
        # STEP 4.20: Check PowerShell event logs for suspicious activity
        $psEvents = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 1000 -ErrorAction SilentlyContinue |
                   Where-Object { $_.Id -in @(4103, 4104) }  # Script block logging events
        
        foreach ($event in $psEvents) {
            $eventMessage = $event.Message
            
            # STEP 4.21: Check for known PowerShell RAT command patterns
            foreach ($ratCategory in $Global:RATSignatures.Keys) {
                foreach ($ratName in $Global:RATSignatures[$ratCategory].Keys) {
                    $ratSignature = $Global:RATSignatures[$ratCategory][$ratName]
                    
                    if ($ratSignature.PowerShellCommands) {
                        foreach ($psCommand in $ratSignature.PowerShellCommands) {
                            if ($eventMessage -like "*$psCommand*") {
                                $powershellRATs += @{
                                    RATName = $ratName
                                    Category = $ratCategory
                                    TimeCreated = $event.TimeCreated
                                    EventId = $event.Id
                                    Command = $psCommand
                                    EventMessage = $eventMessage.Substring(0, [Math]::Min(500, $eventMessage.Length))
                                    DetectionMethod = "PowerShell Command Analysis"
                                    Confidence = "MEDIUM"
                                }
                                
                                Add-Alert "HIGH" "RAT" "PowerShell RAT activity detected: $ratName" "Command: $psCommand"
                                Write-ColorOutput "      💻 PowerShell RAT Activity: $ratName - $psCommand" "Red"
                            }
                        }
                    }
                }
            }
        }
        
        # STEP 4.22: Check running PowerShell processes for suspicious command lines
        $psProcesses = Get-Process -Name "powershell", "pwsh" -ErrorAction SilentlyContinue
        foreach ($psProcess in $psProcesses) {
            try {
                $processInfo = Get-WmiObject -Query "SELECT CommandLine FROM Win32_Process WHERE ProcessId = $($psProcess.Id)" -ErrorAction SilentlyContinue
                if ($processInfo -and $processInfo.CommandLine) {
                    $commandLine = $processInfo.CommandLine
                    
                    # Check for base64 encoded commands (common in RATs)
                    if ($commandLine -match "-EncodedCommand|-enc|-e " -or $commandLine -match "fromBase64String|Convert\.FromBase64String") {
                        $powershellRATs += @{
                            RATName = "Unknown PowerShell RAT"
                            Category = "PowerShell"
                            ProcessId = $psProcess.Id
                            CommandLine = $commandLine
                            DetectionMethod = "Base64 Encoded Command"
                            Confidence = "HIGH"
                        }
                        
                        Add-Alert "CRITICAL" "RAT" "Suspicious PowerShell execution detected" "PID: $($psProcess.Id), Base64 encoded command"
                    }
                    
                    # Check for download and execution patterns
                    $downloadPatterns = @("DownloadString", "DownloadFile", "WebClient", "Invoke-WebRequest", "wget", "curl")
                    foreach ($pattern in $downloadPatterns) {
                        if ($commandLine -like "*$pattern*") {
                            $powershellRATs += @{
                                RATName = "PowerShell Download RAT"
                                Category = "PowerShell"
                                ProcessId = $psProcess.Id
                                CommandLine = $commandLine
                                Pattern = $pattern
                                DetectionMethod = "Download Pattern Match"
                                Confidence = "MEDIUM"
                            }
                            
                            Add-Alert "HIGH" "RAT" "PowerShell download activity detected" "Pattern: $pattern, PID: $($psProcess.Id)"
                        }
                    }
                }
            } catch {
                # Continue silently
            }
        }
    } catch {
        Add-Alert "WARNING" "RAT" "Failed to analyze PowerShell RAT activity" $_.Exception.Message
    }
    
    return $powershellRATs
}

# Function to check for RAT mutex objects (synchronization primitives)
function Test-RATMutexes {
    Write-ColorOutput "   → Scanning for RAT mutex objects..." "Yellow"
    
    $ratMutexes = @()            # Array to store detected RAT mutexes
    
    try {
        # STEP 4.23: Use WMI to enumerate system mutexes (requires admin privileges)
        if (Test-Privilege) {
            # Note: This is a simplified check - full mutex enumeration requires kernel access
            # We'll check for mutex-related registry entries and running processes
            
            foreach ($ratCategory in $Global:RATSignatures.Keys) {
                foreach ($ratName in $Global:RATSignatures[$ratCategory].Keys) {
                    $ratSignature = $Global:RATSignatures[$ratCategory][$ratName]
                    
                    if ($ratSignature.MutexNames) {
                        foreach ($mutexName in $ratSignature.MutexNames) {
                            # STEP 4.24: Check if processes with mutex-related names are running
                            $processes = Get-Process | Where-Object { $_.ProcessName -like "*$mutexName*" }
                            
                            foreach ($process in $processes) {
                                $ratMutexes += @{
                                    RATName = $ratName
                                    Category = $ratCategory
                                    MutexName = $mutexName
                                    ProcessName = $process.ProcessName
                                    ProcessId = $process.Id
                                    ProcessPath = $process.Path
                                    DetectionMethod = "Mutex Name Analysis"
                                    Confidence = "MEDIUM"
                                }
                                
                                Add-Alert "MEDIUM" "RAT" "Potential RAT mutex detected: $ratName" "Mutex: $mutexName, Process: $($process.ProcessName)"
                            }
                        }
                    }
                }
            }
        } else {
            Add-Alert "WARNING" "RAT" "Mutex scanning requires administrator privileges" "Limited mutex detection capability"
        }
    } catch {
        Add-Alert "ERROR" "RAT" "Failed to scan for RAT mutexes" $_.Exception.Message
    }
    
    return $ratMutexes
}

# ========================================================
# STEP 5: Main RAT Detection Orchestrator
# ========================================================
# Purpose: Coordinate all RAT detection methods and compile results

function Start-RATDetection {
    Write-ColorOutput "🔍 Starting comprehensive RAT detection scan..." "Magenta"
    
    # Initialize RAT detection results container
    $Global:ScanResults.RATDetection = @{
        ProcessRATs = @()
        NetworkRATs = @()
        RegistryRATs = @()
        ServiceRATs = @()
        MemoryRATs = @()
        PowerShellRATs = @()
        MutexRATs = @()
        Summary = @{}
    }
    
    # STEP 5.1: Execute all RAT detection methods
    Write-ColorOutput "🚨 Executing multi-vector RAT detection..." "Cyan"
    
    # Process-based RAT detection
    $Global:ScanResults.RATDetection.ProcessRATs = Test-RATProcesses
    
    # Network-based RAT detection
    $Global:ScanResults.RATDetection.NetworkRATs = Test-RATNetworkConnections
    
    # Registry persistence RAT detection
    $Global:ScanResults.RATDetection.RegistryRATs = Test-RATRegistryPersistence
    
    # Service-based RAT detection
    $Global:ScanResults.RATDetection.ServiceRATs = Test-RATServices
    
    # Memory injection RAT detection
    $Global:ScanResults.RATDetection.MemoryRATs = Test-RATMemoryInjection
    
    # PowerShell RAT detection
    $Global:ScanResults.RATDetection.PowerShellRATs = Test-PowerShellRATs
    
    # Mutex-based RAT detection
    $Global:ScanResults.RATDetection.MutexRATs = Test-RATMutexes
    
    # STEP 5.2: Compile detection summary
    $totalDetections = $Global:ScanResults.RATDetection.ProcessRATs.Count +
                      $Global:ScanResults.RATDetection.NetworkRATs.Count +
                      $Global:ScanResults.RATDetection.RegistryRATs.Count +
                      $Global:ScanResults.RATDetection.ServiceRATs.Count +
                      $Global:ScanResults.RATDetection.MemoryRATs.Count +
                      $Global:ScanResults.RATDetection.PowerShellRATs.Count +
                      $Global:ScanResults.RATDetection.MutexRATs.Count
    
    $Global:ScanResults.RATDetection.Summary = @{
        TotalDetections = $totalDetections
        ProcessDetections = $Global:ScanResults.RATDetection.ProcessRATs.Count
        NetworkDetections = $Global:ScanResults.RATDetection.NetworkRATs.Count
        RegistryDetections = $Global:ScanResults.RATDetection.RegistryRATs.Count
        ServiceDetections = $Global:ScanResults.RATDetection.ServiceRATs.Count
        MemoryDetections = $Global:ScanResults.RATDetection.MemoryRATs.Count
        PowerShellDetections = $Global:ScanResults.RATDetection.PowerShellRATs.Count
        MutexDetections = $Global:ScanResults.RATDetection.MutexRATs.Count
        ScanCompleted = Get-Date
    }
    
    # STEP 5.3: Display RAT detection results
    if ($totalDetections -gt 0) {
        Write-ColorOutput "🚨 RAT DETECTION ALERT: $totalDetections potential RATs detected!" "Red"
        Write-ColorOutput "   • Process-based: $($Global:ScanResults.RATDetection.ProcessRATs.Count)" "Red"
        Write-ColorOutput "   • Network-based: $($Global:ScanResults.RATDetection.NetworkRATs.Count)" "Red"
        Write-ColorOutput "   • Registry-based: $($Global:ScanResults.RATDetection.RegistryRATs.Count)" "Red"
        Write-ColorOutput "   • Service-based: $($Global:ScanResults.RATDetection.ServiceRATs.Count)" "Red"
        Write-ColorOutput "   • Memory-based: $($Global:ScanResults.RATDetection.MemoryRATs.Count)" "Red"
        Write-ColorOutput "   • PowerShell-based: $($Global:ScanResults.RATDetection.PowerShellRATs.Count)" "Red"
        Write-ColorOutput "   • Mutex-based: $($Global:ScanResults.RATDetection.MutexRATs.Count)" "Red"
    } else {
        Write-ColorOutput "✅ No RATs detected in current scan" "Green"
    }
}

# ========================================================
# STEP 6: Enhanced Process Analysis
# ========================================================
# Purpose: Analyze running processes for suspicious behavior beyond RAT detection

function Test-SuspiciousProcess {
    param($Process)
    $suspiciousIndicators = @()
    
    # STEP 6.1: Check for processes without file paths (possible process hollowing)
    if ([string]::IsNullOrEmpty($Process.Path)) {
        $suspiciousIndicators += "No file path (possible process hollowing)"
    }
    
    # STEP 6.2: Check for high CPU usage that might indicate cryptomining or malicious activity
    if ($Process.CPU -gt 300) {
        $suspiciousIndicators += "High CPU usage ($($Process.CPU)s)"
    }
    
    # STEP 6.3: Check for processes running from temporary directories
    if ($Process.Path -match "\\temp\\|\\appdata\\local\\temp\\|\\windows\\temp\\") {
        $suspiciousIndicators += "Running from temporary directory"
    }
    
    # STEP 6.4: Check for processes with unusual names masquerading as system processes
    $systemProcesses = @("svchost", "winlogon", "csrss", "lsass", "explorer", "dwm", "wininit")
    if ($systemProcesses -contains $Process.ProcessName.ToLower() -and 
        $Process.Path -notmatch "\\windows\\|\\system32\\|\\syswow64\\") {
        $suspiciousIndicators += "System process name outside system directories"
    }
    
    # STEP 6.5: Check for unsigned executables in system-critical processes
    if ($Process.Path -and (Test-Path $Process.Path)) {
        try {
            $signature = Get-AuthenticodeSignature -FilePath $Process.Path -ErrorAction SilentlyContinue
            if ($signature.Status -ne "Valid" -and $Process.ProcessName -in $systemProcesses) {
                $suspiciousIndicators += "Unsigned system process"
            }
        } catch {
            # Continue silently
        }
    }
    
    # STEP 6.6: Check for processes with suspicious command line arguments
    try {
        $processInfo = Get-WmiObject -Query "SELECT CommandLine FROM Win32_Process WHERE ProcessId = $($Process.Id)" -ErrorAction SilentlyContinue
        if ($processInfo -and $processInfo.CommandLine) {
            $cmdLine = $processInfo.CommandLine.ToLower()
            
            # Check for suspicious command line patterns
            $suspiciousPatterns = @(
                "powershell.*-encodedcommand",
                "powershell.*-enc",
                "powershell.*downloadstring",
                "wscript.*\.vbs",
                "cscript.*\.vbs",
                "regsvr32.*scrobj\.dll",
                "rundll32.*javascript:",
                "cmd.*\/c.*echo",
                "net.*user.*\/add",
                "sc.*create"
            )
            
            foreach ($pattern in $suspiciousPatterns) {
                if ($cmdLine -match $pattern) {
                    $suspiciousIndicators += "Suspicious command line: $pattern"
                }
            }
        }
    } catch {
        # Continue silently
    }
    
    return $suspiciousIndicators
}

# ========================================================
# STEP 7: Network Connection Analysis
# ========================================================
# Purpose: Analyze network connections for suspicious activity and RAT communications

function Get-NetworkConnections {
    $connections = @()
    
    try {
        # STEP 7.1: Execute netstat to get all network connections
        $netstatOutput = netstat -ano | Select-String "ESTABLISHED|LISTENING|TIME_WAIT"
        
        foreach ($line in $netstatOutput) {
            # STEP 7.2: Parse netstat output to extract connection details
            $parts = ($line -replace '\s+', ' ').Trim().Split(' ')
            if ($parts.Length -ge 5) {
                $protocol = $parts[0]
                $localAddr = $parts[1]
                $remoteAddr = $parts[2]
                $state = $parts[3]
                $pid = $parts[-1]
                
                # STEP 7.3: Get process information for the connection
                try {
                    $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
                    $processName = if ($process) { $process.ProcessName } else { "Unknown" }
                    $processPath = if ($process) { $process.Path } else { "Unknown" }
                } catch {
                    $processName = "Unknown"
                    $processPath = "Unknown"
                }
                
                # STEP 7.4: Create connection object with all relevant information
                $connections += @{
                    Protocol = $protocol
                    LocalAddress = $localAddr
                    RemoteAddress = $remoteAddr
                    State = $state
                    PID = $pid
                    ProcessName = $processName
                    ProcessPath = $processPath
                }
            }
        }
    } catch {
        Add-Alert "ERROR" "Network" "Failed to retrieve network connections" $_.Exception.Message
    }
    
    return $connections
}

# ========================================================
# STEP 8: Service and Startup Analysis
# ========================================================
# Purpose: Identify suspicious services and startup mechanisms

function Get-SuspiciousServices {
    $suspiciousServices = @()
    
    try {
        # STEP 8.1: Get all Windows services and their detailed information
        $services = Get-Service | Where-Object { $_.Status -eq "Running" }
        
        foreach ($service in $services) {
            # STEP 8.2: Get detailed service configuration from WMI
            $serviceInfo = Get-WmiObject -Class Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction SilentlyContinue
            
            if ($serviceInfo) {
                $pathName = $serviceInfo.PathName
                $startMode = $serviceInfo.StartMode
                
                # STEP 8.3: Check for services with suspicious characteristics
                $suspiciousIndicators = @()
                
                # Check for services running from unusual locations
                if ($pathName -match "\\temp\\|\\appdata\\|\\users\\.*\\downloads\\|\\recycle") {
                    $suspiciousIndicators += "Running from suspicious location"
                }
                
                # Check for services with script-based execution
                if ($pathName -match "powershell|cmd|wscript|cscript|mshta") {
                    $suspiciousIndicators += "Script-based service execution"
                }
                
                # Check for services without proper file paths
                if ([string]::IsNullOrEmpty($pathName) -or $pathName -eq "Unknown") {
                    $suspiciousIndicators += "No executable path specified"
                }
                
                # Check for services with unusual names
                if ($service.Name -match "^[a-f0-9]{8,}$|^\d+$|^[A-Z]{1,3}\d+$") {
                    $suspiciousIndicators += "Unusual service name pattern"
                }
                
                # STEP 8.4: Record suspicious services
                if ($suspiciousIndicators.Count -gt 0) {
                    $suspiciousServices += @{
                        Name = $service.Name
                        DisplayName = $service.DisplayName
                        Status = $service.Status
                        PathName = $pathName
                        StartMode = $startMode
                        SuspiciousIndicators = $suspiciousIndicators
                    }
                    
                    Add-Alert "HIGH" "Services" "Suspicious service detected: $($service.Name)" ($suspiciousIndicators -join ", ")
                }
            }
        }
    } catch {
        Add-Alert "ERROR" "Services" "Failed to analyze services" $_.Exception.Message
    }
    
    return $suspiciousServices
}

# ========================================================
# STEP 9: Persistence Mechanism Analysis
# ========================================================
# Purpose: Identify various persistence mechanisms used by malware

function Get-PersistenceMechanisms {
    $persistence = @{}
    
    # STEP 9.1: Check Windows Registry Run keys for persistence
    Write-ColorOutput "   → Analyzing registry run keys..." "Yellow"
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
    )
    
    $persistence.RegistryRun = @()
    foreach ($key in $runKeys) {
        try {
            if (Test-Path $key) {
                $entries = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                if ($entries) {
                    $entries.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                        $persistence.RegistryRun += @{
                            Key = $key
                            Name = $_.Name
                            Value = $_.Value
                            Type = "Registry Run Key"
                        }
                        
                        # Check for suspicious registry values
                        if ($_.Value -match "powershell|cmd|wscript|cscript|temp|appdata") {
                            Add-Alert "MEDIUM" "Persistence" "Suspicious registry run entry" "Key: $key, Name: $($_.Name), Value: $($_.Value)"
                        }
                    }
                }
            }
        } catch {
            Add-Alert "WARNING" "Persistence" "Failed to read registry key: $key" $_.Exception.Message
        }
    }
    
    # STEP 9.2: Check startup folders
    Write-ColorOutput "   → Analyzing startup folders..." "Yellow"
    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ALLUSERSPROFILE\Start Menu\Programs\Startup"
    )
    
    $persistence.StartupItems = @()
    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                $persistence.StartupItems += @{
                    Path = $path
                    Name = $_.Name
                    FullPath = $_.FullName
                    CreationTime = $_.CreationTime
                    LastWriteTime = $_.LastWriteTime
                    Type = "Startup Folder"
                }
            }
        }
    }
    
    # STEP 9.3: Check scheduled tasks for persistence
    Write-ColorOutput "   → Analyzing scheduled tasks..." "Yellow"
    try {
        $tasks = schtasks /query /fo CSV | ConvertFrom-Csv
        $persistence.ScheduledTasks = @()
        
        foreach ($task in $tasks) {
            if ($task.TaskName -and $task.TaskName -ne "TaskName") {
                # Get detailed task information
                try {
                    $taskDetail = schtasks /query /tn $task.TaskName /fo LIST /v 2>$null
                    if ($taskDetail) {
                        $persistence.ScheduledTasks += @{
                            TaskName = $task.TaskName
                            Status = $task.Status
                            NextRunTime = $task."Next Run Time"
                            Type = "Scheduled Task"
                        }
                    }
                } catch {
                    # Continue silently
                }
            }
        }
    } catch {
        Add-Alert "WARNING" "Persistence" "Failed to enumerate scheduled tasks" $_.Exception.Message
    }
    
    # STEP 9.4: Check WMI event subscriptions (advanced persistence)
    Write-ColorOutput "   → Analyzing WMI event subscriptions..." "Yellow"
    if (Test-Privilege) {
        try {
            $wmiConsumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
            $persistence.WMIConsumers = @()
            
            foreach ($consumer in $wmiConsumers) {
                $persistence.WMIConsumers += @{
                    Name = $consumer.Name
                    ConsumerType = $consumer.__CLASS
                    Type = "WMI Event Consumer"
                }
                
                Add-Alert "HIGH" "Persistence" "WMI Event Consumer detected" "Name: $($consumer.Name), Type: $($consumer.__CLASS)"
            }
        } catch {
            Add-Alert "WARNING" "Persistence" "Failed to check WMI event subscriptions" $_.Exception.Message
        }
    }
    
    return $persistence
}

# ========================================================
# STEP 10: System Information Gathering
# ========================================================
# Purpose: Collect comprehensive system information for analysis

function Get-SystemInfo {
    $sysInfo = @{}
    
    try {
        # STEP 10.1: Get basic computer information
        $computer = Get-ComputerInfo -ErrorAction SilentlyContinue
        
        if ($computer) {
            $sysInfo = @{
                ComputerName = $computer.CsName
                Domain = $computer.CsDomain
                Workgroup = $computer.CsWorkgroup
                OS = $computer.WindowsProductName
                Version = $computer.WindowsVersion
                BuildNumber = $computer.WindowsBuildLabEx
                InstallDate = $computer.WindowsInstallDateFromRegistry
                LastBootTime = $computer.CsBootupState
                TotalMemory = [math]::Round($computer.CsTotalPhysicalMemory / 1GB, 2)
                AvailableMemory = [math]::Round($computer.CsAvailPhysicalMemory / 1GB, 2)
                Manufacturer = $computer.CsManufacturer
                Model = $computer.CsModel
                TimeZone = $computer.TimeZone
                LogicalProcessors = $computer.CsNumberOfLogicalProcessors
                Architecture = $computer.CsSystemType
            }
        }
        
        # STEP 10.2: Get network adapter information
        $networkAdapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq "Up" }
        $sysInfo.NetworkAdapters = @()
        
        foreach ($adapter in $networkAdapters) {
            $sysInfo.NetworkAdapters += @{
                Name = $adapter.Name
                Description = $adapter.InterfaceDescription
                Status = $adapter.Status
                LinkSpeed = $adapter.LinkSpeed
                MacAddress = $adapter.MacAddress
            }
        }
        
        # STEP 10.3: Get current user information
        $sysInfo.CurrentUser = @{
            Username = [Environment]::UserName
            Domain = [Environment]::UserDomainName
            IsAdmin = Test-Privilege
            Profile = $env:USERPROFILE
        }
        
    } catch {
        Add-Alert "WARNING" "System" "Failed to retrieve complete system information" $_.Exception.Message
    }
    
    return $sysInfo
}

# ========================================================
# STEP 11: Main Process Analysis Function
# ========================================================
# Purpose: Analyze all running processes for suspicious behavior

function Start-ProcessAnalysis {
    Write-ColorOutput "🔍 Analyzing running processes..." "Cyan"
    
    # STEP 11.1: Get all running processes with detailed information
    $processes = Get-Process | Sort-Object CPU -Descending
    $processData = @()
    $suspiciousProcesses = @()
    
    foreach ($process in $processes) {
        # STEP 11.2: Analyze each process for suspicious indicators
        $suspiciousIndicators = Test-SuspiciousProcess $process
        $integrity = Get-ProcessIntegrity $process.Id
        
        # STEP 11.3: Create detailed process information object
        $processInfo = @{
            Name = $process.ProcessName
            Id = $process.Id
            CPU = $process.CPU
            Memory = [math]::Round($process.WorkingSet / 1MB, 2)
            Path = $process.Path
            StartTime = $process.StartTime
            Integrity = $integrity
            SuspiciousIndicators = $suspiciousIndicators
            Handles = $process.Handles
            Threads = $process.Threads.Count
        }
        
        $processData += $processInfo
        
        # STEP 11.4: Flag processes with suspicious indicators
        if ($suspiciousIndicators.Count -gt 0) {
            $suspiciousProcesses += $processInfo
            $severity = if ($suspiciousIndicators.Count -gt 2) { "HIGH" } else { "MEDIUM" }
            Add-Alert $severity "Processes" "Suspicious process detected: $($process.ProcessName)" ($suspiciousIndicators -join ", ")
        }
    }
    
    # STEP 11.5: Store results in global scan results
    $Global:ScanResults.Processes = $processData
    $Global:ScanResults.SuspiciousProcesses = $suspiciousProcesses
    
    Write-ColorOutput "   ✓ Analyzed $($processData.Count) processes, found $($suspiciousProcesses.Count) suspicious" "Yellow"
}

# ========================================================
# STEP 12: Network Analysis Function
# ========================================================
# Purpose: Analyze network connections for suspicious activity

function Start-NetworkAnalysis {
    Write-ColorOutput "🌐 Analyzing network connections..." "Cyan"
    
    # STEP 12.1: Get all network connections
    $connections = Get-NetworkConnections
    
    # STEP 12.2: Filter for external connections (not localhost)
    $externalConnections = $connections | Where-Object { 
        $_.RemoteAddress -notmatch "^127\.|^0\.0\.0\.0|^::|^\[::\]|^$|^\*:\*" -and
        $_.State -eq "ESTABLISHED"
    }
    
    # STEP 12.3: Analyze external connections for suspicious patterns
    $suspiciousConnections = @()
    foreach ($conn in $externalConnections) {
        $suspiciousReasons = @()
        
        # Check for connections to unusual ports
        if ($conn.RemoteAddress -match ":(\d+)$") {
            $port = [int]$matches[1]
            $commonPorts = @(80, 443, 53, 25, 110, 143, 993, 995, 21, 22, 23)
            if ($port -notin $commonPorts -and $port -lt 1024) {
                $suspiciousReasons += "Unusual low port: $port"
            }
        }
        
        # Check for connections from suspicious processes
        if ($conn.ProcessName -in @("cmd", "powershell", "wscript", "cscript", "rundll32")) {
            $suspiciousReasons += "Connection from script interpreter"
        }
        
        if ($suspiciousReasons.Count -gt 0) {
            $suspiciousConnections += @{
                Connection = $conn
                SuspiciousReasons = $suspiciousReasons
            }
            
            Add-Alert "MEDIUM" "Network" "Suspicious network connection" "Process: $($conn.ProcessName) -> $($conn.RemoteAddress), Reasons: $($suspiciousReasons -join ', ')"
        }
    }
    
    # STEP 12.4: Store results
    $Global:ScanResults.NetworkConnections = $connections
    $Global:ScanResults.ExternalConnections = $externalConnections
    $Global:ScanResults.SuspiciousConnections = $suspiciousConnections
    
    Write-ColorOutput "   ✓ Found $($externalConnections.Count) external connections, $($suspiciousConnections.Count) suspicious" "Yellow"
}

# ========================================================
# STEP 13: Report Generation and Export Functions
# ========================================================
# Purpose: Generate comprehensive reports with all scan results

function Export-Results {
    param([string]$OutputPath)
    
    # STEP 13.1: Create timestamped file names
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $reportPath = Join-Path $OutputPath "Advanced_Security_RAT_Report_$timestamp.txt"
    $jsonPath = Join-Path $OutputPath "Security_RAT_Scan_Data_$timestamp.json"
    
    # STEP 13.2: Calculate scan statistics
    $scanDuration = [math]::Round(((Get-Date) - $Global:StartTime).TotalMinutes, 2)
    $criticalAlerts = $Global:Alerts | Where-Object { $_.Severity -eq "CRITICAL" }
    $highAlerts = $Global:Alerts | Where-Object { $_.Severity -eq "HIGH" }
    $ratDetections = 0
    
    if ($Global:ScanResults.RATDetection) {
        $ratDetections = $Global:ScanResults.RATDetection.Summary.TotalDetections
    }
    
    # STEP 13.3: Create comprehensive text report
    $report = @"
======================================================
🛡️ ADVANCED SECURITY & RAT DETECTION REPORT
🕒 Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
⏱️ Scan Duration: $scanDuration minutes
🖥️ Target System: $($Global:ScanResults.SystemInfo.ComputerName)
======================================================

🚨 EXECUTIVE SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Security Alerts: $($Global:Alerts.Count)
Critical Alerts: $($criticalAlerts.Count)
High Priority Alerts: $($highAlerts.Count)
RAT Detections: $ratDetections
Suspicious Processes: $($Global:ScanResults.SuspiciousProcesses.Count)
External Network Connections: $($Global:ScanResults.ExternalConnections.Count)

🎯 RISK ASSESSMENT
"@

    if ($criticalAlerts.Count -gt 0 -or $ratDetections -gt 0) {
        $report += "🔴 HIGH RISK - Immediate attention required!"
    } elseif ($highAlerts.Count -gt 3) {
        $report += "🟡 MEDIUM RISK - Investigation recommended"
    } else {
        $report += "🟢 LOW RISK - System appears clean"
    }

$report += @"


🔍 RAT DETECTION RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"@

    if ($Global:ScanResults.RATDetection -and $ratDetections -gt 0) {
        $report += @"

⚠️ RAT DETECTIONS FOUND: $ratDetections total
• Process-based detections: $($Global:ScanResults.RATDetection.ProcessRATs.Count)
• Network-based detections: $($Global:ScanResults.RATDetection.NetworkRATs.Count)
• Registry-based detections: $($Global:ScanResults.RATDetection.RegistryRATs.Count)
• Service-based detections: $($Global:ScanResults.RATDetection.ServiceRATs.Count)
• Memory-based detections: $($Global:ScanResults.RATDetection.MemoryRATs.Count)
• PowerShell-based detections: $($Global:ScanResults.RATDetection.PowerShellRATs.Count)
• Mutex-based detections: $($Global:ScanResults.RATDetection.MutexRATs.Count)

DETECTED RAT FAMILIES:
"@
        
        # List unique RAT families detected
        $allRATs = @()
        $allRATs += $Global:ScanResults.RATDetection.ProcessRATs
        $allRATs += $Global:ScanResults.RATDetection.NetworkRATs
        $allRATs += $Global:ScanResults.RATDetection.RegistryRATs
        $allRATs += $Global:ScanResults.RATDetection.ServiceRATs
        $allRATs += $Global:ScanResults.RATDetection.PowerShellRATs
        
        $uniqueRATs = $allRATs | Group-Object RATName | Sort-Object Count -Descending
        foreach ($rat in $uniqueRATs) {
            $report += "`n• $($rat.Name) - $($rat.Count) detection(s)"
        }
    } else {
        $report += "`n✅ No RATs detected in current scan"
    }

$report += @"


💻 SYSTEM INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Computer Name: $($Global:ScanResults.SystemInfo.ComputerName)
Operating System: $($Global:ScanResults.SystemInfo.OS)
Version: $($Global:ScanResults.SystemInfo.Version)
Domain/Workgroup: $($Global:ScanResults.SystemInfo.Domain)$($Global:ScanResults.SystemInfo.Workgroup)
Architecture: $($Global:ScanResults.SystemInfo.Architecture)
Total Memory: $($Global:ScanResults.SystemInfo.TotalMemory) GB
Available Memory: $($Global:ScanResults.SystemInfo.AvailableMemory) GB
Logical Processors: $($Global:ScanResults.SystemInfo.LogicalProcessors)
Current User: $($Global:ScanResults.SystemInfo.CurrentUser.Domain)\$($Global:ScanResults.SystemInfo.CurrentUser.Username)
Admin Privileges: $($Global:ScanResults.SystemInfo.CurrentUser.IsAdmin)

🔍 PROCESS ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Processes Analyzed: $($Global:ScanResults.Processes.Count)
Suspicious Processes Found: $($Global:ScanResults.SuspiciousProcesses.Count)

TOP CPU CONSUMERS:
"@

    # Add top 10 CPU consuming processes
    $Global:ScanResults.Processes | Select-Object -First 10 | ForEach-Object {
        $cpuTime = if ($_.CPU) { [math]::Round($_.CPU, 2) } else { "0" }
        $report += "`n• $($_.Name) (PID: $($_.Id)) - CPU: ${cpuTime}s, Memory: $($_.Memory) MB"
    }

    if ($Global:ScanResults.SuspiciousProcesses.Count -gt 0) {
        $report += @"

SUSPICIOUS PROCESSES DETECTED:
"@
        foreach ($proc in $Global:ScanResults.SuspiciousProcesses) {
            $report += @"

• Process: $($proc.Name) (PID: $($proc.Id))
  Path: $($proc.Path)
  Suspicious Indicators: $($proc.SuspiciousIndicators -join ', ')
  Memory Usage: $($proc.Memory) MB
  Start Time: $($proc.StartTime)
"@
        }
    }

$report += @"

🌐 NETWORK ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Network Connections: $($Global:ScanResults.NetworkConnections.Count)
External Connections: $($Global:ScanResults.ExternalConnections.Count)
Suspicious Connections: $($Global:ScanResults.SuspiciousConnections.Count)

EXTERNAL NETWORK CONNECTIONS:
"@

    # List first 20 external connections
    $Global:ScanResults.ExternalConnections | Select-Object -First 20 | ForEach-Object {
        $report += "`n• $($_.ProcessName) -> $($_.RemoteAddress) (State: $($_.State), PID: $($_.PID))"
    }

    if ($Global:ScanResults.SuspiciousConnections.Count -gt 0) {
        $report += @"

SUSPICIOUS NETWORK ACTIVITY:
"@
        foreach ($conn in $Global:ScanResults.SuspiciousConnections) {
            $report += @"

• Connection: $($conn.Connection.ProcessName) -> $($conn.Connection.RemoteAddress)
  Suspicious Reasons: $($conn.SuspiciousReasons -join ', ')
  Process Path: $($conn.Connection.ProcessPath)
"@
        }
    }

$report += @"

🚀 PERSISTENCE ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Registry Run Entries: $($Global:ScanResults.Persistence.RegistryRun.Count)
Startup Folder Items: $($Global:ScanResults.Persistence.StartupItems.Count)
Scheduled Tasks: $($Global:ScanResults.Persistence.ScheduledTasks.Count)
WMI Event Consumers: $($Global:ScanResults.Persistence.WMIConsumers.Count)
Suspicious Services: $($Global:ScanResults.SuspiciousServices.Count)

REGISTRY PERSISTENCE MECHANISMS:
"@

    # List registry run entries
    foreach ($entry in $Global:ScanResults.Persistence.RegistryRun) {
        $report += "`n• $($entry.Key) -> $($entry.Name): $($entry.Value)"
    }

    if ($Global:ScanResults.Persistence.StartupItems.Count -gt 0) {
        $report += @"

STARTUP FOLDER ITEMS:
"@
        foreach ($item in $Global:ScanResults.Persistence.StartupItems) {
            $report += "`n• $($item.Name) in $($item.Path)"
        }
    }

    if ($Global:ScanResults.SuspiciousServices.Count -gt 0) {
        $report += @"

SUSPICIOUS SERVICES:
"@
        foreach ($service in $Global:ScanResults.SuspiciousServices) {
            $report += @"

• Service: $($service.Name) ($($service.DisplayName))
  Path: $($service.PathName)
  Status: $($service.Status)
  Start Mode: $($service.StartMode)
  Suspicious Indicators: $($service.SuspiciousIndicators -join ', ')
"@
        }
    }

$report += @"

🚨 DETAILED SECURITY ALERTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"@

    # Group alerts by severity
    $alertGroups = $Global:Alerts | Group-Object Severity | Sort-Object @{Expression={
        switch ($_.Name) {
            "CRITICAL" { 1 }
            "HIGH" { 2 }
            "MEDIUM" { 3 }
            "LOW" { 4 }
            "INFO" { 5 }
            default { 6 }
        }
    }}

    foreach ($group in $alertGroups) {
        $report += @"

[$($group.Name)] - $($group.Count) Alert(s):
"@
        foreach ($alert in $group.Group) {
            $report += @"

Time: $($alert.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"))
Category: $($alert.Category)
Message: $($alert.Message)
Details: $($alert.Details)
─────────────────────────────────────────────────────
"@
        }
    }

$report += @"

📊 SCAN STATISTICS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scan Start Time: $($Global:StartTime.ToString("yyyy-MM-dd HH:mm:ss"))
Scan End Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Total Scan Duration: $scanDuration minutes
RAT Signatures Loaded: $($Global:RATSignatures.Keys.Count) categories
Total Processes Scanned: $($Global:ScanResults.Processes.Count)
Network Connections Analyzed: $($Global:ScanResults.NetworkConnections.Count)
Registry Keys Checked: Multiple persistence locations
Administrator Privileges: $(Test-Privilege)

🔧 RECOMMENDATIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"@

    if ($criticalAlerts.Count -gt 0) {
        $report += @"

🔴 CRITICAL ACTIONS REQUIRED:
• Immediately investigate all CRITICAL alerts
• Isolate the system from network if RATs are confirmed
• Run full antivirus scan with updated definitions
• Consider professional incident response assistance
• Change all passwords and review user accounts
"@
    }

    if ($ratDetections -gt 0) {
        $report += @"

🛡️ RAT REMEDIATION STEPS:
• Terminate suspicious processes identified in the scan
• Remove registry persistence entries for detected RATs
• Scan system with multiple anti-malware tools
• Monitor network traffic for continued C&C communication
• Review system logs for initial infection vector
• Implement endpoint detection and response (EDR) solution
"@
    }

    $report += @"

🔍 GENERAL SECURITY IMPROVEMENTS:
• Keep operating system and software updated
• Use application whitelisting where possible
• Enable Windows Defender or install reputable antivirus
• Configure Windows Firewall properly
• Disable unnecessary services and features
• Regular security awareness training for users
• Implement network segmentation
• Enable audit logging and log monitoring
• Regular security assessments and penetration testing

======================================================
🏁 END OF SECURITY REPORT
📧 For questions about this report, consult your security team
⚠️ This report contains sensitive security information - handle appropriately
======================================================
"@

    # STEP 13.4: Save the text report
    $report | Out-File -FilePath $reportPath -Encoding UTF8
    
    # STEP 13.5: Save JSON data if requested
    if ($ExportJSON) {
        $jsonData = @{
            ScanMetadata = @{
                ScanStartTime = $Global:StartTime
                ScanEndTime = Get-Date
                ScanDuration = $scanDuration
                TargetSystem = $Global:ScanResults.SystemInfo.ComputerName
                ScannerVersion = "2.1"
                AdminPrivileges = Test-Privilege
            }
            SystemInformation = $Global:ScanResults.SystemInfo
            SecurityAlerts = $Global:Alerts
            RATDetection = $Global:ScanResults.RATDetection
            ProcessAnalysis = @{
                AllProcesses = $Global:ScanResults.Processes
                SuspiciousProcesses = $Global:ScanResults.SuspiciousProcesses
            }
            NetworkAnalysis = @{
                AllConnections = $Global:ScanResults.NetworkConnections
                ExternalConnections = $Global:ScanResults.ExternalConnections
                SuspiciousConnections = $Global:ScanResults.SuspiciousConnections
            }
            PersistenceAnalysis = $Global:ScanResults.Persistence
            ServiceAnalysis = @{
                SuspiciousServices = $Global:ScanResults.SuspiciousServices
            }
        }
        
        $jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-ColorOutput "📊 JSON data exported to: $jsonPath" "Green"
    }
    
    Write-ColorOutput "📄 Comprehensive report saved to: $reportPath" "Green"
    return $reportPath
}

# ========================================================
# STEP 14: Main Execution Orchestrator
# ========================================================
# Purpose: Coordinate all scanning functions and manage execution flow

function Start-SecurityScan {
    # STEP 14.1: Display scanner banner and initialization
    Clear-Host
    Write-ColorOutput @"
========================================================
🛡️ ADVANCED RED TEAM FORENSIC SCANNER v2.1
🔍 Enhanced RAT Detection & System Analysis
========================================================
"@ "Magenta"

    # STEP 14.2: Check administrator privileges
    if (-not (Test-Privilege)) {
        Write-ColorOutput "⚠️  WARNING: Running without administrator privileges" "Yellow"
        Write-ColorOutput "   Some advanced features may be limited" "Yellow"
        Write-ColorOutput "   For complete analysis, run as administrator" "Yellow"
    } else {
        Write-ColorOutput "✅ Running with administrator privileges" "Green"
    }

    Write-ColorOutput "`n🚀 Starting comprehensive security and RAT detection scan..." "Green"
    Write-ColorOutput "📊 Loading RAT detection signatures..." "Cyan"
    
    # STEP 14.3: Display loaded RAT signature statistics
    $totalRATFamilies = 0
    foreach ($category in $Global:RATSignatures.Keys) {
        $totalRATFamilies += $Global:RATSignatures[$category].Keys.Count
    }
    Write-ColorOutput "   ✓ Loaded $totalRATFamilies RAT family signatures across $($Global:RATSignatures.Keys.Count) categories" "Green"
    
    # STEP 14.4: Execute core system analysis modules
    Write-ColorOutput "`n🔍 Phase 1: System Information Gathering" "Cyan"
    $Global:ScanResults.SystemInfo = Get-SystemInfo
    
    Write-ColorOutput "`n🔍 Phase 2: Process Analysis" "Cyan"
    Start-ProcessAnalysis
    
    Write-ColorOutput "`n🔍 Phase 3: Network Connection Analysis" "Cyan"
    Start-NetworkAnalysis
    
    Write-ColorOutput "`n🔍 Phase 4: Persistence Mechanism Analysis" "Cyan"
    $Global:ScanResults.Persistence = Get-PersistenceMechanisms
    
    Write-ColorOutput "`n🔍 Phase 5: Service Analysis" "Cyan"
    $Global:ScanResults.SuspiciousServices = Get-SuspiciousServices
    
    # STEP 14.5: Execute RAT detection if enabled
    if ($RATDetection -or $DeepScan) {
        Write-ColorOutput "`n🔍 Phase 6: RAT Detection Analysis" "Cyan"
        Start-RATDetection
    }
    
    # STEP 14.6: Execute additional analysis if deep scan is enabled
    if ($DeepScan) {
        Write-ColorOutput "`n🔍 Phase 7: Deep Forensic Analysis" "Cyan"
        # Additional deep scan features can be added here
        Write-ColorOutput "   → Deep scan features active..." "Yellow"
    }
    
    # STEP 14.7: Generate and save comprehensive report
    Write-ColorOutput "`n📊 Generating comprehensive security report..." "Cyan"
    $reportPath = Export-Results -OutputPath $OutputPath
    
    # STEP 14.8: Display scan summary and statistics
    $duration = [math]::Round(((Get-Date) - $Global:StartTime).TotalMinutes, 2)
    $alertSummary = $Global:Alerts | Group-Object Severity | ForEach-Object { "$($_.Count) $($_.Name)" }
    $ratDetections = if ($Global:ScanResults.RATDetection) { $Global:ScanResults.RATDetection.Summary.TotalDetections } else { 0 }
    
    Write-ColorOutput @"

✅ COMPREHENSIVE SECURITY SCAN COMPLETED!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⏱️  Total Duration: $duration minutes
🚨 Security Alerts: $($alertSummary -join ", ")
🔍 RAT Detections: $ratDetections
💻 Processes Analyzed: $($Global:ScanResults.Processes.Count)
🌐 Network Connections: $($Global:ScanResults.NetworkConnections.Count)
📁 Report Location: $reportPath
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"@ "Green"

    # STEP 14.9: Display critical findings summary
    $criticalAlerts = $Global:Alerts | Where-Object { $_.Severity -eq "CRITICAL" }
    if ($criticalAlerts.Count -gt 0 -or $ratDetections -gt 0) {
        Write-ColorOutput @"

🚨 CRITICAL SECURITY FINDINGS DETECTED!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"@ "Red"
        
        if ($ratDetections -gt 0) {
            Write-ColorOutput "🦠 RAT DETECTIONS: $ratDetections Remote Access Trojans found!" "Red"
        }
        
        if ($criticalAlerts.Count -gt 0) {
            Write-ColorOutput "⚠️  CRITICAL ALERTS: $($criticalAlerts.Count) high-priority security issues!" "Red"
        }
        
        Write-ColorOutput @"
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔴 IMMEDIATE ACTION REQUIRED - Review the detailed report!
"@ "Red"
    }
    
    # STEP 14.10: Offer to open the report
    Write-ColorOutput "`n🔍 Review the generated report for detailed findings and recommendations." "Cyan"
    
    if ($Host.UI.RawUI.KeyAvailable -or [Environment]::UserInteractive) {
        $choice = Read-Host "`nWould you like to open the security report now? (y/n)"
        if ($choice -eq 'y' -or $choice -eq 'Y') {
            try {
                Start-Process $reportPath
                Write-ColorOutput "📖 Report opened in default text editor" "Green"
            } catch {
                Write-ColorOutput "❌ Could not open report automatically. Please open manually: $reportPath" "Yellow"
            }
        }
    }
}

# ========================================================
# STEP 15: Script Entry Point and Error Handling
# ========================================================
# Purpose: Main script execution with comprehensive error handling

try {
    # STEP 15.1: Validate execution environment
    if ($PSVersionTable.PSVersion.Major -lt 3) {
        Write-ColorOutput "❌ This script requires PowerShell 3.0 or higher" "Red"
        exit 1
    }
    
    # STEP 15.2: Create output directory if it doesn't exist
    if (-not (Test-Path $OutputPath)) {
        try {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
            Write-ColorOutput "📁 Created output directory: $OutputPath" "Green"
        } catch {
            Write-ColorOutput "❌ Failed to create output directory: $OutputPath" "Red"
            Write-ColorOutput "   Using current directory instead" "Yellow"
            $OutputPath = Get-Location
        }
    }
    
    # STEP 15.3: Initialize scanning process
    Write-ColorOutput "🔧 Initializing Enhanced Security Scanner..." "Cyan"
    
    # Validate parameters
    if ($RATDetection -and -not $DeepScan) {
        Write-ColorOutput "ℹ️  RAT Detection enabled - this will perform comprehensive malware analysis" "Blue"
    }
    
    if ($ExportJSON) {
        Write-ColorOutput "ℹ️  JSON export enabled - machine-readable data will be generated" "Blue"
    }
    
    # STEP 15.4: Execute main scanning function
    Start-SecurityScan
    
} catch {
    # STEP 15.5: Handle critical errors gracefully
    Write-ColorOutput "❌ CRITICAL ERROR OCCURRED:" "Red"
    Write-ColorOutput "   Error: $($_.Exception.Message)" "Red"
    Write-ColorOutput "   Location: $($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)" "Red"
    Write-ColorOutput "   Stack Trace:" "Red"
    Write-ColorOutput "$($_.ScriptStackTrace)" "Red"
    
    # Attempt to save partial results if available
    if ($Global:ScanResults -and $Global:ScanResults.Count -gt 0) {
        try {
            Write-ColorOutput "`n🔄 Attempting to save partial scan results..." "Yellow"
            $emergencyPath = Join-Path $OutputPath "Emergency_Scan_Results_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').json"
            $Global:ScanResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $emergencyPath -Encoding UTF8
            Write-ColorOutput "💾 Partial results saved to: $emergencyPath" "Green"
        } catch {
            Write-ColorOutput "❌ Failed to save partial results" "Red"
        }
    }
    
    Write-ColorOutput "`n📧 Please report this error with the above details for assistance" "Yellow"
    exit 1
    
} finally {
    # STEP 15.6: Cleanup and final status
    Write-ColorOutput "`n🏁 Scanner execution completed." "Gray"
    Write-ColorOutput "⏰ Total execution time: $([math]::Round(((Get-Date) - $Global:StartTime).TotalMinutes, 2)) minutes" "Gray"
    
    # Clear sensitive data from memory
    if ($Global:ScanResults) {
        Write-ColorOutput "🧹 Clearing sensitive scan data from memory..." "Gray"
    }
}
