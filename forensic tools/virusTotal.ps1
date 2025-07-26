# ==============================
# 💣 Enhanced VirusTotal Scanner
# ==============================

# ✅ إعداداتك:
$ApiKey = "PUT_YOUR_API_KEY_HERE"
$TargetFolder = "C:\Users\$env:USERNAME\Downloads"
$VTBaseURL = "https://www.virustotal.com/api/v3/files/"
$LogFile = ".\scan_log.txt"

# 🔄 إعداد الهيدر:
$Headers = @{ "x-apikey" = $ApiKey }

# 🧼 نظف اللوج القديم:
if (Test-Path $LogFile) { Remove-Item $LogFile }

function Write-Log {
    param ([string]$Text)
    $Text | Tee-Object -FilePath $LogFile -Append
}

# ✅ دالة لحساب SHA256:
function Get-FileHashSHA256 {
    param ([string]$FilePath)
    try {
        return (Get-FileHash -Algorithm SHA256 -Path $FilePath).Hash
    } catch {
        return $null
    }
}

# ✅ دالة لفحص الفايل على VT:
function Query-VirusTotal {
    param ([string]$sha256, [string]$fileName)

    $url = $VTBaseURL + $sha256
    try {
        $response = Invoke-RestMethod -Uri $url -Headers $Headers -Method GET -ErrorAction Stop
        $stats = $response.data.attributes.last_analysis_stats
        $verdict = $response.data.attributes.popular_threat_classification.suggested_threat_label
        $link = "https://www.virustotal.com/gui/file/$sha256"

        if ($stats.malicious -gt 0) {
            Write-Log "`n[⚠️] MALICIOUS: $fileName"
            Write-Log "     ↪ Detections: $($stats.malicious) engines"
            Write-Log "     ↪ Verdict: $verdict"
            Write-Log "     ↪ Link: $link"
        } elseif ($stats.suspicious -gt 0) {
            Write-Log "`n[❓] SUSPICIOUS: $fileName"
            Write-Log "     ↪ Suspicious detections: $($stats.suspicious)"
            Write-Log "     ↪ Link: $link"
        } else {
            Write-Host "[-] Clean: $fileName"
        }

    } catch {
        Write-Log "[X] Error querying VT for: $fileName"
    }
}

# ✅ مسح المجلد:
function Scan-Folder {
    param ([string]$folder)

    Write-Host "[+] Scanning: $folder"
    Get-ChildItem -Path $folder -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        $file = $_.FullName
        try {
            if ($_.Length -lt 10240) { return } # تجاهل ملفات أقل من 10KB
            if ($_.Extension -match "\.(sys|dll|tmp|log)$") { return } # تجاهل ملفات النظام

            $sha256 = Get-FileHashSHA256 -FilePath $file
            if ($sha256) {
                Write-Host "[•] $($_.Name)"
                Query-VirusTotal -sha256 $sha256 -fileName $_.Name
            }
        } catch {
            continue
        }
    }
    Write-Log "`n[✓] Scan complete. Log saved to: $LogFile"
}

Scan-Folder -folder $TargetFolder
