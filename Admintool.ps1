# ========== FEHLERCODE-DATENBANK + HILFE ===============
$KnownOSErrors = @(
    @{ Code="0x000000EF"; Typ="Bluescreen/SYSTEM_SERVICE_EXCEPTION"; Desc="Kernel/Service-Fehler (Treiber, Systemdateien, Hardware)"; Solution="Treiber prüfen und aktualisieren.`nWindows Updates ausführen.`n'sfc /scannow' und 'dism /online /cleanup-image /restorehealth' nutzen.`nRAM auf Fehler prüfen (Windows Speicherdiagnose)." },
    @{ Code="0x80070422"; Typ="Windows Update Fehler"; Desc="Update-Dienst deaktiviert oder Policy-Problem."; Solution="Windows Update Dienst aktivieren.`nSet-Service wuauserv -StartupType Automatic; Start-Service wuauserv`nFirewall/GPO prüfen." },
    @{ Code="0x80070005"; Typ="Access Denied"; Desc="Zugriffsfehler: Rechte fehlen, Virenscanner blockiert oder Datei gesperrt."; Solution="Als Administrator ausführen.`nDatei- und Ordnerrechte prüfen.`nVirenscanner/Schutzsoftware testweise deaktivieren." },
    @{ Code="0x800F081F"; Typ="DISM/SFC Fehler – Quelle fehlt"; Desc="Windows-Quelldateien fehlen, z.B. auf Server-Image."; Solution="Install.wim/ISO mounten, DISM mit /Source starten.`nDISM /Online /Cleanup-Image /RestoreHealth /Source:..." },
    @{ Code="43"; Typ="Gerätemanager Fehler (Code 43)"; Desc="Gerät (meist Grafik/USB) fehlerhaft oder Hardware defekt."; Solution="Gerät entfernen, neu starten, Treiber neu installieren.`nWenn dauerhaft: Gerät tauschen." },
    @{ Code="0x80070002"; Typ="Update-/Dateifehler"; Desc="Datei/Ordner nicht gefunden, oft bei Updates."; Solution="Windows Update Problembehandlung ausführen.`nSystemdatum prüfen.`n'sfc /scannow' ausführen." },
    @{ Code="0x80070003"; Typ="Update-/Dateifehler"; Desc="Pfad oder Datei konnte nicht gefunden werden."; Solution="Windows Update zurücksetzen.`nInstallationsquelle prüfen." },
    @{ Code="0x80072EFE"; Typ="Update-Timeout"; Desc="Keine Verbindung zum Update-Server (Firewall, Proxy, Netzwerkproblem)"; Solution="Internet prüfen.`nProxy/Firewall-Settings kontrollieren." },
    @{ Code="0x80240034"; Typ="Update-Fehler"; Desc="Fehler beim Herunterladen/Installieren von Updates."; Solution="Windows Update Problembehandlung.`nUpdate-Cache leeren." },
    @{ Code="0x80242006"; Typ="Update-Fehler"; Desc="Ein Update konnte nicht installiert werden."; Solution="Wiederholen oder Einzel-Update manuell installieren." },
    @{ Code="0x8024402F"; Typ="Update-Fehler (WSUS/Proxy)"; Desc="Verbindung zu Update-Server unterbrochen."; Solution="Proxy- und Netzwerk-Einstellungen kontrollieren." },
    @{ Code="0x800B0109"; Typ="Update-Fehler"; Desc="Zertifikat nicht vertrauenswürdig."; Solution="Uhrzeit prüfen.`nRoot-CA installieren/aktualisieren." },
    @{ Code="0xC1900101"; Typ="Upgrade Bluescreen"; Desc="Kompatibilitätsfehler bei Windows-Upgrade, meist Treiber."; Solution="Alle Treiber aktualisieren.`nUSB-Geräte entfernen während Upgrade." },
    @{ Code="0xC000021A"; Typ="Winlogon-Fatalfehler"; Desc="Systemprozess ist abgestürzt."; Solution="Letzte Änderungen rückgängig machen.`n'Sfc /scannow' ausführen." },
    @{ Code="0xC000000F"; Typ="Bootmgr fehlt/bootbcd Fehler"; Desc="Bootloader nicht gefunden."; Solution="Boot-Repair per Installationsmedium.`nbootrec /rebuildbcd" },
    @{ Code="0x0000007B"; Typ="INACCESSIBLE_BOOT_DEVICE"; Desc="System findet das Startlaufwerk nicht."; Solution="AHCI/IDE im BIOS umstellen.`nTreiber prüfen." },
    @{ Code="0x0000001E"; Typ="KMODE_EXCEPTION_NOT_HANDLED"; Desc="Meist Treiber-/Speicherfehler."; Solution="Treiber und RAM prüfen." },
    @{ Code="0x0000000A"; Typ="IRQL_NOT_LESS_OR_EQUAL"; Desc="Speicherzugriffsproblem (RAM, Treiber)"; Solution="RAM prüfen.`nTreiber aktualisieren." },
    @{ Code="0x00000050"; Typ="PAGE_FAULT_IN_NONPAGED_AREA"; Desc="Speicherfehler oder Treiberproblem."; Solution="RAM testen.`nTreiber prüfen." },
    @{ Code="0x0000003B"; Typ="SYSTEM_SERVICE_EXCEPTION"; Desc="Fehler im Grafik- oder Systemtreiber."; Solution="Grafiktreiber aktualisieren." },
    @{ Code="0x00000024"; Typ="NTFS_FILE_SYSTEM"; Desc="Dateisystemfehler auf Systemlaufwerk."; Solution="chkdsk ausführen.`nSSD/HDD prüfen." },
    @{ Code="0x0000007E"; Typ="SYSTEM_THREAD_EXCEPTION_NOT_HANDLED"; Desc="Meist inkompatible Treiber/Hardware."; Solution="Treiber aktualisieren." },
    @{ Code="0x0000009F"; Typ="DRIVER_POWER_STATE_FAILURE"; Desc="Treiber geht nicht korrekt in Standby/Resume."; Solution="Treiber aktualisieren." },
    @{ Code="0x80073D02"; Typ="AppX Deployment Fehler"; Desc="App kann nicht installiert werden."; Solution="Store Cache löschen.`nPC neu starten." },
    @{ Code="0x80042302"; Typ="VSS Fehler (Schattenkopien)"; Desc="Volume Shadow Copy Service nicht erreichbar."; Solution="Dienst starten.`nSystem neu starten." },
    @{ Code="0x80070570"; Typ="Installationsfehler"; Desc="Datei beschädigt oder Datenträgerfehler."; Solution="Installationsquelle prüfen.`nDatenträger testen." },
    @{ Code="0x80004005"; Typ="Unbekannter Fehler"; Desc="Viele mögliche Ursachen, meist Rechteproblem."; Solution="Mehr Details im Logfile suchen.`nAdminrechte prüfen." },
    @{ Code="0x00000116"; Typ="VIDEO_TDR_ERROR"; Desc="Grafikkarten-Treiberproblem oder Hardware."; Solution="Treiber aktualisieren.`nGPU-Hardware prüfen." },
    @{ Code="0x80090016"; Typ="TPM-Fehler"; Desc="Trusted Platform Module hat ein Problem."; Solution="TPM im BIOS aktivieren oder zurücksetzen." },
    @{ Code="0x800705B4"; Typ="Timeout Fehler"; Desc="Aktion hat zu lange gedauert, oft bei Updates."; Solution="Update-Services neu starten." },
    @{ Code="0x80070643"; Typ="Installationsfehler"; Desc="Update-Installation fehlgeschlagen."; Solution="Windows Update Problembehandlung ausführen." }
    # ...
)

function Show-KnownError {
    param([string]$MsgOrCode)
    $err = $KnownOSErrors | Where-Object { $MsgOrCode -match [regex]::Escape($_.Code) }
    if ($err) {
        Write-Host "`n>>> BEKANNTER FEHLER GEFUNDEN:" -ForegroundColor Yellow
        Write-Host "Code: $($err.Code) – $($err.Typ)" -ForegroundColor Red
        Write-Host "Beschreibung: $($err.Desc)"
        Write-Host "Lösung:`n$($err.Solution)"
        return $true
    }
    return $false
}



# ========== MENU Modusauswahl ===============
function Write-Ok($msg) { Write-Host $msg -ForegroundColor Green }
function Write-Problem($msg) { Write-Host $msg -ForegroundColor Red }
function Write-Hint($msg) { Write-Host $msg -ForegroundColor Yellow }
function Write-Section($msg) { Write-Host "`n==== $msg ====" -ForegroundColor Cyan }

Write-Host "`n######## FISI MULTI-TOOL ########" -ForegroundColor Magenta
Write-Host "1. Full Check (alles prüfen)"
Write-Host "2. Smart Check (Netzwerk & Logs, schnell)"
Write-Host "3. Exit"

$choice = Read-Host "Auswahl"



# ========== Ausgabe und Ergebnisblock ===============
function Print-DiskSmartStat($diskResult) {
    Write-Host "`n--- Festplatten/Storage Übersicht ---"
    Write-Host "Laufwerke:"
    $diskResult.Disks | ForEach-Object { Write-Host "  $($_.DeviceID): $($_.SizeGB) GB gesamt / $($_.FreeGB) GB frei" }
    Write-Host "`nPhysische Disks:"
    $diskResult.Phys | ForEach-Object { Write-Host "  $($_.Model) ($($_.SerialNumber)), $([math]::Round($_.Size/1GB,1)) GB, Status: $($_.Status)" }
    Write-Host "`nSMART Status:"
    if ($diskResult.SMART) {
        foreach ($s in $diskResult.SMART) {
            $ok = if ($s.PredictFailure -eq $false) {"OK"} else {"FEHLER!"}
            Write-Host "  Instance: $($s.InstanceName) - SMART: $ok"
        }
    } else {
        Write-Hint "SMART nicht auslesbar oder nicht unterstützt."
    }
}

function Print-Report {
    param(
        $vm, $sys, $disk, $problems, $success, $summary, $treiberDetails, $cpuTopDetails, $speedWarn
    )
    Write-Section "ERGEBNIS"
    Write-Host "Systeminformationen:"
    Write-Host " Hostname: $($sys.ComputerName)"
    Write-Host " Betriebssystem: $($sys.OS)"
    Write-Host " CPU: $($sys.CPU)"
    Write-Host " RAM: $($sys.MemoryGB) GB"
    Write-Host " Virtuell: $(if ($vm.IsVirtual) {"Ja, $($vm.Model)"} else {"Nein"})"
    Print-DiskSmartStat $disk

    Write-Section "Check-Ergebnisse"
    foreach ($msg in $success) { Write-Ok $msg }
    foreach ($msg in $problems) { 
        Write-Problem $msg 
        if ($msg -like "Treiberprobleme gefunden!*" -and $treiberDetails.Count -gt 0) {
            $treiberDetails | ForEach-Object { Write-Problem $_ }
        }
        if ($msg -like "CPU-Last > 50%*" -and $cpuTopDetails.Count -gt 0) {
            $cpuTopDetails | ForEach-Object { Write-Problem $_ }
        }
        if ($msg -like "Speedtest fehlgeschlagen*" -and $speedWarn) {
            if ($speedWarn -eq "None") {
                Write-Hint "Kein Speedtest-Tool vorhanden. Automatischer Download/Run war nicht möglich."
            } else {
                Write-Hint "Speedtest-Methode: $speedWarn. Möglicherweise Netzwerkblockade oder Tool nicht ausführbar."
            }
        }
    }
    Write-Section "FAZIT"
    Write-Hint $summary
}



# ========== Funktionen/Checks ===============

# --- VM, OS, RAM, Disks ---
function Check-VM {
    # Prüft, ob System virtuell läuft (grob per Win32_ComputerSystem)
    $cs = Get-CimInstance Win32_ComputerSystem
    $manu = $cs.Manufacturer
    $model = $cs.Model
    $isVM = ($manu -match "VMware|Microsoft|Xen|QEMU|VirtualBox|KVM|Virtu" -or $model -match "Virtual|VMware|KVM|VirtualBox|QEMU|Hyper-V")
    return @{ IsVirtual = $isVM; Model = "$manu $model" }
}

function Check-SystemInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $mem = Get-CimInstance Win32_ComputerSystem
    return @{
        ComputerName = $env:COMPUTERNAME
        OS = "$($os.Caption) $($os.Version)"
        CPU = $cpu.Name
        MemoryGB = [math]::Round($mem.TotalPhysicalMemory / 1GB, 1)
    }
}

function Check-Disks {
    $drives = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
    $list = @()
    foreach ($d in $drives) {
        $list += [pscustomobject]@{
            DeviceID = $d.DeviceID
            SizeGB   = [math]::Round($d.Size / 1GB, 1)
            FreeGB   = [math]::Round($d.FreeSpace / 1GB, 1)
        }
    }
    # Physische Disks und SMART Dummy, falls ausbaufähig
    return @{
        Disks = $list
        Phys = @()
        SMART = $null
    }
}

# --- Netzwerk-Check ---
function Check-Network {
    $results = foreach($t in @("127.0.0.1","1.1.1.1","8.8.8.8")){
        try { $r = Test-Connection -Count 3 -Quiet -ErrorAction Stop -TargetName $t; [pscustomobject]@{ Target=$t; Reachable=$r } }
        catch { [pscustomobject]@{ Target=$t; Reachable=$false } }
    }
    $gw = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop)
    $portRes = @()
    foreach($p in @(80,443,445,3389,53)) {
        try{ $tcp = Test-NetConnection -ComputerName $gw -Port $p -WarningAction SilentlyContinue
              $portRes += [pscustomobject]@{ Port=$p; TcpOpen=$tcp.TcpTestSucceeded }
        } catch { $portRes += [pscustomobject]@{ Port=$p; TcpOpen=$false } }
    }
    [pscustomobject]@{ Ping = $results; Port = $portRes }
}

# --- Speedtest ---
function Check-Speed {
    $speedtest = Get-Command speedtest -ErrorAction SilentlyContinue
    if (-not $speedtest) {
        # Versuche automatisch die Ookla Speedtest CLI temporär herunterzuladen
        $speedtestUrl = "https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-win64.zip"
        $zipPath = "$env:TEMP\speedtest.zip"
        $speedtestDir = "$env:TEMP\speedtestcli"
        $exePath = "$speedtestDir\speedtest.exe"

        try {
            Invoke-WebRequest -Uri $speedtestUrl -OutFile $zipPath -UseBasicParsing
            if (-not (Test-Path $speedtestDir)) { New-Item -ItemType Directory -Path $speedtestDir | Out-Null }
            Expand-Archive -Path $zipPath -DestinationPath $speedtestDir -Force
            Remove-Item $zipPath -Force
            $speedtest = Get-Command $exePath -ErrorAction SilentlyContinue
        } catch {
            Write-Hint "Speedtest-CLI konnte nicht automatisch geladen werden."
            $speedtest = $null
        }
    }

    if ($speedtest) {
        try {
            $out = & $speedtest --format=json --accept-license --accept-gdpr 2>$null
            if ($LASTEXITCODE -eq 0 -and $out) {
                $j = $out | ConvertFrom-Json
                # Nach Test Exe entfernen
                if (Test-Path $exePath) { Remove-Item $exePath -Force }
                if (Test-Path $speedtestDir) { Remove-Item $speedtestDir -Recurse -Force }
                return [pscustomobject]@{
                    Method   = 'Ookla'
                    PingMs   = [math]::Round($j.ping.latency,1)
                    DownMbps = [math]::Round($j.download.bandwidth*8/1MB,1)
                    UpMbps   = [math]::Round($j.upload.bandwidth*8/1MB,1)
                    Server   = $j.server.name
                }
            }
        } catch {
            Write-Hint "Speedtest-CLI konnte nicht ausgeführt werden."
        }
    }
    # HTTP-Fallback (wie bisher)
    try{
        $tmp = Join-Path $env:TEMP ("netcheck_" + [guid]::NewGuid().Guid + ".bin")
        $url = "http://speed.hetzner.de/100MB.bin"
        $wc  = New-Object System.Net.WebClient
        $sw  = [System.Diagnostics.Stopwatch]::StartNew()
        $wc.DownloadFile($url, $tmp)
        $sw.Stop()
        $bytes = (Get-Item $tmp).Length
        Remove-Item $tmp -Force
        $mbps = [math]::Round((($bytes*8)/$sw.Elapsed.TotalSeconds)/1MB,1)
        [pscustomobject]@{
            Method   = 'HTTP-Download'
            PingMs   = $null
            DownMbps = $mbps
            UpMbps   = $null
            Server   = 'Hetzner (HTTP)'
        }
    }catch{
        [pscustomobject]@{
            Method='None'; PingMs=$null; DownMbps=$null; UpMbps=$null; Server='n/a'
        }
    }
}

# --- Resource (Prozesse, Autostarts, Treiber) ---
function Check-Resource {
    $proc = Get-Process | Sort-Object CPU -Descending | Select -First 10
    $drv = Get-PnpDevice | Where-Object {$_.Status -ne 'OK'} | Select FriendlyName, Status, ProblemCode
    [pscustomobject]@{ TopProc = $proc; Driver = $drv }
}

# --- Security ---
function Check-Security {
    $def = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $icmp = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*ICMPv4-In*" -and $_.Enabled -eq "True" }
    [pscustomobject]@{ Defender = $def; ICMP = $icmp }
}

# --- Eventlog + Klartext Fehlerhilfe ---
function Check-Events {
    $since = (Get-Date).AddDays(-3)
    $ev = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$since} | 
          Where-Object { $_.LevelDisplayName -in @("Error","Warning") }
    $highlighted = $ev | Group-Object Id | Sort-Object Count -Descending | Select -First 10
    foreach ($group in $highlighted) {
        $firstEvent = $ev | Where-Object { $_.Id -eq $group.Name } | Select-Object -First 1
        $msg = $firstEvent.Message
        if (-not (Show-KnownError $msg)) {
            Write-Hint "`nUnbekannter Fehler:"
            Write-Host "EventID: $($group.Name) | Provider: $($firstEvent.ProviderName)"
            Write-Host "Text: $($msg.Substring(0, [Math]::Min(120,$msg.Length)))`n"
        }
    }
}
function Run-SmartCheck {
    Write-Section "SMART CHECK (adaptiv)"

    $problems = @()
    $success = @()
    $treiberDetails = @()
    $cpuTopDetails = @()
    $speedWarn = $null

    $deepNetCheck = $false
    $deepSysCheck = $false

    # 1. Schneller Netzwerk-Basistest (Ping)
    $net = Check-Network
    $errPings = $net.Ping | Where-Object { !$_.Reachable }
    if ($errPings) {
        foreach ($e in $errPings) { $problems += "Netzwerkproblem: Ziel $($e.Target) nicht erreichbar." }
        $deepNetCheck = $true  # Signal: tieferes Nachforschen!
    } else {
        $success += "Alle getesteten Ziele erreichbar."
    }

    # 2. Grobe System-Log-Analyse
    $eventsFound = $false
    $eventBuffer = @()
    $since = (Get-Date).AddDays(-3)
    $ev = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$since} | 
          Where-Object { $_.LevelDisplayName -in @("Error","Warning") }
    $highlighted = $ev | Group-Object Id | Sort-Object Count -Descending | Select -First 5
    foreach ($group in $highlighted) {
        $firstEvent = $ev | Where-Object { $_.Id -eq $group.Name } | Select-Object -First 1
        $msg = $firstEvent.Message
        if (-not (Show-KnownError $msg)) {
            $eventBuffer += "EventID: $($group.Name) | Provider: $($firstEvent.ProviderName) | Text: $($msg.Substring(0, [Math]::Min(120,$msg.Length)))"
        }
        $eventsFound = $true
    }
    if ($eventsFound) {
        $problems += "Fehler im System-Eventlog erkannt."
        $deepSysCheck = $true
        $problems += $eventBuffer
    } else {
        $success += "Keine kritischen Fehler im Systemlog."
    }

    # 3. Erweiterte Netzwerkprüfung (wenn grob auffällig)
    if ($deepNetCheck) {
        foreach ($t in $net.Port) {
            if ($t.TcpOpen) { $success += "Port $($t.Port) offen." } else { $problems += "Port $($t.Port) nicht offen!" }
        }
        # Weitere Checks wie DNS, DHCP, ARP, Traceroute etc. könntest du hier einbauen
    }

    # 4. Erweiterte Systemprüfung (wenn Logs auffällig)
    if ($deepSysCheck) {
        # Ressourcen/Autostarts
        $res = Check-Resource
        if ($res.Driver.Count -gt 0) {
            $problems += "Treiberprobleme gefunden!"
            $treiberDetails = $res.Driver | Select-Object -First 5 | ForEach-Object { "   - $($_.FriendlyName) [$($_.Status)] (ProblemCode: $($_.ProblemCode))" }
        }
        $cpuTop = $res.TopProc | Sort-Object CPU -Descending | Select-Object -First 2
        if ($cpuTop | Where-Object {$_.CPU -gt 50}) {
            $problems += "CPU-Last > 50% durch einzelne Prozesse."
            $cpuTopDetails = $cpuTop | ForEach-Object { "   - $($_.ProcessName) : $($_.CPU) CPU" }
        }
        # Storage/SMART
        $disk = Check-Disks
        $diskStats = @()
        $disk.Disks | ForEach-Object { $diskStats += "$($_.DeviceID): $($_.SizeGB)GB gesamt / $($_.FreeGB)GB frei" }
        $problems += $diskStats
        if ($disk.SMART) {
            foreach ($s in $disk.SMART) {
                if ($s.PredictFailure -eq $true) {
                    $problems += "SMART-Fehler! Festplatte kritisch: $($s.InstanceName)"
                }
            }
        }
        # Security/Antivirus/ICMP
        $sec = Check-Security
        if (-not ($sec.Defender.AntivirusEnabled)) { $problems += "Antivirus nicht aktiv!" }
        if (-not ($sec.ICMP)) { $problems += "ICMP (Ping) nicht erlaubt durch Firewall!" }
    }

    # Ausgabe
    $summary = if ($problems) { "Probleme erkannt! Siehe oben. Bitte analysieren und Maßnahmen ergreifen." } else { "System OK – keine gravierenden Probleme erkannt." }
    Print-Report $null $null $null $problems $success $summary $treiberDetails $cpuTopDetails $speedWarn
}



# ========== MainLogik zusammenführen ===============

switch ($choice) {
    '1' {
        $vm = Check-VM
        $sys = Check-SystemInfo
        $disk = Check-Disks
        $problems = @()
        $success  = @()
        $treiberDetails = @()
        $cpuTopDetails  = @()
        $speedWarn      = $null

        $net = Check-Network
        foreach ($p in $net.Ping) {
            if ($p.Reachable) { $success += "Ping zu $($p.Target) OK." } else { $problems += "Ping zu $($p.Target) FEHLER!" }
        }
        foreach ($t in $net.Port) {
            if ($t.TcpOpen) { $success += "Port $($t.Port) (Gateway) offen." } else { $problems += "Port $($t.Port) nicht offen!" }
        }
        $spd = Check-Speed
        if ($spd.DownMbps -gt 1) { $success += "Down: $($spd.DownMbps) Mbps / Up: $($spd.UpMbps) Mbps" }
        else { 
            $speedWarn = $spd.Method
            $problems += "Speedtest fehlgeschlagen oder zu langsam."
        }
        Check-Events
        $res = Check-Resource
        if ($res.Driver.Count -gt 0) {
            $problems += "Treiberprobleme gefunden!"
            $treiberDetails = $res.Driver | Select-Object -First 10 | ForEach-Object { "   - $($_.FriendlyName) [$($_.Status)] (ProblemCode: $($_.ProblemCode))" }
        }
        $cpuTop = $res.TopProc | Sort-Object CPU -Descending | Select-Object -First 3
        if ($cpuTop | Where-Object {$_.CPU -gt 50}) {
            $problems += "CPU-Last > 50% durch einzelne Prozesse."
            $cpuTopDetails = $cpuTop | ForEach-Object { "   - $($_.ProcessName) : $($_.CPU) CPU" }
        }
        $sec = Check-Security
        if (-not ($sec.Defender.AntivirusEnabled)) { $problems += "Antivirus nicht aktiv!" }
        if (-not ($sec.ICMP)) { $problems += "ICMP (Ping) nicht erlaubt durch Firewall!" }
        $summary = if ($problems) { "Probleme erkannt! Siehe oben. Bitte analysieren und Maßnahmen ergreifen." } else { "System OK – keine gravierenden Probleme erkannt." }
        Print-Report $vm $sys $disk $problems $success $summary $treiberDetails $cpuTopDetails $speedWarn
    }
    '2' { Run-SmartCheck }
	
}

