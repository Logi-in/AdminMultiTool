# Admin-Elevation Block 
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $PSExe = $PSVersionTable.PSVersion.Major -gt 5 ? 'pwsh.exe' : 'powershell.exe'
    $args = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Start-Process $PSExe -ArgumentList $args -Verb RunAs
    exit
}



# ===================================================================
#    ######## FISI MULTI-TOOL ########
#      Komplett-Skript mit Kommentaren
# ===================================================================

# ========== Farbige Ausgabe-Funktionen ==========
function Write-Ok($msg)      { Write-Host $msg -ForegroundColor Green }
function Write-Problem($msg) { Write-Host $msg -ForegroundColor Red }
function Write-Hint($msg)    { Write-Host $msg -ForegroundColor Yellow }
function Write-Section($msg) { Write-Host "`n==== $msg ====" -ForegroundColor Cyan }
#Hilfsfuntion
function Test-PortOpen {
    param(
        [string]$ip,
        [int]$port = 9100,
        [int]$timeout = 1000
    )
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($ip, $port, $null, $null)
        $success = $iar.AsyncWaitHandle.WaitOne($timeout, $false)
        if ($success -and $client.Connected) {
            $client.EndConnect($iar)
            $client.Close()
            return $true
        } else {
            $client.Close()
            return $false
        }
    } catch { return $false }
}

# ===================================================================
#   Fehlercode-Datenbank (vollständig, nach deinem Vorbild)
# ===================================================================
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
    # ... bei Bedarf erweiterbar ...
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

# ===================================================================
#   Funktionsblöcke: Checks (System, Netzwerk, Ressourcen, usw.)
# ===================================================================
function Check-VM {
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
    return @{
        Disks = $list
        Phys = @()
        SMART = $null
    }
}

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

# Speedcheck
function Ensure-SpeedtestCLI {
    $speedtestCmd = Get-Command speedtest -ErrorAction SilentlyContinue
    if ($speedtestCmd) {
        Write-Host "[OK] Speedtest-CLI gefunden: $($speedtestCmd.Source)" -ForegroundColor Green
        return $speedtestCmd.Source
    }
    Write-Hint "[INFO] Speedtest-CLI nicht gefunden, versuche Download von Ookla..."
    $tempDir = "$env:TEMP\speedtestcli_temp"
    $speedtestExe = "$tempDir\speedtest.exe"
    $speedtestExeAlt = "$tempDir\win64\speedtest.exe"
    if (!(Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir | Out-Null }
    $url = "https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-win64.zip"
    $zipFile = "$tempDir\speedtest.zip"
    try {
        Write-Hint "[INFO] Lade $url herunter..."
        Invoke-WebRequest -Uri $url -OutFile $zipFile -UseBasicParsing
        Write-Host "[INFO] Download erfolgreich, entpacke..." -ForegroundColor Yellow
        Expand-Archive $zipFile -DestinationPath $tempDir -Force
        Remove-Item $zipFile -Force
        if (Test-Path $speedtestExe) {
            Write-Host "[OK] Speedtest-CLI bereitgestellt: $speedtestExe" -ForegroundColor Green
            return $speedtestExe
        } elseif (Test-Path $speedtestExeAlt) {
            Write-Host "[OK] Speedtest-CLI (im Unterordner) bereitgestellt: $speedtestExeAlt" -ForegroundColor Green
            return $speedtestExeAlt
        } else {
            Write-Problem "Entpacken fehlgeschlagen – speedtest.exe nicht gefunden!"
            Write-Host "[DEBUG] Gesucht in: $speedtestExe und $speedtestExeAlt"
            return $null
        }
    } catch {
        Write-Problem "Download/Entpacken der Speedtest-CLI fehlgeschlagen: $($_.Exception.Message)"
        Write-Host "[DEBUG] Download/Entpacken Fehler aufgetreten!"
        return $null
    }
}
function Check-Speed {
    $speedtestPath = Ensure-SpeedtestCLI
    if ($speedtestPath) {
        Write-Host "[INFO] Starte Speedtest unter: $speedtestPath" -ForegroundColor Cyan
        $out = & $speedtestPath --format=json --accept-license --accept-gdpr 2>$null
        Write-Host "[DEBUG] Speedtest-CLI Returncode: $LASTEXITCODE"
        Write-Host "[DEBUG] Speedtest-CLI Output: $out"
        if ($LASTEXITCODE -eq 0 -and $out) {
            $j = $out | ConvertFrom-Json
            return [pscustomobject]@{
                Method   = 'Ookla'
                PingMs   = [math]::Round($j.ping.latency,1)
                DownMbps = [math]::Round($j.download.bandwidth*8/1MB,1)
                UpMbps   = [math]::Round($j.upload.bandwidth*8/1MB,1)
                Server   = $j.server.name
            }
        } else {
            Write-Problem "Speedtest-CLI lief, aber keine sinnvolle Rückgabe erhalten."
            return [pscustomobject]@{ Method='None'; PingMs=$null; DownMbps=$null; UpMbps=$null; Server='n/a' }
        }
    } else {
        Write-Problem "Speedtest konnte nicht durchgeführt werden (CLI nicht bereitgestellt)."
        return [pscustomobject]@{ Method='None'; PingMs=$null; DownMbps=$null; UpMbps=$null; Server='n/a' }
    }
}

function Check-Resource {
    $proc = Get-Process | Sort-Object CPU -Descending | Select -First 10
    $drv = Get-PnpDevice | Where-Object {$_.Status -ne 'OK'} | Select FriendlyName, Status, ProblemCode
    [pscustomobject]@{ TopProc = $proc; Driver = $drv }
}

function Check-Security {
    $def = $null
    try { $def = Get-MpComputerStatus -ErrorAction SilentlyContinue } catch {}
    $icmp = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*ICMPv4-In*" -and $_.Enabled -eq "True" }
    [pscustomobject]@{ Defender = $def; ICMP = $icmp }
}

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
    if ($sys) {
        Write-Host "Systeminformationen:"
        Write-Host " Hostname: $($sys.ComputerName)"
        Write-Host " Betriebssystem: $($sys.OS)"
        Write-Host " CPU: $($sys.CPU)"
        Write-Host " RAM: $($sys.MemoryGB) GB"
        Write-Host " Virtuell: $(if ($vm.IsVirtual) {"Ja, $($vm.Model)"} else {"Nein"})"
        Print-DiskSmartStat $disk
    }
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

function Run-FullCheck {
    Write-Section "Starte Full Check..."

    Write-Host "1. Prüfe Virtualisierungsstatus..."
    $vm = Check-VM

    Write-Host "2. Lese Systeminformationen..."
    $sys = Check-SystemInfo

    Write-Host "3. Überprüfe Festplatten und SMART..."
    $disk = Check-Disks

    $problems = @()
    $success  = @()
    $treiberDetails = @()
    $cpuTopDetails  = @()
    $speedWarn      = $null

    Write-Host "4. Netzwerkprüfung (Ping und Ports)..."
    $net = Check-Network
    foreach ($p in $net.Ping) {
        if ($p.Reachable) { $success += "Ping zu $($p.Target) OK." } else { $problems += "Ping zu $($p.Target) FEHLER!" }
    }
    foreach ($t in $net.Port) {
        if ($t.TcpOpen) { $success += "Port $($t.Port) (Gateway) offen." } else { $problems += "Port $($t.Port) nicht offen!" }
    }

    Write-Host "5. Führe Speedtest aus..."
    $spd = Check-Speed

    if ($spd.Method -eq "Ookla" -and $spd.DownMbps -gt 0) {
    $success += "Down: $($spd.DownMbps) Mbps / Up: $($spd.UpMbps) Mbps"
    } elseif ($spd.Method -eq "None") {
    $problems += "Kein Speedtest-Tool vorhanden. Automatischer Download/Run war nicht möglich."
    $speedWarn = $spd.Method
    } else {
    $problems += "Speedtest fehlgeschlagen oder zu langsam."
    $speedWarn = $spd.Method
    }

    Write-Host "6. Analysiere System-Events (Eventlog)..."
    Check-Events

    Write-Host "7. Prüfe Prozesse und Treiber..."
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

    Write-Host "8. Sicherheits-Checks (Antivirus/Firewall)..."
    $sec = Check-Security
    if (-not ($sec.Defender.AntivirusEnabled)) { $problems += "Antivirus nicht aktiv!" }
    if (-not ($sec.ICMP)) { $problems += "ICMP (Ping) nicht erlaubt durch Firewall!" }

    $summary = if ($problems) { "Probleme erkannt! Siehe oben. Bitte analysieren und Maßnahmen ergreifen." } else { "System OK – keine gravierenden Probleme erkannt." }
    Print-Report $vm $sys $disk $problems $success $summary $treiberDetails $cpuTopDetails $speedWarn
}

function Run-SmartCheck {
    Write-Section "SMART CHECK (adaptiv)"
    Write-Host "1. Systeminfo einlesen..."
    $sys = Check-SystemInfo

    $problems = @()
    $success  = @()
    $treiberDetails = @()
    $cpuTopDetails  = @()
    $speedWarn      = $null

    Write-Host "2. Netzwerk-Quicktest: 3x Ping auf 8.8.8.8..."
    $presult = cmd /c "ping -n 3 8.8.8.8"
    if ($presult -match "TTL=") {
        $success += "Ping zu 8.8.8.8 OK."
    } else {
        $problems += "Ping zu 8.8.8.8 fehlgeschlagen!"
    }

    Write-Host "3. System-Events (letzte 1h) analysieren..."
    $since = (Get-Date).AddHours(-1)
    $ev = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$since} | 
          Where-Object { $_.LevelDisplayName -in @("Error","Warning") }
    if ($ev.Count -gt 0) {
        $problems += "Fehlerhafte System-Events (letzte Stunde) erkannt:"
        foreach ($event in $ev | Select-Object -First 5) {
            $problems += "[$($event.TimeCreated)] $($event.ProviderName): $($event.Message.Substring(0,[math]::Min(80,$event.Message.Length)))"
        }
    } else {
        $success += "Keine kritischen System-Events in letzter Stunde."
    }

    Write-Host "4. Sicherheitsstatus prüfen..."
    $sec = Check-Security
    if (-not ($sec.Defender.AntivirusEnabled)) { $problems += "Antivirus nicht aktiv!" }
    if (-not ($sec.ICMP)) { $problems += "ICMP (Ping) nicht erlaubt durch Firewall!" }
    if ($sec.Defender.AntivirusEnabled) { $success += "Windows Defender ist aktiv." }

    $summary = if ($problems) { "Probleme erkannt! Siehe oben. Bitte analysieren." } else { "System OK – keine gravierenden Probleme erkannt." }

    Print-Report $null $sys $null $problems $success $summary $treiberDetails $cpuTopDetails $speedWarn
}

function Find-And-Install-Printer {
    Write-Section "Starte Drucker-Suche"

    # 1. Gateway suchen und anzeigen
    Write-Host "==> Suche Gateway..."
    $gw = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop)
    if (-not $gw) { Write-Problem "Kein Gateway gefunden."; return }
    Write-Host "Gateway gefunden: $gw"

    # 2. Subnetz erkennen und anzeigen
    if ($gw -match '^(\d+\.\d+\.\d+)\.') {
        $subnet = $Matches[1]
        Write-Host "Subnetz erkannt: $subnet"
    } else {
        Write-Problem "Subnetz nicht erkannt."; return
    }

    # 3. Suche Drucker per echtem Portscan (Port 9100, 1s Timeout pro Host)
	Write-Host "Starte Suche nach Druckern im Bereich $subnet.1-254 (Port 9100, Timeout 1s)..."
	$found = @()
	for ($i=1; $i -le 254; $i++) {
    $ip = "$subnet.$i"
    Write-Host -NoNewline ("`rScanne $ip...".PadRight(40))
    $tcp = Test-PortOpen -ip $ip -port 9100 -timeout 500
    if ($tcp) {
        $dns = ""
        try {
            $dns = [System.Net.Dns]::GetHostEntry($ip).HostName
        } catch {
            $dns = $ip
        }
        $name = if ($dns -ne "" -and $dns -ne $ip) { $dns } else { $ip }
        $found += [pscustomobject]@{ Nummer=$found.Count+1; IP=$ip; Name=$name }
        Write-Host ("`rGefunden: $ip $name".PadRight(40))
    }
}

    Write-Host "`nSuche abgeschlossen."
    if ($found.Count -eq 0) {
        Write-Hint "Keine Drucker im Netz gefunden (Port 9100 offen)."
        return
    }

    # 4. Liste alle gefundenen Drucker mit Namen
    Write-Host "Gefundene Drucker:"
    foreach ($p in $found) {
        Write-Host ("{0}. {1}   ({2})" -f $p.Nummer, $p.IP, $p.Name)
    }

    # 5. Abfrage, welcher Drucker installiert werden soll
    $sel = Read-Host "Nummer des zu installierenden Druckers eingeben (oder Enter zum Abbruch)"
    if (-not $sel -or -not ($sel -match '^\d+$') -or [int]$sel -lt 1 -or [int]$sel -gt $found.Count) {
        Write-Hint "Abbruch oder ungültige Auswahl."; return
    }
    $dr = $found[[int]$sel-1]

    # 6. Optional Namensänderung
    $name = Read-Host "Name für den Drucker (Enter für '$($dr.Name)')"
    if (-not $name) { $name = $dr.Name }

    # 7. Treiber installieren (Generic / Text Only)
    $port = "IP_$($dr.IP)"
    Write-Host "Erstelle Druckerport: $port"
    if (-not (Get-PrinterPort -Name $port -ErrorAction SilentlyContinue)) {
        Add-PrinterPort -Name $port -PrinterHostAddress $dr.IP
    }

    $driver = "Generic / Text Only"
    if (-not (Get-PrinterDriver -Name $driver -ErrorAction SilentlyContinue)) {
        Write-Hint "Treiber '$driver' nicht gefunden, nutze Windows-Default."
        $driver = (Get-PrinterDriver | Select-Object -First 1).Name
    }

    Write-Host "Installiere Drucker '$name' mit Treiber '$driver' an Port '$port'..."
    try {
        Add-Printer -Name $name -DriverName $driver -PortName $port -ErrorAction Stop
        Write-Ok "Drucker erfolgreich installiert: $name ($dr.IP)"
    } catch {
        Write-Problem "Fehler bei der Druckerinstallation: $_"
        return
    }

    # 8. Abschlussmeldung
    Write-Host "`nFertig. Drucker '$name' ist einsatzbereit."
}


# ===================================================================
#    ==== MENÜ + AUSWAHL ====
# ===================================================================
while ($true) {
    Write-Host "`n######## FISI MULTI-TOOL ########" -ForegroundColor Magenta
    Write-Host "1. Full Check (alles prüfen)"
    Write-Host "2. Smart Check (Netzwerk & Logs, schnell)"
    Write-Host "3. Drucker suchen und installieren"
    Write-Host "0. Exit"

    $choice = Read-Host "Auswahl"
    Write-Host "`n[INFO] Initialisiere Prüfung, bitte warten..." -ForegroundColor Yellow
    Start-Sleep -Milliseconds 300

    switch ($choice) {
        '1' { Run-FullCheck }
        '2' { Run-SmartCheck }
        '3' { Find-And-Install-Printer }
        '0' { break }   # verlässt die Schleife, Skript ist zu Ende
        default { Write-Hint "Ungültige Auswahl!" }
    }
}



