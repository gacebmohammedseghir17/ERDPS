<#
.SYNOPSIS
    Script de simulation d'attaques ransomware pour tester ERDPS

.DESCRIPTION
    Ce script simule différents comportements de ransomware pour valider
    les capacités de détection et de réponse de l'agent ERDPS.
    ATTENTION: À utiliser uniquement en environnement de test!

.PARAMETER TestType
    Type de test à exécuter (FileEncryption, ProcessInjection, NetworkScan, RegistryModification, All)

.PARAMETER TestDirectory
    Répertoire de test pour les simulations (par défaut: C:\ERDPSTest)

.PARAMETER Duration
    Durée du test en secondes (par défaut: 60)

.PARAMETER Verbose
    Affichage détaillé des opérations

.EXAMPLE
    .\ransomware-simulation.ps1 -TestType FileEncryption -TestDirectory "C:\TestFolder"

.EXAMPLE
    .\ransomware-simulation.ps1 -TestType All -Duration 120 -Verbose

.NOTES
    Auteur: ERDPS Security Team
    Version: 1.0.0
    AVERTISSEMENT: Script de test uniquement - Ne pas utiliser en production!
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("FileEncryption", "ProcessInjection", "NetworkScan", "RegistryModification", "VolumeEncryption", "All")]
    [string]$TestType = "All",
    
    [Parameter(Mandatory=$false)]
    [string]$TestDirectory = "C:\ERDPSTest",
    
    [Parameter(Mandatory=$false)]
    [int]$Duration = 60,
    
    [Parameter(Mandatory=$false)]
    [switch]$Verbose
)

# Configuration
$ErrorActionPreference = "Continue"
$LOG_FILE = "$env:TEMP\erdps-simulation.log"
$TEST_FILES_COUNT = 100
$ENCRYPTION_KEY = "ERDPS_TEST_KEY_2024"

# Fonctions utilitaires
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [SIMULATION] $Message"
    
    if ($Verbose -or $Level -eq "ERROR") {
        Write-Host $logEntry -ForegroundColor $(if($Level -eq "ERROR") {"Red"} elseif($Level -eq "WARNING") {"Yellow"} else {"White"})
    }
    
    Add-Content -Path $LOG_FILE -Value $logEntry
}

function Test-ERDPSAgent {
    Write-Log "Vérification de l'agent ERDPS..."
    
    $service = Get-Service -Name "ERDPSAgent" -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Log "ATTENTION: Service ERDPS Agent non trouvé" "WARNING"
        return $false
    }
    
    if ($service.Status -ne "Running") {
        Write-Log "ATTENTION: Service ERDPS Agent non démarré" "WARNING"
        return $false
    }
    
    Write-Log "Agent ERDPS détecté et actif"
    return $true
}

function Initialize-TestEnvironment {
    Write-Log "Initialisation de l'environnement de test..."
    
    # Création du répertoire de test
    if (Test-Path $TestDirectory) {
        Remove-Item -Path $TestDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    New-Item -Path $TestDirectory -ItemType Directory -Force | Out-Null
    Write-Log "Répertoire de test créé: $TestDirectory"
    
    # Création de fichiers de test
    for ($i = 1; $i -le $TEST_FILES_COUNT; $i++) {
        $fileName = "test_file_$($i.ToString('000')).txt"
        $filePath = Join-Path $TestDirectory $fileName
        
        $content = @"
Fichier de test ERDPS #$i
Créé le: $(Get-Date)
Contenu: $(Get-Random -Minimum 1000 -Maximum 9999)
Taille: $([System.Text.Encoding]::UTF8.GetBytes((1..100 | ForEach-Object { Get-Random -Minimum 65 -Maximum 90 | ForEach-Object { [char]$_ } }) -join '').Length) bytes
"@
        
        $content | Set-Content -Path $filePath
    }
    
    Write-Log "$TEST_FILES_COUNT fichiers de test créés"
    
    # Création de sous-répertoires
    @("Documents", "Images", "Videos", "Backup") | ForEach-Object {
        $subDir = Join-Path $TestDirectory $_
        New-Item -Path $subDir -ItemType Directory -Force | Out-Null
        
        # Quelques fichiers dans chaque sous-répertoire
        1..10 | ForEach-Object {
            $subFile = Join-Path $subDir "$_-important.dat"
            "Données importantes $_" | Set-Content -Path $subFile
        }
    }
    
    Write-Log "Environnement de test initialisé"
}

function Simulate-FileEncryption {
    Write-Log "=== SIMULATION: Chiffrement de fichiers ==="
    
    $startTime = Get-Date
    $filesEncrypted = 0
    
    Get-ChildItem -Path $TestDirectory -Recurse -File | ForEach-Object {
        if ((Get-Date) -lt $startTime.AddSeconds($Duration)) {
            try {
                # Simulation de lecture du fichier
                $content = Get-Content -Path $_.FullName -Raw
                
                # Simulation de chiffrement (simple XOR pour le test)
                $encryptedContent = ""
                for ($i = 0; $i -lt $content.Length; $i++) {
                    $encryptedContent += [char]([byte]$content[$i] -bxor 0x42)
                }
                
                # Écriture du contenu "chiffré"
                $encryptedContent | Set-Content -Path $_.FullName
                
                # Renommage avec extension ransomware
                $newName = $_.FullName + ".ERDPS_ENCRYPTED"
                Rename-Item -Path $_.FullName -NewName $newName
                
                $filesEncrypted++
                
                if ($filesEncrypted % 10 -eq 0) {
                    Write-Log "Fichiers chiffrés: $filesEncrypted"
                }
                
                # Simulation de la vitesse d'un vrai ransomware
                Start-Sleep -Milliseconds (Get-Random -Minimum 50 -Maximum 200)
                
            } catch {
                Write-Log "Erreur lors du chiffrement de $($_.Name): $($_.Exception.Message)" "ERROR"
            }
        }
    }
    
    Write-Log "Simulation de chiffrement terminée: $filesEncrypted fichiers traités"
    
    # Création d'une note de rançon
    $ransomNote = @"
!!! ATTENTION - VOS FICHIERS ONT ÉTÉ CHIFFRÉS !!!

[SIMULATION ERDPS - CECI EST UN TEST]

Tous vos fichiers importants ont été chiffrés avec un algorithme militaire.
Pour récupérer vos données, vous devez payer une rançon de 1000 bitcoins.

Contact: test@erdps-simulation.local
ID Victime: ERDPS-TEST-$(Get-Date -Format 'yyyyMMdd-HHmmss')

Ce message est généré par le script de test ERDPS.
Aucun fichier n'a été réellement endommagé.

Date: $(Get-Date)
"@
    
    $ransomNote | Set-Content -Path "$TestDirectory\README_RANSOM.txt"
    Write-Log "Note de rançon créée"
}

function Simulate-ProcessInjection {
    Write-Log "=== SIMULATION: Injection de processus ==="
    
    try {
        # Simulation d'injection dans des processus système
        $targetProcesses = @("explorer", "winlogon", "services", "lsass")
        
        foreach ($processName in $targetProcesses) {
            $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
            
            foreach ($process in $processes) {
                Write-Log "Simulation d'injection dans le processus: $($process.Name) (PID: $($process.Id))"
                
                # Simulation d'ouverture de handle sur le processus
                try {
                    $handle = $process.Handle
                    Write-Log "Handle obtenu pour $($process.Name)"
                } catch {
                    Write-Log "Impossible d'obtenir le handle pour $($process.Name)" "WARNING"
                }
                
                # Simulation d'allocation mémoire
                Write-Log "Simulation d'allocation mémoire dans $($process.Name)"
                
                Start-Sleep -Milliseconds 500
            }
        }
        
        # Simulation de création de processus malveillant
        Write-Log "Simulation de création de processus malveillant"
        
        $maliciousScript = @"
@echo off
REM Processus malveillant simulé
echo Processus ERDPS Test en cours...
timeout /t 30 /nobreak > nul
echo Test terminé
"@
        
        $scriptPath = "$TestDirectory\malicious_process.bat"
        $maliciousScript | Set-Content -Path $scriptPath
        
        $process = Start-Process -FilePath $scriptPath -WindowStyle Hidden -PassThru
        Write-Log "Processus malveillant simulé créé (PID: $($process.Id))"
        
        Start-Sleep -Seconds 5
        
        if (-not $process.HasExited) {
            $process.Kill()
            Write-Log "Processus malveillant terminé"
        }
        
    } catch {
        Write-Log "Erreur lors de la simulation d'injection: $($_.Exception.Message)" "ERROR"
    }
}

function Simulate-NetworkScan {
    Write-Log "=== SIMULATION: Scan réseau ==="
    
    try {
        # Simulation de scan de ports
        $targetHosts = @("127.0.0.1", "192.168.1.1", "8.8.8.8")
        $commonPorts = @(21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 3389)
        
        foreach ($host in $targetHosts) {
            Write-Log "Scan réseau de l'hôte: $host"
            
            foreach ($port in $commonPorts) {
                try {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $connect = $tcpClient.BeginConnect($host, $port, $null, $null)
                    $wait = $connect.AsyncWaitHandle.WaitOne(100, $false)
                    
                    if ($wait) {
                        try {
                            $tcpClient.EndConnect($connect)
                            Write-Log "Port ouvert détecté: $host`:$port"
                        } catch {
                            # Port fermé
                        }
                    }
                    
                    $tcpClient.Close()
                } catch {
                    # Erreur de connexion
                }
            }
        }
        
        # Simulation de découverte réseau
        Write-Log "Simulation de découverte réseau"
        
        $networkRange = "192.168.1"
        1..10 | ForEach-Object {
            $ip = "$networkRange.$_"
            Write-Log "Ping de découverte: $ip"
            
            $ping = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue
            if ($ping) {
                Write-Log "Hôte actif détecté: $ip"
            }
        }
        
    } catch {
        Write-Log "Erreur lors du scan réseau: $($_.Exception.Message)" "ERROR"
    }
}

function Simulate-RegistryModification {
    Write-Log "=== SIMULATION: Modification du registre ==="
    
    try {
        # Clés de registre sensibles pour les tests
        $testKeys = @(
            "HKCU:\Software\ERDPSTest",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        )
        
        foreach ($keyPath in $testKeys) {
            Write-Log "Modification de la clé: $keyPath"
            
            if ($keyPath -like "*ERDPSTest*") {
                # Création d'une clé de test
                if (-not (Test-Path $keyPath)) {
                    New-Item -Path $keyPath -Force | Out-Null
                }
                
                # Ajout de valeurs suspectes
                Set-ItemProperty -Path $keyPath -Name "MaliciousValue" -Value "ERDPS_TEST_MALWARE"
                Set-ItemProperty -Path $keyPath -Name "InstallDate" -Value (Get-Date).ToString()
                Set-ItemProperty -Path $keyPath -Name "Version" -Value "1.0.0"
                
                Write-Log "Valeurs malveillantes ajoutées à $keyPath"
            }
            
            if ($keyPath -like "*Run*") {
                # Simulation d'ajout de persistance
                $maliciousCommand = "$TestDirectory\malicious_process.bat"
                
                Write-Log "Simulation d'ajout de persistance dans Run"
                # Note: On ne modifie pas réellement la clé Run pour éviter les problèmes
                Write-Log "[SIMULATION] Ajout de: ERDPSTestMalware = $maliciousCommand"
            }
        }
        
        # Simulation de modification des paramètres de sécurité
        Write-Log "Simulation de modification des paramètres de sécurité"
        
        $securityKey = "HKCU:\Software\ERDPSTest\Security"
        if (-not (Test-Path $securityKey)) {
            New-Item -Path $securityKey -Force | Out-Null
        }
        
        Set-ItemProperty -Path $securityKey -Name "DisableAntivirus" -Value 1
        Set-ItemProperty -Path $securityKey -Name "DisableFirewall" -Value 1
        Set-ItemProperty -Path $securityKey -Name "DisableUAC" -Value 1
        
        Write-Log "Paramètres de sécurité malveillants simulés"
        
    } catch {
        Write-Log "Erreur lors de la modification du registre: $($_.Exception.Message)" "ERROR"
    }
}

function Simulate-VolumeEncryption {
    Write-Log "=== SIMULATION: Chiffrement de volume ==="
    
    try {
        # Simulation d'énumération des volumes
        $volumes = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
        
        foreach ($volume in $volumes) {
            Write-Log "Volume détecté: $($volume.DeviceID) - Taille: $([math]::Round($volume.Size/1GB, 2)) GB"
            
            # Simulation de lecture du MBR/VBR
            Write-Log "Simulation de lecture du secteur de boot pour $($volume.DeviceID)"
            
            # Simulation d'écriture de signature ransomware
            Write-Log "[SIMULATION] Écriture de signature ransomware sur $($volume.DeviceID)"
        }
        
        # Simulation de modification de la table de partition
        Write-Log "Simulation de modification de la table de partition"
        
        # Simulation de chiffrement du MFT (Master File Table)
        Write-Log "Simulation de chiffrement du MFT"
        
    } catch {
        Write-Log "Erreur lors de la simulation de chiffrement de volume: $($_.Exception.Message)" "ERROR"
    }
}

function Cleanup-TestEnvironment {
    Write-Log "Nettoyage de l'environnement de test..."
    
    try {
        # Suppression du répertoire de test
        if (Test-Path $TestDirectory) {
            Remove-Item -Path $TestDirectory -Recurse -Force
            Write-Log "Répertoire de test supprimé"
        }
        
        # Nettoyage du registre
        $testKey = "HKCU:\Software\ERDPSTest"
        if (Test-Path $testKey) {
            Remove-Item -Path $testKey -Recurse -Force
            Write-Log "Clés de registre de test supprimées"
        }
        
        Write-Log "Nettoyage terminé"
        
    } catch {
        Write-Log "Erreur lors du nettoyage: $($_.Exception.Message)" "ERROR"
    }
}

function Show-TestResults {
    Write-Log "=== RÉSULTATS DU TEST ==="
    
    Write-Host "`n" -NoNewline
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                    ERDPS SIMULATION TERMINÉE                ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Type de test: $($TestType.PadRight(47)) ║" -ForegroundColor White
    Write-Host "║ Durée: $($Duration.ToString().PadRight(52)) ║" -ForegroundColor White
    Write-Host "║ Répertoire: $($TestDirectory.PadRight(45)) ║" -ForegroundColor White
    Write-Host "║ Log: $($LOG_FILE.PadRight(54)) ║" -ForegroundColor White
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Vérifiez les alertes ERDPS pour valider la détection        ║" -ForegroundColor Yellow
    Write-Host "║ Consultez le dashboard pour les métriques de performance    ║" -ForegroundColor Yellow
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

# Script principal
try {
    Write-Host "" 
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║                  ERDPS RANSOMWARE SIMULATION                ║" -ForegroundColor Red
    Write-Host "║                                                              ║" -ForegroundColor Red
    Write-Host "║  ATTENTION: Script de test uniquement!                      ║" -ForegroundColor Yellow
    Write-Host "║  Ne pas utiliser en environnement de production!            ║" -ForegroundColor Yellow
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""
    
    Write-Log "=== DÉBUT DE LA SIMULATION ERDPS ==="
    Write-Log "Type de test: $TestType"
    Write-Log "Durée: $Duration secondes"
    Write-Log "Répertoire: $TestDirectory"
    
    # Vérification de l'agent ERDPS
    $agentRunning = Test-ERDPSAgent
    
    # Initialisation
    Initialize-TestEnvironment
    
    # Exécution des tests selon le type
    switch ($TestType) {
        "FileEncryption" { Simulate-FileEncryption }
        "ProcessInjection" { Simulate-ProcessInjection }
        "NetworkScan" { Simulate-NetworkScan }
        "RegistryModification" { Simulate-RegistryModification }
        "VolumeEncryption" { Simulate-VolumeEncryption }
        "All" {
            Simulate-FileEncryption
            Start-Sleep -Seconds 5
            Simulate-ProcessInjection
            Start-Sleep -Seconds 5
            Simulate-NetworkScan
            Start-Sleep -Seconds 5
            Simulate-RegistryModification
            Start-Sleep -Seconds 5
            Simulate-VolumeEncryption
        }
    }
    
    # Attente pour permettre à ERDPS de détecter
    Write-Log "Attente de $Duration secondes pour la détection ERDPS..."
    Start-Sleep -Seconds $Duration
    
    # Nettoyage
    Cleanup-TestEnvironment
    
    Write-Log "=== SIMULATION TERMINÉE ==="
    Show-TestResults
    
    exit 0
    
} catch {
    Write-Log "ERREUR CRITIQUE: $($_.Exception.Message)" "ERROR"
    
    Write-Host "`nErreur lors de la simulation: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Consultez le log: $LOG_FILE" -ForegroundColor Yellow
    
    # Nettoyage en cas d'erreur
    Cleanup-TestEnvironment
    
    exit 1
}