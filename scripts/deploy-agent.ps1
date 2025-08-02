<#
.SYNOPSIS
    Script de déploiement automatique de l'agent ERDPS

.DESCRIPTION
    Ce script automatise l'installation et la configuration de l'agent ERDPS
    sur les endpoints Windows d'entreprise.

.PARAMETER ServerUrl
    URL du serveur ERDPS central

.PARAMETER InstallPath
    Chemin d'installation de l'agent (par défaut: C:\Program Files\ERDPS)

.PARAMETER AgentConfig
    Fichier de configuration personnalisé pour l'agent

.PARAMETER Silent
    Installation silencieuse sans interaction utilisateur

.EXAMPLE
    .\deploy-agent.ps1 -ServerUrl "https://erdps-server.company.com" -InstallPath "C:\Program Files\ERDPS"

.NOTES
    Auteur: ERDPS Team
    Version: 1.0.0
    Dernière mise à jour: 2024
    Prérequis: PowerShell 5.1+, Droits administrateur
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ServerUrl,
    
    [Parameter(Mandatory=$false)]
    [string]$InstallPath = "C:\Program Files\ERDPS",
    
    [Parameter(Mandatory=$false)]
    [string]$AgentConfig = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$Silent
)

# Configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Constantes
$ERDPS_SERVICE_NAME = "ERDPSAgent"
$ERDPS_AGENT_EXE = "erdps-agent.exe"
$ERDPS_CONFIG_FILE = "agent-config.json"
$LOG_FILE = "$env:TEMP\erdps-deployment.log"

# Fonctions utilitaires
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $LOG_FILE -Value $logEntry
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Prerequisites {
    Write-Log "Vérification des prérequis..."
    
    # Vérification des droits administrateur
    if (-not (Test-Administrator)) {
        throw "Ce script nécessite des droits administrateur"
    }
    
    # Vérification de la version Windows
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -lt 10) {
        throw "Windows 10 ou supérieur requis"
    }
    
    # Vérification de PowerShell
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        throw "PowerShell 5.1 ou supérieur requis"
    }
    
    # Vérification de .NET Framework
    $dotNetVersion = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\" -Name Release -ErrorAction SilentlyContinue
    if ($dotNetVersion.Release -lt 461808) {
        throw ".NET Framework 4.7.2 ou supérieur requis"
    }
    
    Write-Log "Prérequis validés avec succès"
}

function Stop-ERDPSService {
    Write-Log "Arrêt du service ERDPS existant..."
    
    $service = Get-Service -Name $ERDPS_SERVICE_NAME -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq "Running") {
            Stop-Service -Name $ERDPS_SERVICE_NAME -Force
            Write-Log "Service ERDPS arrêté"
        }
    }
}

function Install-ERDPSAgent {
    Write-Log "Installation de l'agent ERDPS..."
    
    # Création du répertoire d'installation
    if (-not (Test-Path $InstallPath)) {
        New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
        Write-Log "Répertoire d'installation créé: $InstallPath"
    }
    
    # Copie des fichiers de l'agent
    $agentSource = Join-Path $PSScriptRoot "..\src\agent\target\release\$ERDPS_AGENT_EXE"
    $agentDest = Join-Path $InstallPath $ERDPS_AGENT_EXE
    
    if (Test-Path $agentSource) {
        Copy-Item -Path $agentSource -Destination $agentDest -Force
        Write-Log "Agent copié vers $agentDest"
    } else {
        throw "Fichier agent introuvable: $agentSource"
    }
    
    # Configuration de l'agent
    $configPath = Join-Path $InstallPath $ERDPS_CONFIG_FILE
    $config = @{
        server_url = $ServerUrl
        agent_id = [System.Guid]::NewGuid().ToString()
        log_level = "INFO"
        update_interval = 300
        heartbeat_interval = 60
        encryption_enabled = $true
        certificate_path = "$InstallPath\certs"
    }
    
    if ($AgentConfig -and (Test-Path $AgentConfig)) {
        $customConfig = Get-Content $AgentConfig | ConvertFrom-Json
        foreach ($key in $customConfig.PSObject.Properties.Name) {
            $config[$key] = $customConfig.$key
        }
    }
    
    $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath
    Write-Log "Configuration sauvegardée: $configPath"
}

function Install-ERDPSService {
    Write-Log "Installation du service Windows..."
    
    $servicePath = Join-Path $InstallPath $ERDPS_AGENT_EXE
    $serviceDescription = "ERDPS Enterprise Ransomware Detection and Protection Agent"
    
    # Suppression du service existant
    $existingService = Get-Service -Name $ERDPS_SERVICE_NAME -ErrorAction SilentlyContinue
    if ($existingService) {
        Stop-Service -Name $ERDPS_SERVICE_NAME -Force -ErrorAction SilentlyContinue
        & sc.exe delete $ERDPS_SERVICE_NAME
        Start-Sleep -Seconds 2
    }
    
    # Création du nouveau service
    & sc.exe create $ERDPS_SERVICE_NAME binPath= "\"$servicePath\" --service" DisplayName= "ERDPS Agent" description= $serviceDescription start= auto
    
    if ($LASTEXITCODE -eq 0) {
        Write-Log "Service ERDPS créé avec succès"
        
        # Configuration des permissions du service
        & sc.exe config $ERDPS_SERVICE_NAME obj= "LocalSystem"
        & sc.exe failure $ERDPS_SERVICE_NAME reset= 86400 actions= restart/5000/restart/10000/restart/30000
        
        # Démarrage du service
        Start-Service -Name $ERDPS_SERVICE_NAME
        Write-Log "Service ERDPS démarré"
    } else {
        throw "Échec de la création du service ERDPS"
    }
}

function Set-FirewallRules {
    Write-Log "Configuration des règles de pare-feu..."
    
    # Règle pour la communication sortante vers le serveur
    $ruleName = "ERDPS Agent Outbound"
    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    
    if ($existingRule) {
        Remove-NetFirewallRule -DisplayName $ruleName
    }
    
    New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Protocol TCP -LocalPort Any -RemotePort 443,8443 -Action Allow -Profile Any
    Write-Log "Règles de pare-feu configurées"
}

function Test-Installation {
    Write-Log "Vérification de l'installation..."
    
    # Vérification du service
    $service = Get-Service -Name $ERDPS_SERVICE_NAME -ErrorAction SilentlyContinue
    if (-not $service -or $service.Status -ne "Running") {
        throw "Le service ERDPS n'est pas en cours d'exécution"
    }
    
    # Vérification des fichiers
    $agentPath = Join-Path $InstallPath $ERDPS_AGENT_EXE
    $configPath = Join-Path $InstallPath $ERDPS_CONFIG_FILE
    
    if (-not (Test-Path $agentPath)) {
        throw "Fichier agent manquant: $agentPath"
    }
    
    if (-not (Test-Path $configPath)) {
        throw "Fichier de configuration manquant: $configPath"
    }
    
    Write-Log "Installation vérifiée avec succès"
}

# Script principal
try {
    Write-Log "=== Début du déploiement ERDPS Agent ==="
    Write-Log "Serveur: $ServerUrl"
    Write-Log "Chemin d'installation: $InstallPath"
    
    Test-Prerequisites
    Stop-ERDPSService
    Install-ERDPSAgent
    Install-ERDPSService
    Set-FirewallRules
    Test-Installation
    
    Write-Log "=== Déploiement terminé avec succès ==="
    
    if (-not $Silent) {
        Write-Host "`nDéploiement ERDPS Agent terminé avec succès!" -ForegroundColor Green
        Write-Host "Service: $ERDPS_SERVICE_NAME" -ForegroundColor Yellow
        Write-Host "Chemin: $InstallPath" -ForegroundColor Yellow
        Write-Host "Log: $LOG_FILE" -ForegroundColor Yellow
    }
    
    exit 0
    
} catch {
    Write-Log "ERREUR: $($_.Exception.Message)" "ERROR"
    
    if (-not $Silent) {
        Write-Host "`nÉchec du déploiement: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Consultez le log: $LOG_FILE" -ForegroundColor Yellow
    }
    
    exit 1
}