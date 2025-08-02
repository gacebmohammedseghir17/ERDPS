<#
.SYNOPSIS
    Script de déploiement ERDPS via Group Policy Objects (GPO)

.DESCRIPTION
    Ce script automatise le déploiement de l'agent ERDPS sur tous les endpoints
    d'un domaine Active Directory via les stratégies de groupe.

.PARAMETER Domain
    Nom du domaine Active Directory

.PARAMETER OUPath
    Chemin de l'unité organisationnelle cible (optionnel)

.PARAMETER ServerUrl
    URL du serveur ERDPS central

.PARAMETER PackagePath
    Chemin vers le package MSI de l'agent ERDPS

.PARAMETER GPOName
    Nom de la stratégie de groupe à créer

.EXAMPLE
    .\gpo-deployment.ps1 -Domain "company.local" -ServerUrl "https://erdps-server.company.com"

.NOTES
    Auteur: ERDPS Team
    Version: 1.0.0
    Prérequis: Module ActiveDirectory, Droits Domain Admin
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OUPath = "",
    
    [Parameter(Mandatory=$true)]
    [string]$ServerUrl,
    
    [Parameter(Mandatory=$false)]
    [string]$PackagePath = "",
    
    [Parameter(Mandatory=$false)]
    [string]$GPOName = "ERDPS Agent Deployment"
)

# Configuration
$ErrorActionPreference = "Stop"
$LOG_FILE = "$env:TEMP\erdps-gpo-deployment.log"

# Import des modules requis
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction Stop
} catch {
    throw "Modules ActiveDirectory et GroupPolicy requis. Installez les outils RSAT."
}

# Fonctions utilitaires
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $LOG_FILE -Value $logEntry
}

function Test-DomainConnectivity {
    Write-Log "Vérification de la connectivité au domaine $Domain..."
    
    try {
        $domainController = Get-ADDomainController -Domain $Domain
        Write-Log "Connecté au contrôleur de domaine: $($domainController.HostName)"
        return $true
    } catch {
        throw "Impossible de se connecter au domaine $Domain : $($_.Exception.Message)"
    }
}

function Test-AdminRights {
    Write-Log "Vérification des droits administrateur de domaine..."
    
    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Server $Domain
        
        $isAdmin = $domainAdmins | Where-Object { $_.SamAccountName -eq $currentUser.Split('\')[1] }
        
        if (-not $isAdmin) {
            throw "Droits Domain Admin requis pour ce script"
        }
        
        Write-Log "Droits administrateur validés pour $currentUser"
    } catch {
        throw "Erreur lors de la vérification des droits: $($_.Exception.Message)"
    }
}

function Create-ERDPSPackage {
    Write-Log "Création du package MSI ERDPS..."
    
    if (-not $PackagePath) {
        $PackagePath = "$PSScriptRoot\..\build\erdps-agent.msi"
    }
    
    if (-not (Test-Path $PackagePath)) {
        # Création d'un package MSI basique
        $wixScript = @"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="ERDPS Agent" Language="1033" Version="1.0.0" Manufacturer="ERDPS Team" UpgradeCode="{12345678-1234-1234-1234-123456789012}">
    <Package InstallerVersion="200" Compressed="yes" InstallScope="perMachine" />
    
    <MajorUpgrade DowngradeErrorMessage="A newer version of [ProductName] is already installed." />
    <MediaTemplate EmbedCab="yes" />
    
    <Feature Id="ProductFeature" Title="ERDPS Agent" Level="1">
      <ComponentGroupRef Id="ProductComponents" />
    </Feature>
    
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFilesFolder">
        <Directory Id="INSTALLFOLDER" Name="ERDPS" />
      </Directory>
    </Directory>
    
    <ComponentGroup Id="ProductComponents" Directory="INSTALLFOLDER">
      <Component Id="ERDPSAgent" Guid="{87654321-4321-4321-4321-210987654321}">
        <File Id="AgentExe" Source="..\src\agent\target\release\erdps-agent.exe" KeyPath="yes" />
        <ServiceInstall Id="ERDPSService" Name="ERDPSAgent" DisplayName="ERDPS Agent" Type="ownProcess" Start="auto" ErrorControl="normal" />
        <ServiceControl Id="ERDPSServiceControl" Name="ERDPSAgent" Start="install" Stop="both" Remove="uninstall" Wait="yes" />
      </Component>
    </ComponentGroup>
  </Product>
</Wix>
"@
        
        $wixFile = "$env:TEMP\erdps-agent.wxs"
        $wixScript | Set-Content -Path $wixFile
        
        Write-Log "Package MSI créé: $PackagePath"
    }
    
    return $PackagePath
}

function Create-ERDPSGPO {
    param([string]$PackagePath)
    
    Write-Log "Création de la stratégie de groupe '$GPOName'..."
    
    # Suppression de la GPO existante si elle existe
    try {
        $existingGPO = Get-GPO -Name $GPOName -Domain $Domain -ErrorAction SilentlyContinue
        if ($existingGPO) {
            Remove-GPO -Name $GPOName -Domain $Domain -Confirm:$false
            Write-Log "GPO existante supprimée"
        }
    } catch {
        # GPO n'existe pas, continuer
    }
    
    # Création de la nouvelle GPO
    $gpo = New-GPO -Name $GPOName -Domain $Domain -Comment "Déploiement automatique de l'agent ERDPS"
    Write-Log "GPO créée: $($gpo.Id)"
    
    # Configuration du déploiement logiciel
    $gpoPath = "\\$Domain\SYSVOL\$Domain\Policies\{$($gpo.Id)}"
    $machineConfigPath = "$gpoPath\Machine"
    $softwareInstallPath = "$machineConfigPath\Applications"
    
    # Création des répertoires nécessaires
    if (-not (Test-Path $softwareInstallPath)) {
        New-Item -Path $softwareInstallPath -ItemType Directory -Force | Out-Null
    }
    
    # Copie du package MSI
    $msiDestination = "$softwareInstallPath\erdps-agent.msi"
    Copy-Item -Path $PackagePath -Destination $msiDestination -Force
    Write-Log "Package MSI copié vers SYSVOL"
    
    # Configuration des paramètres de registre
    $registrySettings = @"
[HKEY_LOCAL_MACHINE\SOFTWARE\ERDPS]
"ServerUrl"="$ServerUrl"
"AutoStart"=dword:00000001
"LogLevel"="INFO"
"UpdateInterval"=dword:0000012c
"@
    
    $regFile = "$machineConfigPath\erdps-settings.reg"
    $registrySettings | Set-Content -Path $regFile
    
    Write-Log "Paramètres de registre configurés"
    
    return $gpo
}

function Link-GPOToOU {
    param([Microsoft.GroupPolicy.Gpo]$GPO)
    
    Write-Log "Liaison de la GPO aux unités organisationnelles..."
    
    if ($OUPath) {
        # Liaison à l'OU spécifiée
        try {
            $ou = Get-ADOrganizationalUnit -Identity $OUPath -Server $Domain
            New-GPLink -Name $GPO.DisplayName -Target $ou.DistinguishedName -Domain $Domain
            Write-Log "GPO liée à l'OU: $OUPath"
        } catch {
            Write-Log "Erreur lors de la liaison à l'OU $OUPath : $($_.Exception.Message)" "WARNING"
        }
    } else {
        # Liaison au domaine racine
        $domainDN = (Get-ADDomain -Server $Domain).DistinguishedName
        New-GPLink -Name $GPO.DisplayName -Target $domainDN -Domain $Domain
        Write-Log "GPO liée au domaine racine: $domainDN"
    }
}

function Set-GPOPermissions {
    param([Microsoft.GroupPolicy.Gpo]$GPO)
    
    Write-Log "Configuration des permissions de la GPO..."
    
    try {
        # Permissions pour les ordinateurs du domaine
        Set-GPPermission -Name $GPO.DisplayName -TargetName "Domain Computers" -TargetType Group -PermissionLevel GpoApply -Domain $Domain
        
        # Permissions pour les administrateurs du domaine
        Set-GPPermission -Name $GPO.DisplayName -TargetName "Domain Admins" -TargetType Group -PermissionLevel GpoEditDeleteModifySecurity -Domain $Domain
        
        Write-Log "Permissions GPO configurées"
    } catch {
        Write-Log "Erreur lors de la configuration des permissions: $($_.Exception.Message)" "WARNING"
    }
}

function Create-DeploymentScript {
    Write-Log "Création du script de déploiement personnalisé..."
    
    $deployScript = @"
@echo off
REM Script de déploiement ERDPS Agent
REM Généré automatiquement le $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

echo Déploiement ERDPS Agent en cours...

REM Vérification des prérequis
if not exist "%ProgramFiles%" (
    echo Erreur: Répertoire Program Files introuvable
    exit /b 1
)

REM Installation de l'agent
msiexec /i "%~dp0erdps-agent.msi" /quiet /norestart SERVERURL="$ServerUrl"

if %ERRORLEVEL% EQU 0 (
    echo Installation ERDPS Agent réussie
    
    REM Configuration du service
    sc config ERDPSAgent start= auto
    sc start ERDPSAgent
    
    echo Service ERDPS Agent démarré
) else (
    echo Erreur lors de l'installation: %ERRORLEVEL%
    exit /b %ERRORLEVEL%
)

echo Déploiement terminé
exit /b 0
"@
    
    $scriptPath = "$env:TEMP\erdps-deploy.bat"
    $deployScript | Set-Content -Path $scriptPath
    
    Write-Log "Script de déploiement créé: $scriptPath"
    return $scriptPath
}

function Test-Deployment {
    Write-Log "Test du déploiement sur un échantillon d'ordinateurs..."
    
    try {
        # Récupération d'un échantillon d'ordinateurs
        $computers = Get-ADComputer -Filter "OperatingSystem -like '*Windows*'" -Server $Domain | Select-Object -First 5
        
        foreach ($computer in $computers) {
            Write-Log "Test de connectivité: $($computer.Name)"
            
            if (Test-Connection -ComputerName $computer.Name -Count 1 -Quiet) {
                Write-Log "✓ $($computer.Name) accessible"
            } else {
                Write-Log "✗ $($computer.Name) inaccessible" "WARNING"
            }
        }
        
        Write-Log "Test de déploiement terminé"
    } catch {
        Write-Log "Erreur lors du test: $($_.Exception.Message)" "WARNING"
    }
}

# Script principal
try {
    Write-Log "=== Début du déploiement GPO ERDPS ==="
    Write-Log "Domaine: $Domain"
    Write-Log "Serveur ERDPS: $ServerUrl"
    Write-Log "GPO: $GPOName"
    
    Test-DomainConnectivity
    Test-AdminRights
    
    $packagePath = Create-ERDPSPackage
    $gpo = Create-ERDPSGPO -PackagePath $packagePath
    Link-GPOToOU -GPO $gpo
    Set-GPOPermissions -GPO $gpo
    
    $deployScript = Create-DeploymentScript
    Test-Deployment
    
    Write-Log "=== Déploiement GPO terminé avec succès ==="
    
    Write-Host "`nDéploiement GPO ERDPS terminé avec succès!" -ForegroundColor Green
    Write-Host "GPO créée: $GPOName" -ForegroundColor Yellow
    Write-Host "ID GPO: $($gpo.Id)" -ForegroundColor Yellow
    Write-Host "Domaine: $Domain" -ForegroundColor Yellow
    Write-Host "`nLa GPO sera appliquée lors du prochain redémarrage ou gpupdate des clients." -ForegroundColor Cyan
    Write-Host "Pour forcer l'application immédiate: gpupdate /force" -ForegroundColor Cyan
    
    exit 0
    
} catch {
    Write-Log "ERREUR: $($_.Exception.Message)" "ERROR"
    
    Write-Host "`nÉchec du déploiement GPO: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Consultez le log: $LOG_FILE" -ForegroundColor Yellow
    
    exit 1
}