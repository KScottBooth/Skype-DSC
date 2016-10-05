<#

#>
Param(
    #$SiteCode            = "XYZ-",
    $NodeName            = "hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh",                            # Enter the GUID of the Skype Server as the var
    $ComputerName        = "skype01",                                                         # The Name the then new Skype/Lync Server being added to the Enterprise Pool
    $IP                  = "192.168.0.11",                                                    # Enter the IPv4 Address of the Skype/Lync Server
    $NetBIOSName         = "lab",                                                             # NetBIOS Name of the Domain Skype/Lync will reside
    $DomainName          = $NetBIOSName  + ".com",                                            # FQDN of the the Domain Skype/Lync will reside 
    $ConfigFile          = "C:\Program Files\WindowsPowerShell\DscService\Configuration",     # The directory that you would like the Mof/metamof files created.  Default location depicted
    $AdminAccount        = "InstallAdmin",                                                    # Account that has administrative access to the local Server AND CSAdministrator,RTCUniversalServerAdmins
    $AdminPassword       = ("!@#$Password1234" | ConvertTo-SecureString -AsPlainText -Force), # Administrator Password. NOTE - is here for TESTING purposed ONLY, Should be passed in fron a secure source 
    $DestinationPath     = "C:\Windows\Temp",                                                 # Local directory where you want the Skype/Lync Source files to reside 
    $Uri                 = "HTTP://dscServer.lab.com:8080/",                                  # URI of you DSC Server
    $SXSZip              = "Sxs.Zip",                                                         # Zip file containing the Windows \SXS file (used to install .NET 3.5)
    $UcISO               = "UcISO.Zip",                                                       # Zip file containing the Skype/Lync ISO files (not the image itself)
    $UCTools             = "UCTools.Zip",                                                     # Zip file containing Silverlight.exe and any resource kit like tools
    $UCPool              = "UCPool1",                                                         # Name of the Skype/Lync Pool the FE Server will belong
    $UCSourcePath        = $DestinationPath + "\UC\Setup\amd64",                              # Local server path to the Unified Communications (UC) source files.  Either Skype/Lync
    $UCToolsSourcePath   = $DestinationPath + "\UCTools\",                                    # The working directory destination for the UC Tools
    $Product             = "Skype",                                         # or "Lync"
    #Cert Params
    $UCCertFriendlyName    = "Skype 2015 Core Certificate",                 # A unique ,meaingful name - used to check if lync certs have been issued
    $OAuthCertFriendlyName = "Skype 2015 OAuth Token",                      # A unique ,meaingful name - used to check if lync certs have been issued
    $CATemplate            = "WebServer",                                   # Name o fhte Web template for UC Certificate requests. NOTE: Use the Template Name and NOT the template Display Name

    $DomainCred          = (New-Object -TypeName System.Management.automation.PSCredential -ArgumentList (($NetBIOSName + "\" + $AdminAccount),$Adminpassword))
  )

##### Error Variables #####
$Errorstate   = 0
$ErrorMessage = ""
$Trace        = ""
$Error.Clear

$ConfigData = @{ 
    AllNodes = @(
        @{ 
            Role                = "UCFEConfig"
            NodeName            = $NodeName            
            Computername        = $ComputerName
            IP                  = $IP 
            NetBIOSName         = $NetBIOSName
            DomainName          = $DomainName 
            ComputerFqdn        = $ComputerName + "." + $DomainName
            Account             = $AdminAccount            
            Password            = $AdminPassword 
            DestinationPath     = $DestinationPath
            Uri                 = $Uri
            SXSZip              = $SXSZip              
            UcISO               = $UcISO
            UCTools             = $UCTools 
            UCPool              = $UCPool
            Product             = $Product
            UCSourcePath        = $UCSourcePath
            UCToolsSourcePath   = $UCToolsSourcePath
            UpdateEnabled       = $false 
            ErrorReporting      = $true
            CATemplate          = $CATemplate           
            Credential          = $DomainCred
            PSDscAllowPlainTextPassword = $true       # remove once credentials are in place
            PSDscAllowDomainUser = $true
	        
          # PchatFeatures        = @("MSMQ","MSMQ-Directory")          # Used to load Persistent Chat Pre-requisites on a stand alone Server
          # Add-WindowsFeature NET-Framework-Core, RSAT-ADDS, Windows-Identity-Foundation, Web-Server, Web-Static-Content, Web-Default-Doc, Web-Http-Errors, Web-Dir-Browsing, Web-Asp-Net, Web-Net-Ext, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Http-Logging, Web-Log-Libraries, Web-Request-Monitor, Web-Http-Tracing, Web-Basic-Auth, Web-Windows-Auth, Web-Client-Auth, Web-Filtering, Web-Stat-Compression, Web-Dyn-Compression, NET-WCF-HTTP-Activation45, Web-Asp-Net45, Web-Mgmt-Tools, Web-Scripting-Tools, Web-Mgmt-Compat, Server-Media-Foundation, BITS 
         }
    )
}

Configuration UCFEConfig {
    Import-DscResource -Modulename @{ModuleName="xComputerManagement";ModuleVersion="1.4.0.0"}           # If these modules show up with a red underline in Powershell ISE
    Import-DscResource -Modulename @{ModuleName="cLync2013";ModuleVersion="1.0"}                         # it's because you don't have them available on your server
    #Import-DscResource -Modulename cLync2013
    Import-DscResource -Modulename @{ModuleName="PSDesiredStateConfiguration";ModuleVersion="1.1"}
    Import-DscResource -Modulename @{ModuleName="xActiveDirectory";ModuleVersion="2.9.0.0"}
    Import-DscResource -Modulename @{ModuleName="cDns";ModuleVersion="1.0"}
    Import-DscResource -Modulename @{ModuleName="xDnsServer";ModuleVersion="1.7.0.0"}
    Import-DscResource -Modulename @{ModuleName="xPSDesiredStateConfiguration";ModuleVersion="3.7.0.0"}
    Import-DscResource -ModuleName @{ModuleName="cCertificates";ModuleVersion="1.0"}
    
    Node $AllNodes.Where{$_.Role -eq "UCFEConfig"}.Nodename {
        
        if ($Node.Product -match "Skype"){
            $UCWindowsFeatures  = @("Web-Server","Web-Static-Content","Web-Default-Doc","Web-Http-Errors","Web-Asp-Net","Web-Asp-Net45","Web-Net-Ext","Web-ISAPI-Ext","Web-Dir-Browsing","Web-ISAPI-Filter","Web-Http-Logging","Web-Log-Libraries","Web-Request-Monitor","Web-Http-Tracing","Web-Basic-Auth","Web-Windows-Auth","Web-Client-Auth","Web-Filtering","Web-Stat-Compression","Web-Dyn-Compression","Web-Mgmt-Tools","Web-Scripting-Tools","Web-Mgmt-Compat","NET-WCF-HTTP-Activation45","Desktop-Experience","Windows-Identity-Foundation","Server-Media-Foundation","RSAT-ADDS","RSAT-DNS-Server","BITS")
        } else {
            $UCWindowsFeatures  = @("Web-Server","Web-Static-Content","Web-Default-Doc","Web-Http-Errors","Web-Asp-Net","Web-Asp-Net45","Web-Net-Ext","Web-ISAPI-Ext","Web-ISAPI-Filter","Web-Http-Logging","Web-Log-Libraries","Web-Request-Monitor","Web-Http-Tracing","Web-Basic-Auth","Web-Windows-Auth","Web-Client-Auth","Web-Filtering","Web-Stat-Compression","Web-Dyn-Compression","Web-Mgmt-Tools","Web-Scripting-Tools","Web-Mgmt-Compat","NET-WCF-HTTP-Activation45","Desktop-Experience","Windows-Identity-Foundation","RSAT-ADDS","RSAT-DNS-Server")
        } 
        xRemoteFile SXSSource {
            DestinationPath = ($node.destinationPath + "\" + $Node.SXSZip)
            Uri             = $Node.Uri + $Node.SXSZip
            MatchSource     = $true
        }
        Archive UnZipSXS {
            Ensure      = 'Present'
            Force       = $true
            Path        = $node.destinationPath + "\" +  $Node.SXSZip
            Destination = $node.DestinationPath
            DependsOn   = '[xRemoteFile]SXSSource'        
        }
        xRemoteFile UCSource {
            DestinationPath = $node.destinationPath + "\" + $Node.UcISO
            Uri             = $Node.Uri + $Node.UcISO
            MatchSource     = $true
        }
        Archive UnZipUcISO {
            Ensure      = 'Present'
            Force       = $true
            Path        = $node.destinationPath + "\"+ $Node.UcISO
            Destination = $node.DestinationPath
            DependsOn   = '[xRemoteFile]UCSource'
        }
        xRemoteFile UCSourceTools {
            DestinationPath = $node.destinationPath + "\" + $Node.UCTools
            Uri             = $Node.Uri + $Node.UCTools
        }
        Archive UnZipUCTools {
            Ensure      = 'Present'
            Force       = $true
            Path        = $node.destinationPath + "\" + $Node.UCTools
            Destination = $node.DestinationPath
            DependsOn   = "[xRemoteFile]UCSourceTools" 
        }
        # Optional
        Registry ForceShortNameCreation {
            Ensure    = 'Present'
            Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem" 
            ValueName = "NtfsDisable8dot3NameCreation"
            ValueData = "0"
            ValueType = "Dword"
        }
   
        # Add Required UC Windows Features
        WindowsFeature NetFramework35{
            Ensure    = 'Present'
            Name      = 'Net-Framework-Core'
            Source    = $Node.DestinationPath + "\SXS"
            # DependsOn = "[Archive]UnZipSXS"
        }
	    foreach($Item in $UCWindowsFeatures){
        	WindowsFeature $Item{
	            Ensure = 'Present'
        	    Name = $Item
	        }
	    }
        
        # Add Pre-Requisite UC Applications
        if ($Node.Product -match "Skype"){
            $CPlusPlusDisplayName  = "Microsoft Visual C++ 2013 x64 Additional Runtime"     # Skype 2015 - 12.0.21005"
            $CPlusPlusProductID    = "{929FBD26-9020-399B-9A7A-751D61F0B942}" # Skype 2015
            $SQLSysCLRDisplayName  = "Microsoft System CLR Types for SQL Server 2014"       # Skype 2015
            $SQLSysCLRProductID    = "{8C06D6DB-A391-4686-B050-99CC522A7843}" # Skype 2015
            $SMODisplayname        = "Microsoft SQL Server 2014 Management Objects  (x64)"  # Skype 2015
            $SMOProductID          = "{1F9EB3B6-AED7-4AA7-B8F1-8E314B74B2A5}" # Skype 2015
            $OcsCoreDisplayname    = "Skype for Business Server 2015, Core Components"      # Skype 2015
            $OcsCoreProductID      = "{DE39F60A-D57F-48F5-A2BD-8BA3FE794E1F}" # Skype 2015
            $AdminToolsDisplayname = "Skype for Business Server 2015, Administrative Tools" # Skype 2015
            $AdminToolsProductID   = "{9D5751C8-F6AC-4A33-9704-B1D2EB1769B6}" # Skype 2015
        } else {
            $CPlusPlusDisplayName  = "Microsoft Visual C++ 2012 Redistributable (x64)"      # Lync 2013
            $CPlusPlusProductID    = "{15134cb0-b767-4960-a911-f2d16ae54797}" # Lync 2013
            $SQLSysCLRDisplayName  = "Microsoft System CLR Types for SQL Server 2012  (x64)"# Lync 2013
            $SQLSysCLRProductID    = "{F1949145-EB64-4De7-9D81-E6D27937146C}" # Lync 2013
            $SMODisplayname        = "Microsoft SQL Server 2012 Management Objects  (x64)"  # Lync 2013
            $SMOProductID          = "{FA0A244E-F3C2-4589-B42A-3D522De79A42}" # Lync 2013
            $OcsCoreDisplayname    = "Microsoft Lync Server 2013, Core Components"          # Lync 2013
            $OcsCoreProductID      = "{8901ADFC-435C-4E37-9045-9E2E7A613285}" # Lync 2013
            $AdminToolsDisplayname = "Microsoft Lync Server 2013, Administrative Tools"     # Lync 2013
            $AdminToolsProductID   = "{6408FD69-B5A4-48C7-9484-F3Ea3C847279}" # Lync 2013
        }
        xPackage CPlusPlusRedist {
            Ensure          = 'Present'
            Name            = $CPlusPlusDisplayName
            Path            = $Node.UCSourcePath + "\vcredist_x64.exe"
            Arguments       = "/install /quiet"
            PsDscRunAsCredential = $Node.Credential
            Credential      = $Node.Credential
            ProductID       = $CPlusPlusProductID 
            InstalledCheckRegKey       = "HKLM:\SOFTWARE\Microsoft\DevDiv\VC\Servicing\11.0\RunTimeMinimum"
            InstalledCheckRegValueName = "Install"
            InstalledCheckRegValueData = "1"
        }       
        xPackage SQLSysClrTypes {
            Ensure    = 'Present'
            Name      = $SQLSysCLRDisplayName
            Path      = $Node.UCSourcePath + "\SQLSysClrTypes.msi"
            ProductID = $SQLSysCLRProductID 
            DependsOn = "[xPackage]CPlusPlusRedist"
        }      
        xPackage SMO { # SharedManagementObjects
            Ensure    = 'Present'
            Name      = $SMODisplayname
            Path      = $Node.UCSourcePath + "\SharedManagementObjects.msi"
            ProductID = $SMOProductID
            DependsOn = '[xPackage]SQLSysClrTypes'
        }
        xPackage OcsCore {
            Ensure    = 'Present'
            Name      = $OcsCoreDisplayname
            Path      = $Node.UCSourcePath + "\Setup\OcsCore.msi"
            ProductID = $OcsCoreProductID
            DependsOn = '[xPackage]CPlusPlusRedist'
        }
        xPackage AdminTools {
            Ensure    = 'Present'
            Name      = $AdminToolsDisplayname
            Path      = $Node.UCSourcePath + "\Setup\AdminTools.msi"
            ProductID = $AdminToolsProductID 
            DependsOn = "[xPackage]OcsCore"
        }   
        xPackage SilverLight {
            Ensure          = 'Present'
            Name            = "Microsoft Silverlight"
            Path            = $Node.UCToolsSourcePath + "Silverlight_x64.exe"
            Arguments       = "/q"
            PsDscRunAsCredential = $Node.Credential 
            Credential      = $Node.Credential
            ProductID       = ''
            InstalledCheckRegKey       = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Silverlight"
            InstalledCheckRegValueName = "Version"
           #InstalledCheckRegValueData = "5.1.412120"            # Checks for Silverilght  August 11, 2015  Version - change if installing different version
            InstalledCheckRegValueData = "5.1.50709.0"           # Checks for Silverilght  September 14, 2016  Version - change if installing different version
        }

        xDnsRecord NewFrontEndARecord {
            Ensure = 'Present'
            Type   = "ARecord"
            Name   = $Node.ComputerName
            Target = $Node.IP
            Zone   = $Node.DomainName
        }
        xDnsRecord NewFrontEndcName {
            Ensure = 'Present'
            Type   = "CName"
            Name   = $Node.ComputerName
            Target = $Node.UCPool +"." + $Node.DomainName
            Zone   = $Node.DomainName
        }

        <#
        cLyncFEInstall InstallFrontEnd {
            Ensure  = 'Present'
            productDir
        }
        #>
        
        # Load the resource kit tools on the server
        xRemoteFile UCTools {
            DestinationPath = $Node.UCToolsPath + "UCTools.Zip" 
            Uri             = $Node.Uri + "UCTools.Zip"
        }       
        Archive UCTools {
            Ensure      = 'Present'
            Force       = $true
            Path        = $Node.UCToolsPath + "UCTools.Zip" 
            Destination = "C:\Binn\"
            DependsOn   =  '[xRemoteFile]UCTools'
        }
               
        cPermissionCertificateTemplate WebServer {
            Ensure           = 'Present'
            Template         = $Node.CATemplate
            Group            = $Node.ComputerName + '$'
            PsDscRunAsCredential = $Node.Credential
            #DependsOn        = '[cLyncFEInstall] InstallFrontEnd'
        }

        cLyncCerts UCCert {
            Ensure           = "Present"
            CertRequestType  = "Lync"
            CertSubject      = $Node.Computername + "." + $Node.DomainName
            CertFriendlyName = $Node.UCCertFriendlyName
            CATemplate       = $Node.CATemplate
            #DependsOn        = '[cPermissionCertificateTemplate] WebServer'
        }
        <#                     
        cLyncCerts OAuthCert {
            Ensure           = "Present"
            CertRequestType  = "Oauth"
            CertSubject      = $Node.DomainName
            CertFriendlyName = $Node.OAuthCertFriendlyName
            CATemplate       = $Node.CATemplate
            DependsOn        = '[cLyncTopology]StdEditionTopology'
        } #> #OAuth Cert should install auomatically as part of the synchronization with the CMS
 
    }
}

[DSCLocalConfigurationManager()] 
configuration LCMConfig { 
     Node "172.16.0.11"
   { 
        Settings 
        { 
           ConfigurationID      = "be68a6c2-ef82-4ef1-b249-ff95a222b0d1" # lync-05 GUID"
           # CertificateID      = "AAB7524DAD55ABD9F930A14A2AA8701BAE6B3D17"
           ConfigurationMode    = "ApplyandAutoCorrect"             
           ConfigurationModeFrequencyMins = 15
           RefreshFrequencyMins = 30
           RebootNodeifNeeded   = $true
           AllowModuleOverWrite = $true
           RefreshMode          = "Pull"
        } 
          
         ConfigurationRepositoryWeb DscWeb
         { 
            ServerURL = "HTTP://DSC-001.scottslab.com:8080/PSDSCPullServer.Svc"
            AllowUnsecureConnection = $true
         } 
           ResourceRepositoryWeb DSCResource
         { 
            ServerURL = "HTTP://DSC-001.scottslab.com:8080/PSDSCPullServer.Svc"
            AllowUnsecureConnection = $true
         } 
    }
}
#>
Try {
    $moffile = UCFEConfig -ConfigurationData $ConfigData -OutputPath $ConfigFile
    $metaMof = LCMConfig -ConfigurationData $ConfigData -OutputPath $ConfigFile
    New-DscChecksum -ConfigurationPath $moffile.fullname -Force
    New-DscChecksum -ConfigurationPath $metamof.fullname -Force
} Catch {
    $ErrorState= 2
    $errorMessage = $error[0].ExceptionMessage
    $Trace += "MOF Creation Failed `r `n"
}
##### Populate Orchestrator Databus #####
$ErrorState
$ErrorMessage 
$Trace
