Configuration SeleniumNodeConfiguration 
{
    Node localhost 
    {
        # for 32bit version of IE11
        Registry Registry1
        {
            Ensure      = "Present" 
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_BFCACHE"
            ValueName   = "iexplore.exe"
            ValueData   = "0"
            ValueType   = "dword"
        }

        # for 64bit version of IE11
        Registry Registry2
        {
            Ensure      = "Present" 
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_BFCACHE"
            ValueName   = "iexplore.exe"
            ValueData   = "0"
            ValueType   = "dword"
        }

        # Disable IE ESX (Internet Explorer Enhanced Security Configuration)
        Registry Registry3
        {
            Ensure      = "Present" 
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
            ValueName   = "IsInstalled"
            ValueData   = "0"
            ValueType   = "dword"
        }

        Registry Registry4
        {
            Ensure      = "Present" 
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
            ValueName   = "IsInstalled"
            ValueData   = "0"
            ValueType   = "dword"
        }

        # Disable Enhanced Protected Mode
        Registry Registry5
        {
            Ensure      = "Present" 
            Key         = "HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Main"
            ValueName   = "Isolation"
            ValueData   = "PMIL"
        }

        # Enure Protected Mode is enabled everywhere
        # Zone 0 – My Computer
        # Zone 1 – Local Intranet Zone
        # Zone 2 – Trusted sites Zone
        # Zone 3 – Internet Zone
        # Zone 4 – Restricted Sites Zone
        # https://support.microsoft.com/en-us/help/182569/internet-explorer-security-zones-registry-entries-for-advanced-users
        Registry LocalMachine_ProtectedMode_LocalIntranetZone_x64_Registry
        {
            Ensure      = "Present" 
            Key         = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1"
            ValueName   = "2500"
            ValueData   = "0"
            ValueType   = "dword"
        }

        Registry LocalMachine_ProtectedMode_TrustedSitesZone_x64_Registry
        {
            Ensure      = "Present" 
            Key         = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"
            ValueName   = "2500"
            ValueData   = "0"
            ValueType   = "dword"
        }

        Registry LocalMachine_ProtectedMode_IternetZone_x64_Registry
        {
            Ensure      = "Present" 
            Key         = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
            ValueName   = "2500"
            ValueData   = "0"
            ValueType   = "dword"
        }

        Registry LocalMachine_ProtectedMode_RestrictedSitesZone_x64_Registry
        {
            Ensure      = "Present" 
            Key         = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
            ValueName   = "2500"
            ValueData   = "0"
            ValueType   = "dword"
        }

        Registry LocalMachine_ProtectedMode_LocalIntranetZone_x86_Registry
        {
            Ensure      = "Present" 
            Key         = "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1"
            ValueName   = "2500"
            ValueData   = "0"
            ValueType   = "dword"
        }

        Registry LocalMachine_ProtectedMode_TrustedSitesZone_x86_Registry
        {
            Ensure      = "Present" 
            Key         = "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"
            ValueName   = "2500"
            ValueData   = "0"
            ValueType   = "dword"
        }

        Registry LocalMachine_ProtectedMode_IternetZone_x86_Registry
        {
            Ensure      = "Present" 
            Key         = "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
            ValueName   = "2500"
            ValueData   = "0"
            ValueType   = "dword"
        }

        Registry LocalMachine_ProtectedMode_RestrictedSitesZone_x86_Registry
        {
            Ensure      = "Present" 
            Key         = "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
            ValueName   = "2500"
            ValueData   = "0"
            ValueType   = "dword"
        }

        Registry CurrentUser_ProtectedMode_LocalIntranetZone_x64_Registry
        {
            Ensure      = "Present" 
            Key         = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1"
            ValueName   = "2500"
            ValueData   = "0"
            ValueType   = "dword"
        }

        Registry CurrentUser_ProtectedMode_TrustedSitesZone_x64_Registry
        {
            Ensure      = "Present" 
            Key         = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"
            ValueName   = "2500"
            ValueData   = "0"
            ValueType   = "dword"
        }

        Registry CurrentUser_ProtectedMode_IternetZone_x64_Registry
        {
            Ensure      = "Present" 
            Key         = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
            ValueName   = "2500"
            ValueData   = "0"
            ValueType   = "dword"
        }

        Registry CurrentUser_ProtectedMode_RestrictedSitesZone_x64_Registry
        {
            Ensure      = "Present" 
            Key         = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
            ValueName   = "2500"
            ValueData   = "0"
            ValueType   = "dword"
        }

        Registry CurrentUser_ProtectedMode_LocalIntranetZone_x86_Registry
        {
            Ensure      = "Present" 
            Key         = "HKEY_CURRENT_USER\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1"
            ValueName   = "2500"
            ValueData   = "0"
            ValueType   = "dword"
        }

        Registry CurrentUser_ProtectedMode_TrustedSitesZone_x86_Registry
        {
            Ensure      = "Present" 
            Key         = "HKEY_CURRENT_USER\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"
            ValueName   = "2500"
            ValueData   = "0"
            ValueType   = "dword"
        }

        Registry CurrentUser_ProtectedMode_IternetZone_x86_Registry
        {
            Ensure      = "Present" 
            Key         = "HKEY_CURRENT_USER\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
            ValueName   = "2500"
            ValueData   = "0"
            ValueType   = "dword"
        }

        Registry CurrentUser_ProtectedMode_RestrictedSitesZone_x86_Registry
        {
            Ensure      = "Present" 
            Key         = "HKEY_CURRENT_USER\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
            ValueName   = "2500"
            ValueData   = "0"
            ValueType   = "dword"
        }
    }
}
SeleniumNodeConfiguration 
Start-DscConfiguration -Wait -Verbose -Path .\SeleniumNodeConfiguration
