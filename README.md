# commands

### One Liner

```
Set-ExecutionPolicy Bypass -Scope Process -Force; iex "& { $(irm https://raw.githubusercontent.com/tristanbeatty/ttt/main/techtools.ps1) }"
```

### winget

'''
$ErrorActionPreference='Stop'; [Net.ServicePointManag]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; if(Get-Command winget.exe -ErrorAction SilentlyContinue){winget --version} else { if(-not (Get-Module -ListAvailable Microsoft.WinGet.Client)){ Install-PackageProvider NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null; Set-PSRepository PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue; Install-Module Microsoft.WinGet.Client -Scope CurrentUser -Force -AllowClobber } Import-Module Microsoft.WinGet.Client -Force; Repair-WinGetPackageManager -Force -Latest; if(Get-Command winget.exe -ErrorAction SilentlyContinue){winget --version} else { throw 'winget still missing (App Installer install/Store/PSGallery likely blocked).' } }
'''
