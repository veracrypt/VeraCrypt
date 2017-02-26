Set-ExecutionPolicy Bypass -Force
Import-Module secureboot

Set-SecureBootUEFI -Name PK -Time 2015-09-11 -Content $null
Set-SecureBootUEFI -Name KEK -Time 2015-09-11 -Content $null
Set-SecureBootUEFI -Name db -Time 2015-09-11 -Content $null
Set-SecureBootUEFI -Name dbx -Time 2015-09-11 -Content $null

Write-Host "Setting self-signed PK..."
Set-SecureBootUEFI -Time 2016-08-08T00:00:00Z -ContentFilePath siglists\DCS_platform_SigList.bin -SignedFilePath siglists\DCS_platform_SigList_Serialization.bin.p7 -Name PK

Write-Host "Setting PK-signed KEK..."
Set-SecureBootUEFI -Time 2016-08-08T00:00:00Z -ContentFilePath siglists\DCS_key_exchange_SigList.bin -SignedFilePath siglists\DCS_key_exchange_SigList_Serialization.bin.p7 -Name KEK

Write-Host "Setting KEK-signed DCS cert in db..."
Set-SecureBootUEFI -Time 2016-08-08T00:00:00Z -ContentFilePath siglists\DCS_sign_SigList.bin -SignedFilePath siglists\DCS_sign_SigList_Serialization.bin.p7 -Name db

Write-Host "Setting KEK-signed MS cert in db..."
Set-SecureBootUEFI -Time 2016-08-08T00:00:00Z -ContentFilePath siglists\MicWinProPCA2011_2011-10-19_SigList.bin -SignedFilePath siglists\MicWinProPCA2011_2011-10-19_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true

Write-Host "Setting KEK-signed MS UEFI cert in db..."
Set-SecureBootUEFI -Time 2016-08-08T00:00:00Z -ContentFilePath siglists\MicCorUEFCA2011_2011-06-27_SigList.bin -SignedFilePath siglists\MicCorUEFCA2011_2011-06-27_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true
