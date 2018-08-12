Set-ExecutionPolicy Bypass -Force
Import-Module secureboot

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition

try
{
	Set-SecureBootUEFI -Name dbx -Time 2018-07-05T00:00:00Z -Content $null
	Set-SecureBootUEFI -Name db -Time 2018-07-05T00:00:00Z -Content $null
	Set-SecureBootUEFI -Name KEK -Time 2018-07-05T00:00:00Z -Content $null
	Set-SecureBootUEFI -Name PK -Time 2018-07-05T00:00:00Z -Content $null
}
catch
{
}

Write-Host "Setting KEK-signed content of dbx..."
Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\dbx_list_SigList.bin -SignedFilePath $scriptPath\siglists\dbx_list_SigList_Serialization.bin.p7 -Name dbx

Write-Host "Setting KEK-signed DCS cert in db..."
Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\DCS_sign_SigList.bin -SignedFilePath $scriptPath\siglists\DCS_sign_SigList_Serialization.bin.p7 -Name db

Write-Host "Setting KEK-signed MS cert in db..."
Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\MicWinProPCA2011_2011-10-19_SigList.bin -SignedFilePath $scriptPath\siglists\MicWinProPCA2011_2011-10-19_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true

Write-Host "Setting KEK-signed MS UEFI cert in db..."
Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\MicCorUEFCA2011_2011-06-27_SigList.bin -SignedFilePath $scriptPath\siglists\MicCorUEFCA2011_2011-06-27_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true

# Add any additional certificate that already existed in your original db variable (see output of dumpEfiVars tool)
# Below is a list of commands for each manufacturer. Uncommand only the lines that correspond to your configuration
# as displayed by dumpEfiVars tool

############### Acer ###############
# Write-Host "Setting KEK-signed Acer certs in db..."
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Acer_2012-05-31_SigList.bin -SignedFilePath $scriptPath\siglists\Acer_2012-05-31_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Acer_Database_2013-07-10_SigList.bin -SignedFilePath $scriptPath\siglists\Acer_Database_2013-07-10_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Acer_db_Manufacture_2015-06-17_SigList.bin -SignedFilePath $scriptPath\siglists\Acer_db_Manufacture_2015-06-17_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Acer_LINPUS_2012-10-09_SigList.bin -SignedFilePath $scriptPath\siglists\Acer_LINPUS_2012-10-09_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Acer_Quanta_NB4_2012-07-18_SigList.bin -SignedFilePath $scriptPath\siglists\Acer_Quanta_NB4_2012-07-18_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Acer_ABO_2010-12-31_SigList.bin -SignedFilePath $scriptPath\siglists\Acer_ABO_2010-12-31_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Acer_DisablePW_2012-12-31_SigList.bin -SignedFilePath $scriptPath\siglists\Acer_DisablePW_2012-12-31_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Acer_Wistron_Secure_Flash_2013-05-17_SigList.bin -SignedFilePath $scriptPath\siglists\Acer_Wistron_Secure_Flash_2013-05-17_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true

############### ASUS ###############
# Write-Host "Setting KEK-signed ASUS certs in db..."
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\ASUSTeK_MotherBoard_SW_Key_Certificate_2011-12_27_SigList.bin -SignedFilePath $scriptPath\siglists\ASUSTeK_MotherBoard_SW_Key_Certificate_2011-12_27_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\ASUSTeK_Notebook_SW_Key_Certificate_2011-12_27_SigList.bin -SignedFilePath $scriptPath\siglists\ASUSTeK_Notebook_SW_Key_Certificate_2011-12_27_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Canonical_Master_CA_2012_04_12_SigList.bin -SignedFilePath $scriptPath\siglists\Canonical_Master_CA_2012_04_12_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true

############### DELL ###############
# Write-Host "Setting KEK-signed Dell cert in db..."
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Dell_UEFI_DB_2016_06_03_SigList.bin -SignedFilePath $scriptPath\siglists\Dell_UEFI_DB_2016_06_03_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Dell_CompalA31CSMB_2012-07-17_SigList.bin -SignedFilePath $scriptPath\siglists\Dell_CompalA31CSMB_2012-07-17_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true

############### HP ###############
# Write-Host "Setting KEK-signed HP cert in db..."
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\HP_UEFI_Secure_Boot_2013_DB_key_2013_08_23_SigList.bin -SignedFilePath $scriptPath\siglists\HP_UEFI_Secure_Boot_2013_DB_key_2013_08_23_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\HP_UEFI_Secure_Boot_DB_2017_2017-01-20_SigList.bin -SignedFilePath $scriptPath\siglists\HP_UEFI_Secure_Boot_DB_2017_2017-01-20_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true

############### Lenovo ###############
# Write-Host "Setting KEK-signed Lenovo certs in db..."
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Lenovo_1T110-1415ISK-2016-02-17_SigList.bin -SignedFilePath $scriptPath\siglists\Lenovo_1T110-1415ISK-2016-02-17_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Lenovo_DCU31-80E31-80_2015-03-03_SigList.bin -SignedFilePath $scriptPath\siglists\Lenovo_DCU31-80E31-80_2015-03-03_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Lenovo_ThinkPad_Product_CA_2012-06-29_SigList.bin -SignedFilePath $scriptPath\siglists\Lenovo_ThinkPad_Product_CA_2012-06-29_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Lenovo_UEFI_CA_2014-01-24_SigList.bin -SignedFilePath $scriptPath\siglists\Lenovo_UEFI_CA_2014-01-24_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Lenovo_2JYoga910_2015-12-02_SigList.bin -SignedFilePath $scriptPath\siglists\Lenovo_2JYoga910_2015-12-02_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Lenovo_LCFC_2015-05-29_SigList.bin -SignedFilePath $scriptPath\siglists\Lenovo_LCFC_2015-05-29_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Lenovo_Mocca_2012-06-20_SigList.bin -SignedFilePath $scriptPath\siglists\Lenovo_Mocca_2012-06-20_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Lenovo_4MYoga720-15IKB_2016-11-09_SigList.bin -SignedFilePath $scriptPath\siglists\Lenovo_4MYoga720-15IKB_2016-11-09_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true

############### MSI ###############
# Write-Host "Setting KEK-signed MSI certs in db..."
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\MSI_SHIP_OWN_CA_2012-06-09_SigList.bin -SignedFilePath $scriptPath\siglists\MSI_SHIP_OWN_CA_2012-06-09_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true

############### OriginPC ###############
# Write-Host "Setting KEK-signed OriginPC certs in db..."
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\OriginPC_OWN_CA_2018-01-09_SigList.bin -SignedFilePath $scriptPath\siglists\OriginPC_OWN_CA_2018-01-09_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true

############### Panasonic ###############
# Write-Host "Setting KEK-signed Panasonic certs in db..."
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Panasonic_Corporation_db_CA_2013-03-31_SigList.bin -SignedFilePath $scriptPath\siglists\Panasonic_Corporation_db_CA_2013-03-31_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true

############### Toshiba ###############
# Write-Host "Setting KEK-signed Toshiba certs in db..."
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Toshiba_Corporation_Utility_CA_2012-08-10_SigList.bin -SignedFilePath $scriptPath\siglists\Toshiba_Corporation_Utility_CA_2012-08-10_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Toshiba_QCI_2012-07-24_SigList.bin -SignedFilePath $scriptPath\siglists\Toshiba_QCI_2012-07-24_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true
# Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\Toshiba_QCI_Shell_2012-07-24_SigList.bin -SignedFilePath $scriptPath\siglists\Toshiba_QCI_Shell_2012-07-24_SigList_Serialization.bin.p7 -Name db -AppendWrite:$true

Write-Host "Setting PK-signed KEK..."
Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\DCS_key_exchange_SigList.bin -SignedFilePath $scriptPath\siglists\DCS_key_exchange_SigList_Serialization.bin.p7 -Name KEK

Write-Host "Setting self-signed PK..."
Set-SecureBootUEFI -Time 2018-07-05T00:00:00Z -ContentFilePath $scriptPath\siglists\DCS_platform_SigList.bin -SignedFilePath $scriptPath\siglists\DCS_platform_SigList_Serialization.bin.p7 -Name PK

