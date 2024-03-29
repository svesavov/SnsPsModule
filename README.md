
###### If you like it, please consider buy me a beer :beer:
###### [![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=6NKR7XQH5E2P2&source=url)


# SnsPsModule


## Requirements

* .NET Framework 4.7.2
* PowerShell 4


## Instructions

Simply run
```powershell
Install-Module "SnsPsModule" -Scope "AllUsers";
```
OR
1. Download SnsPsModule.zip.
2. Don't forget to check the .ZIP file for viruses and etc.
3. File MD5 hash: `4E67014D3DE3412F13A9E2CDA9EA630C`
4. Unzip in one of the following folders depending of your preference:
* `C:\Users\UserName\Documents\WindowsPowerShell\Modules` - Replace "UserName" with the actual username, If you want the module to be available for specific user.
* `C:\Program Files\WindowsPowerShell\Modules` - If you want the module to be available for all users on the machine.
* Or any other location present in `$env:PSModulePath`
5. Run the following command replacing "PathWhereModuleIsInstalled" with the actual path where the module files were unzipped.
```powershell
Get-ChildItem -Path "PathWhereModuleIsInstalled" -Recurse | Unblock-File
```
6. Enjoy!

For additional information, please use the CmdLets built-in help.
```powershell
Get-Help Add-SnsAdGroupMember -Full;
Get-Help Add-SnsAdMultiValuedStringAttributeValue -Full;
Get-Help Clear-SnsAdAttribute -Full;
Get-Help ConvertFrom-SnsIADsLargeInteger -Full;
Get-Help ConvertFrom-SnsIpAddressString -Full;
Get-Help Get-SnsAdAttribute -Full;
Get-Help Get-SnsWebPage -Full;
Get-Help Invoke-SnsSQLQuery -Full; #Deprecated. Please Use "Invoke-SnsMsSqlQuery" CmdLet From "https://www.powershellgallery.com/packages/SnsMsSqlPsModule/" Module
Get-Help Move-SnsAdObject -Full;
Get-Help New-SnsAdObject -Full;
Get-Help New-SnsChart -Full;
Get-Help New-SnsHtmlHeader -Full;
Get-Help New-SnsPassword -Full;
Get-Help New-SnsPieChart -Full;
Get-Help New-SnsZipArchive -Full;
Get-Help Remove-SnsAdGroupMember -Full;
Get-Help Remove-SnsAdMultiValuedStringAttributeValue -Full;
Get-Help Remove-SnsAdObject -Full;
Get-Help Rename-SnsAdObject -Full;
Get-Help Reset-SnsAdPassword -Full;
Get-Help Search-SnsAdObject -Full;
Get-Help Set-SnsAdBooleanAttribute -Full;
Get-Help Set-SnsAdByteAttribute -Full;
Get-Help Set-SnsAdIadsiLargeIntegerAttribute -Full;
Get-Help Set-SnsAdInt32Attribute -Full;
Get-Help Set-SnsAdMultiValuedStringAttribute -Full;
Get-Help Set-SnsAdProtectFromAccidentalDeletion -Full;
Get-Help Set-SnsAdStringAttribute -Full;
Get-Help Set-SnsAdUserMustChangePassword -Full;
Get-Help Set-SnsRegistry -Full;

Get-Help Assert-SnsDirectAssignedLicense -Full;
Get-Help Assert-SnsGroupBasedLicense -Full;
Get-Help Connect-SnsAzureAd -Full;
Get-Help Connect-SnsExchangeEws -Full;
Get-Help Connect-SnsExchangeOnline -Full;
Get-Help Connect-SnsExchangeOnPremises -Full;
Get-Help Connect-SnsMsolService -Full;
Get-Help Connect-SnsSharePointOnline -Full;
Get-Help Connect-SnsSkypeOnPremises -Full;
Get-Help Connect-SnsMicrosoftTeams -Full;
Get-Help Convert-SnsObjectToSQLInsertQuery -Full; #Deprecated. Please Use "Invoke-SnsMsSqlObjectInsert" CmdLet From "https://www.powershellgallery.com/packages/SnsMsSqlPsModule/" Module
Get-Help Disable-SnsMfa -Full;
Get-Help Enable-SnsMfa -Full;
Get-Help Export-SnsCredentialFile -Full;
Get-Help Get-SnsAdGroupMembers -Full; #Deprecated. Please Use "Search-SnsAdObject" CmdLet With LDAP Query "memberOf:1.2.840.113556.1.4.1941:=<YourGroupDN>" As It Is Described Here https://bit.ly/2RFdUr2
Get-Help Import-SnsCredentialFile -Full;
Get-Help New-SnsTemporaryPsDrive -Full;
```


## External Links

- svesavov on GitHub: [https://github.com/svesavov](https://github.com/svesavov)
- svesavov on PowerShell Gallery: [https://www.powershellgallery.com/packages/SnsPsModule/](https://www.powershellgallery.com/packages/SnsPsModule/)
- Svetoslav Savov on LinkedIn: [https://www.linkedin.com/in/svetoslavsavov](https://www.linkedin.com/in/svetoslavsavov)
