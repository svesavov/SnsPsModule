
###### If you like it, please consider buy me a beer :beer:
###### [![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=6NKR7XQH5E2P2&source=url)


# SnsPsModule


## Requirements

* .NET Framework 4.5
* PowerShell 4


## Instructions

Simply run
```powershell
Install-Module "SnsPsModule" -Scope "AllUsers";
```
OR
1. Download SnsPsModule.zip.
2. Don't forget to check the .ZIP file for viruses and etc.
3. File MD5 hash: `94F8269958D972DC9E25212557D045B6`
4. Unzip in one of the following folders depending of your preference:
* `C:\Users\UserName\Documents\WindowsPowerShell\Modules` - Replace "UserName" with the actual username, If you want the module to be available for specific user.
* `C:\Program Files\WindowsPowerShell\Modules` - If you want the module to be available for all users on the machine.
* Or any other location present in `$env:PSModulePath`
5. Run the following command replacing "PathWhereModuleIsInstalled" with the actual path where the module files were unzipped.
```powershell
Get-ChildItem -Path "PathWhereModuleIsInstalled" -Recurse | Unblock-File
```
6. Enjoy!


## External Links

- svesavov on GitHub: [https://github.com/svesavov](https://github.com/svesavov)
- Svetoslav Savov on LinkedIn [https://www.linkedin.com/in/svetoslavsavov](https://www.linkedin.com/in/svetoslavsavov)
