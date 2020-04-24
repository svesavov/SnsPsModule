# SnsPsModule
General PowerShell Module

1. Download SnsPsModule.zip
2. Don't forget to check the .ZIP file for viruses and etc.
3. File MD5 hash: 6DBD5D077FC6236AAB8F4EDB4B93998E
4. Unzip in one of the following folders depending of the preference:
- C:\Users\UserName\Documents\WindowsPowerShell\Modules - Replace "UserName" with the actual username, If you want the module available for specific user
- C:\Program Files\WindowsPowerShell\Modules - If you want the module to be available for all user on the machine
- Or any other location present in $env:PSModulePath
5. Run the following command replacing "PathWhereModuleIsInstalled" with the actual path where the module files were unzipped.
Get-ChildItem -Path "PathWhereModuleIsInstalled" -Recurse | Unblock-File
6. Enjoy


[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://PayPal.Me/svesavov)