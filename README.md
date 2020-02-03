# SnsPsModule
General PowerShell Module

1. Download SnsPsModule.zip
2. Unzip in one of the following folders depending of the preference:
- C:\Users\UserName\Documents\WindowsPowerShell\Modules - Replace "UserName" with the actual username, If you want the module available for specific user
- C:\Program Files\WindowsPowerShell\Modules - If you want the module to be available for all user on the machine
- Or any other location present in $env:PSModulePath
3. Run the following command replacing "PathWhereModuleIsInstalled" with the actual path where the module files were unzipped.
Get-ChildItem -Path "PathWhereModuleIsInstalled" -Recurse | Unblock-File
4. Enjoy
