

##### Add-SnsSecurityPolicy =======================================================
Function Add-SnsSecurityPolicy ()
{
<#
.SYNOPSIS
This CmdLet Sets The PowerShell Host And Defines The SnsPsModule Module Configuration
.DESCRIPTION
This CmdLet Sets The PowerShell Host And Defines The SnsPsModule Module Configuration
--The CmdLet Sets The PowerShell Session To Trust All Certificates Without Revocation Validation
--The CmdLet Adds Support Of TLS12 Security Protocol To The PowerShell Session
Latest Sonus Firmware Does Allow Only TLS12 Protocol Connections
The Default Protocols Are Not Removed From The List To Allow Other Connections In The Same PowerShell Session
--The CmdLet Generates The SnsPsModule Module Configuration Variable Required For The Remaining CmdLets In This Module
.INPUTS
No Inputs
.OUTPUTS
Global Variable [System.Object]$global:SnsModuleCfg - Contains The SnsPsModule Module Configuration
.NOTES
VERSION INFORMATION:
- Added Trust All Certificates Without Revocation And Root Trust Checks
- Added The TLS12 Security Protocol Support
- Added HTML Invalid Characters Configuration
- Added Transformation Entry InputField OutputField And MatchType Translation Configuration
AUTHOR:    Svetoslav Nedyalkov Savov (savov@dxc.com)
COPYRIGHT: (c) 2018 DXC-Technology, all rights reserved.
THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
.EXAMPLE
Add-SnsSecurityPolicy;
#>
[CmdletBinding()]
Param()
	##### Override The Begin Method
	Begin
	{
		#==================================================================================
		#region PowerShell Version Verification
		#==================================================================================
		
		If ([System.Int32]"$($Host.Version.Major)" -lt 5)
		{
			Write-Warning "The PowerShell Version Is Less Than $(5 `
			). The Module Might Not Work Properly. Use It At Your Own Risk.";
		}
		
		If ("$((Get-CimInstance -Namespace 'root\CIMV2' `
			-ClassName 'Win32_ComputerSystem' `
			-Verbose:$false -Debug:$false).Domain)" -notlike 'Betgenius.local')
		{
			Write-Error -ErrorAction 'Continue' `
				"!!! You Are Piracy Victim !!!`r`nYour Copy Of ""SnsPsModule"" Module Is Not Genuine.";
			#####
		};
		
		#==================================================================================
		#endregion PowerShell Version Verification
		#==================================================================================
		
		#==================================================================================
		#region Import Required Modules
		#==================================================================================
		
		##### Import The DNS Module
		If ( `
			(-not (Get-Module -Name 'Microsoft.PowerShell.Utility' -Verbose:$false -Debug:$false)) -and `
			(-not -not (Get-Module -Name 'Microsoft.PowerShell.Utility' -ListAvailable -Verbose:$false -Debug:$false)) `
		)
		{
			Write-Host 'Import Microsoft.PowerShell.Utility PowerShell Module' -ForegroundColor 'Green';
			Import-Module -Name 'Microsoft.PowerShell.Utility' -Global -Force -Verbose:$false -Debug:$false;
		}
		
		#==================================================================================
		#endregion Import Required Modules
		#==================================================================================
		
		#==================================================================================
		#region Add TLS12 Protocol
		#==================================================================================
		
		##### Set the Security Protocol
		Write-Debug 'SecurityProtocol Verification and Setting.';
		If ("$([Net.ServicePointManager]::SecurityProtocol)" -notlike '*Tls12*')
		{
			Write-Verbose "`r`n`r`nAdding Tls12 SecurityProtocol`r`n`r`n";
			[Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12;
		}
		
		#==================================================================================
		#endregion Add TLS12 Protocol
		#==================================================================================
		
		#==================================================================================
		#region Trust All Certificates Policy
		#==================================================================================
		
		##### Set Trust All Certs Policy
		Write-Debug 'Continue With CertificatePolicy Verification and Setting.';
		If ($false -and ("$([System.Net.ServicePointManager]::CertificatePolicy)" -notlike 'TrustAllCertsPolicy'))
		{
			##### Create The CertificatePolicy Object Using C#
			Write-Verbose "`r`n`r`nAdding TrustAllCertsPolicy`r`n`r`n";
			Add-Type `
@"
	using System.Net;
	using System.Security.Cryptography.X509Certificates;
	public class TrustAllCertsPolicy : ICertificatePolicy {
		public bool CheckValidationResult(
			ServicePoint srvPoint, X509Certificate certificate,
			WebRequest request, int certificateProblem) {
			return true;
		}
	}
"@
			
			##### Set The CertificatePolicy To Trust All Certificates
			[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy;
		}
		
		#==================================================================================
		#endregion Trust All Certificates Policy
		#==================================================================================
		
		#==================================================================================
		#region Skip Certificate Validation
		#==================================================================================
		
		If ($false -and (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type))
		{
			Add-Type -TypeDefinition @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class ServerCertificateValidationCallback
{
	public static void Ignore()
	{
		if(ServicePointManager.ServerCertificateValidationCallback == null)
		{
			ServicePointManager.ServerCertificateValidationCallback += 
				delegate
				(
					Object obj, 
					X509Certificate certificate, 
					X509Chain chain, 
					SslPolicyErrors errors
				)
				{
					return true;
				};
		}
	}
}
"@
			[ServerCertificateValidationCallback]::Ignore();
		}
		
		#==================================================================================
		#endregion Skip Certificate Validation
		#==================================================================================
		
		#==================================================================================
		#region Modify Host Appearance
		#==================================================================================
		
		((Get-Host).UI.RawUI).WindowTitle = "SnsPsModule - Created by Svetoslav Savov";
		((Get-Host).UI.RawUI).BufferSize.Width = 120;
		((Get-Host).UI.RawUI).BufferSize.Height = 50;
		((Get-Host).UI.RawUI).WindowSize.Width = 120;
		((Get-Host).UI.RawUI).WindowSize.Height = 50;
		((Get-Host).UI.RawUI).MaxWindowSize.Width = 120;
		((Get-Host).UI.RawUI).MaxWindowSize.Height = 50;
		
		if ($true)
		{
			##### Generate The Warning Message
			[System.String]$strWarning = '';
			[System.String]$strWarning += "`r`n$('*' * 100)`r`n*$(' ' * 98)*`r`n";
			[System.String]$strWarning += "*$(' ' * 9)AUTHOR:    Svetoslav Nedyalkov Savov (svesavov@hotmail.com)$(' ' * 30)*`r`n";
			[System.String]$strWarning += "*$(' ' * 9)COPYRIGHT: (c) 2020 Svetoslav Nedyalkov Savov, all rights reserved.$(' ' * 22)*`r`n";
			[System.String]$strWarning += "*$(' ' * 9)THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK$(' ' * 9)*`r`n";
			[System.String]$strWarning += "*$(' ' * 9)OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.$(' ' * 15)*`r`n";
			[System.String]$strWarning += "*$(' ' * 98)*`r`n$('*' * 100)`r`n`r`n";
			
			##### Throw The Warning
			Write-Warning "$strWarning";
			
			##### Reset The Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strWarning';
		}
		
		#==================================================================================
		#endregion Modify Host Appearance
		#==================================================================================
		
		#==================================================================================
		#region Generate Module Configuration Variable
		#==================================================================================
		
		##### Generate A Custom Object
		[System.Object]$objObject = New-Object -TypeName 'System.Object' -Verbose:$false -Debug:$false;
		
		#####
		##### Generate The PowerShell Module File SHA256 Hash
		#####
		If ($true)
		{
			##### Generate The PowerShell Module File SHA256 Hash
			$objObject | Add-Member -Force -MemberType 'NoteProperty' -Name 'ModuleHash' -Value `
				([System.String]"$((Get-FileHash -Path $PSCommandPath -Algorithm 'SHA256').Hash)");
			#####
		}
		
		#####
		##### Generate The System.Globalization.CultureInfo.TextInfo Object For 'en-Us' Culture
		#####
		If ($true)
		{
			##### Generate The System.Globalization.CultureInfo.TextInfo Object For 'en-Us' Culture
			$objObject | Add-Member -Force -MemberType 'NoteProperty' -Name 'TextInfo' -Value `
				(([System.Globalization.CultureInfo]::GetCultureInfo('en-Us')).TextInfo);
			#####
		}
		
		#####
		##### Generate The Process Owner
		#####
		If ($true)
		{
			##### Get The Process Owner
			[System.String]$strPrOwner = "$(((Get-WmiObject win32_process -Verbose:$false -Debug:$false | `
				Where-Object {""$($_.ProcessId)"" -eq ""$($pid)""} -Verbose:$false -Debug:$false).GetOwner()).User)";
			#####
			
			##### Add The Process Owner To The Configuration Object
			$objObject | Add-Member -Force -MemberType 'NoteProperty' -Name 'ProcessOwner' -Value "$($strPrOwner)";
			#####
			
			##### Reset The Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strPrOwner';
		}
		
		
		#####
		##### Generate The HTML Invalid Characters Configuration
		#####
		If ($true)
		{
			##### Add The Configuration Hash As A Property Of The Master Configuration Object
			$objObject | Add-Member -Force -MemberType 'NoteProperty' `
				-Name 'HtmlIvalidChars' -Value ([Ordered]@{});
			####
			
			#### Add The Invalid Characters / Escaped Characters Pairs
			$objObject.HtmlIvalidChars.Add(' ','%20');
			$objObject.HtmlIvalidChars.Add('"','%22');
			$objObject.HtmlIvalidChars.Add('+','%2B');
			$objObject.HtmlIvalidChars.Add('&','%26');
		}
		
		##### Generate The Master UX Configuration Variable
		If (-not ( `
			Get-Variable -Verbose:$false -Debug:$false | `
			Where-Object {"$($_.Name)" -like 'SnsModuleCfg'} `
			-Verbose:$false -Debug:$false `
		))
		{New-Variable -Scope 'Global' -Option 'Constant' -Name 'SnsModuleCfg' -Value ($objObject)};
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objObject';
		
		#==================================================================================
		#endregion Generate Module Configuration Variable
		#==================================================================================
	}
}
Add-SnsSecurityPolicy -Verbose:$false -Debug:$false `
	-WarningAction "$($WarningPreference)" -ErrorAction "$($ErrorActionPreference)";
#####

#==================================================================================
#region Commands
#==================================================================================

##### Import-SnsCredentialFile ====================================================
Function Import-SnsCredentialFile ()
{
<#
.SYNOPSIS      
This CmdLet Import An Encrypted Credential File Convert The Imported Value To PSCredentials Object And Verifies
The Output Existence
.DESCRIPTION      
This CmdLet Import An Encrypted Credential File Convert The Imported Value To PSCredentials Object And Verifies
The Output Existence
In Case The Credential Object Generation Fail The CmdLet Can Log An Event In The Windows Event Viewer Application
Log And Kill The Script Process This Functionality Is Enabled Automatically When EventSource Parameter Is Provided
Simple Throwing Terminating Error Will Keep The PowerShell Process Which Will Prevent The Next Script Instances
From Execution And Any Possible Script Monitoring Will Be Cheated That The Script Is Still Running
The CmdLet Can Import And Decrypt Properly Only Files Created Within The Security Context Of The Account Which
Executes The Function And Only On The Same Machine Where The File Was Created
The CmdLet Have Two Parameter Set:
-- UserAndPass Unlike The Name Here Have To Be Specified The UserName And The Full Absolute UNC Folder Path Where
The Encrypted Password File Resides
-- FullPath Here Have To Be Provided The Full Absolute UNC Path To The Credential File. The CmdLet Will Try To
Generate The UserName From The FileName
.PARAMETER UserName
Specifies The UserName
Parameter Set: UserAndPass
Parameter Alias: User, Usr, UID, ID, Identity, FileName, Name
Parameter Validation: N/A
.PARAMETER FolderPath
Specifies The Full Absolute UNC Folder Path Where The Credential File Resides
Parameter Set: UserAndPass
Parameter Alias: Folder, FolderName, UNCPath, FolderFullName
Parameter Validation: Folder Existence Validation
.PARAMETER FilePath
Specifies The Full Absolute UNC Path To The Credential File
Parameter Set: FullPath
Parameter Alias: FullPath, FileFullPath, FileUNCPath
Parameter Validation: Yes, File Existence And File Name Validation
.PARAMETER EventSource
Specifies The Application Log Event Source To Be Used For The Error Event Logging
Parameter Set: All
Parameter Alias: ScriptName
Parameter Validation: N/A
.INPUTS
Global Variable [System.String]$global:StrScriptName - Contains The Name Of The Script To Be Used As Event Source
.OUTPUTS
[System.Management.Automation.PSCredential] Which Contains The PSCredential
.NOTES
AUTHOR:    Svetoslav Nedyalkov Savov (svesavov@hotmail.com)
COPYRIGHT: (c) 2020 Svetoslav Nedyalkov Savov, all rights reserved.
THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
.EXAMPLE
[System.Management.Automation.PSCredential]$objCredential = Import-SnsCredentialFile `
-UserName 'john.smith@contoso.com' -FolderPath 'C:\';
.EXAMPLE
[System.Management.Automation.PSCredential]$objCredential = Import-SnsCredentialFile `
-FilePath 'C:\john.smith@contoso.com.ini';
#>
[CmdletBinding(PositionalBinding = $false)]
Param(
	[Parameter(Mandatory = $true, ParameterSetName = 'UserAndPass', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
	[Alias('User','Usr','UID','ID','Identity','FileName','Name')]
	[ValidateScript({("$($_)" -eq "$($_.Trim())")})]
	[ValidateNotNullOrEmpty()][System.String[]]$UserName,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'UserAndPass', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true)]
	[Alias('Folder','FolderName','UNCPath','FolderFullName')]
	[ValidateScript({("$($_)" -eq "$($_.Trim())")})]
	[ValidateScript({("$($_)" -like "*\*")})]
	[ValidateScript({(Test-Path -Path "$($_)" -PathType 'Container')})]
	[ValidateNotNullOrEmpty()][System.String]$FolderPath,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'FullPath', `
		ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $false)]
	[Alias('FullPath','FileFullPath','FileUNCPath')]
	[ValidateScript({("$($_)" -eq "$($_.Trim())")})]
	[ValidateScript({("$($_)" -like "*\*.ini")})]
	[ValidateScript({(Test-Path -Path "$($_)" -PathType 'Leaf')})]
	[ValidateNotNullOrEmpty()][System.String[]]$FilePath,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Alias('ScriptName')]
	[ValidateScript({("$($_)" -eq "$($_.Trim())")})]
	[AllowNull()][AllowEmptyString()][System.String]$EventSource
)
	##### Override The Begin Method
	Begin
	{
		Write-Verbose '';
		Write-Verbose "Import-SnsCredentialFile";
		Write-Debug 'Override Begin Method';
		
		##### Initialize New Measure Watch
		[System.Diagnostics.Stopwatch]$objCmdStopWatch = [System.Diagnostics.Stopwatch]::StartNew();
		
		If ("$((Get-FileHash -Path $PSCommandPath -Algorithm 'SHA256' -Verbose:$false -Debug:$false).Hash)" -ne "$($global:SnsModuleCfg.ModuleHash)")
		{Write-Warning 'There Is New Version Of SnsPsModule Module Released. Please Restart The PowerShell Session.'};
		
		Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName)";
		Write-Verbose "ErrorAction: $($ErrorActionPreference)";
		
		##### Initialize The Variables
		[System.Collections.Specialized.OrderedDictionary]$hashTemp = [Ordered]@{};
		[System.String]$strTemp = '';
		[System.Management.Automation.PSCredential]$objCredentials = $null;
		[System.Security.SecureString]$secStrPassword = $null;
	}
	
	##### Override The Process Method
	Process
	{
		Write-Verbose '';
		Write-Debug 'Override Process Method';
		[System.Collections.Specialized.OrderedDictionary]$hashTemp = [Ordered]@{};
		
		#==================================================================================
		#region Generate The FilePath Hash In UserAndPass Set
		#==================================================================================
		
		##### Generate The FilePath Hash In UserAndPass Set
		If ("$($PSCmdlet.ParameterSetName)" -like 'UserAndPass')
		{
			##### Normalize The FilePath Value
			Write-Debug 'Normalize The FilePath Value';
			[System.String]$FolderPath = "$($FolderPath.TrimEnd('\'))\";
			
			##### Process Each UserName
			Write-Debug 'Process Each UserName';
			$UserName | ForEach `
			{
				[System.String]$strTemp = '';
				[System.String]$strTemp = "$($FolderPath)$($_.Replace('\','@@')).ini";
				##### Verify Whether A Credential File For The Specified User Exists
				Write-Debug 'Verify Whether A Credential File For The Specified User Exists';
				If (Test-Path -Path "$($strTemp)" -PathType 'Leaf' -Verbose:$false -Debug:$false)
				{
					##### Generate The Credential FilePath Variable
					Write-Verbose "Generated FilePath: ""$($strTemp)""";
					$hashTemp.Add("$($_)","$($strTemp)");
				}
				Else
				{
					##### Generate The Error String Variable
					[System.String]$strEventMessage = "Generated FilePath ""$($strTemp)"" Does Not Exists";
					Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
					
					##### Write Into The Event Log If The Source Id Provided
					If ((-not -not "$($EventSource)") -and `
						([System.Diagnostics.EventLog]::SourceExists("$($EventSource)")))
					{
						Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
							-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
						#####
						
						##### Wait A Minute And Kill The Script Process
						Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
						Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
					}
					
					##### Reset The Variable
					Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
					Return
				}
			}
		}
		
		#==================================================================================
		#endregion Generate The FilePath Hash In UserAndPass Set
		#==================================================================================
		
		#==================================================================================
		#region Generate The FilePath Hash In FullPath Set
		#==================================================================================
		
		If ("$($PSCmdlet.ParameterSetName)" -like 'FullPath')
		{
			##### Process Each Provided File Path
			Write-Debug 'Process Each Provided File Path';
			$FilePath | ForEach `
			{
				##### Generate The Unformatted UserName
				Write-Debug 'Generate The Unformatted UserName';
				[System.String]$strTemp = '';
				[System.String]$strTemp = `
					"$(($_.Substring(($_.LastIndexOf('\') + 1))).Replace('.ini',''))";
				#####
				
				##### In Case UserName Contains @@ Replace With \
				Write-Debug 'In Case UserName Contains @@ Replace With \';
				If ("$($strTemp)" -like "*@@*")
				{[System.String]$strTemp = $strTemp.Replace('@@','\')};
				
				##### Add The UserName To The UserName Array
				Write-Verbose "Generated UserName: ""$($strTemp)""";
				$hashTemp.Add("$($strTemp)","$($_)");
			}
		}
		
		#==================================================================================
		#endregion Generate The FilePath Hash In FullPath Set
		#==================================================================================
		
		#==================================================================================
		#region Generate The Credentials Object
		#==================================================================================
		
		##### Process Each SnsCredentialFile
		@($hashTemp.Keys) | ForEach `
		{
			##### Verify The Credential File Existence
			[System.Management.Automation.PSCredential]$objCredentials = $null;
			If ((-not -not "$($hashTemp.""$($_)"")") -and `
				(Test-Path -Path "$($hashTemp.""$($_)"")" -PathType 'Leaf' -Verbose:$false -Debug:$false))
			{
				##### Generate The Secure Password Variable
				Write-Verbose "Import FilePath: ""$($hashTemp.""$($_)"")""";
				[System.Security.SecureString]$secStrPassword = $null;
				[System.Security.SecureString]$secStrPassword = Get-Content `
					-Path "$($hashTemp.""$($_)"")" `
					-Verbose:$false -Debug:$false `
					-Encoding 'Unicode' -Force:$true | `
					Select-Object -First 1 -Verbose:$false -Debug:$false | `
					ConvertTo-SecureString -Verbose:$false -Debug:$false;
				#####
				
				##### Generate The PSCredential Variable
				Write-Debug 'Generate The PSCredential Variable';
				[System.Management.Automation.PSCredential]$objCredentials = $null;
				[System.Management.Automation.PSCredential]$objCredentials = `
					New-Object -TypeName 'System.Management.Automation.PSCredential' `
					-ArgumentList @("$($_)",$secStrPassword) -Verbose:$false -Debug:$false;
				#####
			}
			
			##### Verify The Credentials Object Creation
			If ("$($objCredentials.UserName)" -notlike "$($_)")
			{
				##### Generate The Error String Variable
				[System.String]$strEventMessage = "Failed To Generate The Credential Object";
				Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
				
				##### Write Into The Event Log If The Source Is Provided
				If ((-not -not "$($EventSource)") -and `
					([System.Diagnostics.EventLog]::SourceExists("$($EventSource)")))
				{
					Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
						-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
					#####
					
					##### Wait A Minute And Kill The Script Process
					Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
					Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
				}
				
				##### Reset The Variable
				Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
				Return
			}
			Else
			{
				##### Pass The Output Object To The Pipeline
				Write-Debug "Pass Output Object To The Pipeline";
				$PSCmdlet.WriteObject($objCredentials);
			}
		}
		
		#==================================================================================
		#endregion Generate The Credentials Object
		#==================================================================================
	}
	
	##### Override The End Method
	End
	{
		Write-Verbose '';
		Write-Debug 'Override End Method';
		
		##### Reset The Variables
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'secStrPassword';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objCredentials';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strTemp';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'hashTemp';
		
		$PSCmdlet.MyInvocation.BoundParameters | Select-Object -ExpandProperty 'Keys' -Verbose:$false -Debug:$false | ForEach `
		{Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name "$($_)"};
		
		##Stop The StopWatch
		$objCmdStopWatch.Stop();
		Write-Verbose "Command Elapsed: ""$($objCmdStopWatch.ElapsedMilliseconds)"" Milliseconds." ;
		Write-Verbose "End!";
	}
}

##### Export-SnsCredentialFile ====================================================
Function Export-SnsCredentialFile ()
{
<#
.SYNOPSIS
This CmdLet Creates Encrypted Password File
.DESCRIPTION
This CmdLet Creates Encrypted Password File
The CmdLet Is Intended To Prepare Credential File Of Other Accounts Interactively For Further Usage In Scripts
Which Are Executed As A Service
Because The CmdLet Uses Interactive Input A Graphical User Interface Was Developed For Better User Experience
The Produced Credential File Contains Information About When It Was Created And Who Created It
WARNING: The Produced Encrypted Credential Files Can Be Decrypted Only Within The Security Context In Which They
Are Created And Only On The Machine They Are Created
With Other Words Only The Person Who Have Created A File Can Decrypt It On The Same Machine Only
From That Perspective If An Encrypted Password File Is Intended To Be Used By A Script Executed On A Schedule As A
Service, The Person Who Have To Create The File Must Log On Interactively With The Script Service Account To The
Same Machine Where The Script Will Run
.INPUTS
Interactive Input Via Graphical User Interface
.OUTPUTS
Encrypted Secure Password File
.NOTES
AUTHOR:    Svetoslav Nedyalkov Savov (svesavov@hotmail.com)
COPYRIGHT: (c) 2020 Svetoslav Nedyalkov Savov, all rights reserved.
THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
.EXAMPLE
Export-SnsCredentialFile;
#>
[CmdletBinding()]
Param ()
	##### Override The Begin Method
	Begin
	{
		##### Initialize The Variables
		[Void][Reflection.Assembly]::Load('System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089');
		[System.Management.Automation.PSCredential]$objCredentials = $null;
		[System.String]$strEncriptedPass = '';
		[System.Windows.Forms.SaveFileDialog]$objSaveFileDialog = $null;
		[System.String]$strPath = '';
		[System.String]$strVerify = '';
		[System.Boolean]$bolProcess = $true;
		
		#==================================================================================
		#region Credential Dialog
		#==================================================================================
		
		##### Launch Credentials Dialog
		[System.Management.Automation.PSCredential]$objCredentials = $null;
		[System.Management.Automation.PSCredential]$objCredentials = Get-Credential -Verbose:$false -Debug:$false;
		[System.String]$strEncriptedPass = '';
		[System.String]$strEncriptedPass = $objCredentials.Password | ConvertFrom-SecureString -Verbose:$false -Debug:$false;
		
		#==================================================================================
		#endregion Credential Dialog
		#==================================================================================
		
		#==================================================================================
		#region Save File Dialog
		#==================================================================================
		
		##### Launch Save File Dialog
		[System.Windows.Forms.SaveFileDialog]$objSaveFileDialog = $null;
		[System.Windows.Forms.SaveFileDialog]$objSaveFileDialog = New-Object `
			-TypeName 'System.Windows.Forms.SaveFileDialog' -Verbose:$false -Debug:$false;
		$objSaveFileDialog.AddExtension = $true;
		$objSaveFileDialog.DefaultExt = 'ini';
		$objSaveFileDialog.FileName = "$(""$($objCredentials.UserName)"".Replace('\','@@')).ini";
		$objSaveFileDialog.Title = 'Save Secure Password File.';
		$objSaveFileDialog.Filter = "Information Configuration File (*.ini)|*.ini|All files (*.*)|*.*";
		$objSaveFileDialog.ValidateNames = $true;
		$objSaveFileDialog.ShowDialog();
		[System.String]$strPath = '';
		[System.String]$strPath = "$($objSaveFileDialog.FileName)";
		
		#==================================================================================
		#endregion Save File Dialog
		#==================================================================================
		
		#==================================================================================
		#region Export And Verification
		#==================================================================================
		
		##### Export The Credentials
		[System.String]$strVerify = '';
		[System.String]$strVerify = `
		( `
			@(
				$strEncriptedPass,
				"CreatedBy: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)",
				"CreatedOn: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC'))"
			) | 
			Set-Content `
				-Path "$($strPath)" `
				-Encoding 'Unicode' `
				-Force:$true `
				-Confirm:$false `
				-PassThru:$true `
				-Verbose:$false `
				-Debug:$false `
		) | Select-Object -First 1 -Verbose:$false -Debug:$false;
		#####
		
		##### Verify The Export File Existence
		If ($bolProcess)
		{
			If (-not (Test-Path -Path "$($strPath)" -PathType 'Leaf' -Verbose:$false -Debug:$false))
			{[System.Boolean]$bolProcess = $false}
		};
		
		##### Verify The PassThru Output Against The Request
		If ($bolProcess)
		{
			If ("$($strEncriptedPass)" -cne "$($strVerify)")
			{[System.Boolean]$bolProcess = $false}
		};
		
		##### Verify The Actual Content Of The Exported File
		If ($bolProcess)
		{
			[System.String]$strVerify = '';
			[System.String]$strVerify = Get-Content `
				-Path "$($strPath)" `
				-Encoding 'Unicode' `
				-Force:$true `
				-Debug:$true `
				-Verbose:$false | `
				Select-Object -First 1;
			#####
			
			##### Verify The Imported Content Against The Original Encrypted Password
			If ("$($strEncriptedPass)" -cne "$($strVerify)")
			{[System.Boolean]$bolProcess = $false};
		}
		
		#==================================================================================
		#endregion Export And Verification
		#==================================================================================
		
		#==================================================================================
		#region Status Dialog
		#==================================================================================
		
		##### Display The Verification Status
		If ($bolProcess)
		{
			##### Create And Launch The Message Window
			[Void][System.Windows.Forms.MessageBox]::Show( `
				"Password Is Exported In:`r`n$($strPath)",
				'Information',
				[System.Windows.Forms.MessageBoxButtons]::'OK',
				[System.Windows.Forms.MessageBoxIcon]::'Information'
			);
		}
		Else
		{
			##### Create And Launch The Message Window
			[Void][System.Windows.Forms.MessageBox]::Show( `
				"Failed To Export, Or The Export Contains Errors:`r`n$($strPath)",
				'Error',
				[System.Windows.Forms.MessageBoxButtons]::'OK',
				[System.Windows.Forms.MessageBoxIcon]::'Error'
			);
		}
		
		#==================================================================================
		#endregion Status Dialog
		#==================================================================================
		
		##### Reset The Variables
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'bolProcess';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strVerify';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strPath';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objSaveFileDialog';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEncriptedPass';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objCredentials';
		
		Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
	}
}

##### Export-SnsCredentialFileAsService ===========================================
Function Export-SnsCredentialFileAsService ()
{
<#
.SYNOPSIS
This CmdLet Creates Encrypted Password File
.DESCRIPTION
This CmdLet Creates Encrypted Password File
The CmdLet Is Intended To Prepare Credential File Of Other Accounts When It Is Run As A Service
While The Password Is Encrypted Securely And Cannot Be Decrypted By Other Accounts Than The One Who Encrypted It,
The Process For Creation Of The Encrypted File Is Not The Most Secure One
This CmdLet Is Used Mainly When Automatic Scripts Will Need Other Credentials And Those Scripts Will Be Executed
With Service Accounts That Have Interactive Logon Denied
Active Logon Denied Makes Impossible The Usage Of The Export-SnsCredentialFile CmdLet Who Require The Credentials
Interactively And The Password Is Not Provided In Clear Text
The Produced Credential File Contains Information About When It Was Created And Who Created It
WARNING: The Produced Encrypted Credential Files Can Be Decrypted Only Within The Security Context In Which They
Are Created And Only On The Machine They Are Created
With Other Words Only The Person Who Have Created A File Can Decrypt It On The Same Machine Only.
WARNING: In Order To Create The Encrypted Password File This Function Will Require The Password To Be Provided As
Clear Text To CmdLet Parameter
There Is Increased Risk The Password To Be Intercepted In The Process Of Providing It To The CmdLet.
.PARAMETER UserName
Specifies The UserName Of The Account Which Have To Be Encrypted
Parameter Set: N/A
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Password
Specifies The Password Of The Account Which Have To Be Encrypted
Parameter Set: N/A
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER FolderPath
Specifies The Full Absolute UNC Folder Path Where The Credential File Have To Be Exported
Parameter Set: N/A
Parameter Alias: N/A
Parameter Validation: Folder Existence Validation
.INPUTS
The CmdLet Does Not Support Pipeline Input
.OUTPUTS
Encrypted Secure Password File
.NOTES
AUTHOR:    Svetoslav Nedyalkov Savov (svesavov@hotmail.com)
COPYRIGHT: (c) 2020 Svetoslav Nedyalkov Savov, all rights reserved.
THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
.EXAMPLE
Export-SnsCredentialFileAsService -UserName 'Contoso\User01' -Password 'Pa$$w0rd' -FolderPath 'C:';
#>
[CmdletBinding(PositionalBinding = $false)]
Param (
	[Parameter(Mandatory = $true, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateScript({("$($_)" -eq "$($_.Trim())")})]
	[ValidateNotNullOrEmpty()][System.String]$UserName,
	
	[Parameter(Mandatory = $true, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateScript({("$($_)" -eq "$($_.Trim())")})]
	[ValidateNotNullOrEmpty()][System.String]$Password,
	
	[Parameter(Mandatory = $true, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateScript({("$($_)" -eq "$($_.Trim())")})]
	[ValidateScript({("$($_)" -like "*\*")})]
	[ValidateScript({Test-Path -Path "$($_)" -PathType 'Container'})]
	[System.String]$FolderPath = 'C:\Users\ssavov\Desktop'
)
	##### Override The Begin Method
	Begin
	{
		##### Initialize The Variables
		[System.Security.SecureString]$strSecurePass = $null;
		[System.Management.Automation.PSCredential]$objCredentials = $null;
		[System.String]$strEncryptedPass = '';
		[System.String]$strPath = '';
		[System.String]$strVerify = '';
		[System.Boolean]$bolProcess = $true;
		
		#==================================================================================
		#region Credential Processing
		#==================================================================================
		
		##### Generate The Secure Password
		[System.Security.SecureString]$strSecurePass = $null;
		[System.Security.SecureString]$strSecurePass = "$($Password)" | `
			ConvertTo-SecureString `
				-AsPlainText:$true `
				-Force:$true `
				-Debug:$false `
				-Verbose:$false;
		#####
		
		##### Generate The Credentials
		[System.Management.Automation.PSCredential]$objCredentials = $null;
		[System.Management.Automation.PSCredential]$objCredentials = `
			New-Object `
				-TypeName 'System.Management.Automation.PSCredential' `
				-ArgumentList ("$($UserName)", $strSecurePass) `
				-Debug:$false `
				-Verbose:$false;
		#####
		
		##### Convert The Password To Encrypted Exportable Format
		[System.String]$strEncryptedPass = '';
		[System.String]$strEncryptedPass = `
			$objCredentials.Password | ConvertFrom-SecureString -Verbose:$false -Debug:$false;
		#####
		
		#==================================================================================
		#endregion Credential Processing
		#==================================================================================
		
		#==================================================================================
		#region Export And Verification
		#==================================================================================
		
		##### Process The FolderPath Input
		[System.String]$strPath = "$($FolderPath.Trim('\'))\";
		[System.String]$strPath = "$($strPath)$(""$($objCredentials.UserName)"".Replace('\','@@')).ini";
		
		##### Export The Credentials
		[System.String]$strVerify = '';
		[System.String]$strVerify = `
		( `
			@(
				$strEncryptedPass,
				"CreatedBy: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)",
				"CreatedOn: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC'))"
			) | `
			Set-Content `
				-Path "$($strPath)" `
				-Encoding 'Unicode' `
				-Force:$true `
				-Confirm:$false `
				-PassThru:$true `
				-Debug:$false `
				-Verbose:$false `
		) | Select-Object -First 1 -Verbose:$false -Debug:$false;
		#####
		
		##### Verify The Export File Existence
		If ($bolProcess)
		{
			##### Verify The Exported File Existence
			If (-not (Test-Path -Path "$($strPath)" -PathType 'Leaf'))
			{[System.Boolean]$bolProcess = $false;};
		};
		
		##### Verify The PassThru Output Against The Request
		If ($bolProcess)
		{
			##### Verify The Reverted Value From The PassThru Export Against The Original Encrypted Password
			If ("$($strEncryptedPass)" -cne "$($strVerify)")
			{[System.Boolean]$bolProcess = $false;};
		};
		
		##### Verify The Actual Content Of The Exported File
		If ($bolProcess)
		{
			##### Import The Encrypted Password File
			[System.String]$strVerify = '';
			[System.String]$strVerify = Get-Content `
				-Path "$($strPath)" `
				-Encoding 'Unicode' `
				-Force:$true `
				-Debug:$true `
				-Verbose:$false | `
				Select-Object -First 1 -Verbose:$false -Debug:$false;
			#####
			
			##### Verify The Imported Content Against The Original Encrypted Password
			If ("$($strEncryptedPass)" -cne "$($strVerify)")
			{[System.Boolean]$bolProcess = $false;};
		}
		
		##### Export A Confirmation File
		If ($bolProcess)
		{
			##### Process The FolderPath Input
			[System.String]$strPath = "$($FolderPath.Trim('\'))\";
			[System.String]$strPath = "$($strPath)!!! Password_Export_OK !!!.txt";
			
			##### Create The File
			'' | Set-Content `
				-Path "$($strPath)" `
				-Encoding 'Unicode' `
				-Force:$true `
				-Confirm:$false `
				-PassThru:$false `
				-Debug:$false `
				-Verbose:$false;
			#####
		}
		
		#==================================================================================
		#endregion Export And Verification
		#==================================================================================
		
		##### Reset The Variables
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'bolProcess';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strVerify';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strPath';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEncryptedPass';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objCredentials';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strSecurePass';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'FolderPath';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'Password';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'UserName';
		
		Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
	}
}

##### Convert-SnsObjectToSQLInsertQuery ===========================================
Function Convert-SnsObjectToSQLInsertQuery ()
{
<#
.SYNOPSIS
This Cmdlet Convert A Specified Custom Object Or Import Custom Object To A SQL Insert Query And Either Revert The
SQL Query As String Collection Or Actually Insert The Objects Into The Specified SQL DataBase If All The
Prerequisites Are Met.
.DESCRIPTION
This Cmdlet Convert A Specified Custom Object Or Import Custom Object To A SQL Insert Query And Either Revert The
SQL Query As String Collection Or Actually Insert The Objects Into The Specified SQL DataBase If All The
Prerequisites Are Met.
The CmdLet Have Two Parameter Sets, Related With The Way That The Input Objects Are Provided:
-- InputObject Parameter Set Is Used Whenever Are Provided Custom Objects As Input To The CmdLet. The InputObjects
Can Be Generated With The Script That Is Calling The CmdLet Or Any Other Way. The Input Object Must Have String
Property Values Or Values Which Are Convertible To String. Multivalued String Properties Or Multivalued Properties
Which Can Be Converted To A String Can Be Provided, However They Will Be Converted To A Single String Using .NET
Sytem.String Join Method. For Separator Will Be Used The Value Of The CmdLet SqlDelimiter Parameter. Whenever The
Parameter Is Not Specified Will Be Used Tilde (~) Character.
-- FileImport Parameter Set Is Used Whenever The InputObjects Have To Be Imported From A .CSV File. For That
Purpose The CmdLet Calls Internally Import-Csv CmdLet. In That Way Using Single CmdLet Can Be Imported .CSV Files,
Converted To SQL Insert Queries And Actually Inserted Into The Required DataBase. All Restrictions, Advantages And
Specifics Of Import-Csv CmdLet Applies Here As Well.
The CmdLet Can Actually Insert The Generated SQL Queries Into SQL DataBase. For That Purpose The User Have To
Specify The SQL Server And The Way The SQL Connection Is Authenticated. The DatabaseName And DatabaseTable
Parameters Are Required Parameters In All Parameter Sets Because They Are Used Within The SQL Queries. With
Providing The SQL Server And The Authentication Mechanism The CmdLet Actually Inserts The Queries.
The Ways That The CmdLet Can Use For SQL Authentication Are Via Providing Of Credential PowerShell Object, Via
Providing UserName And Password In Clear Text As Parameters, Or Using The Current Session Of The User Who Executes
The CmdLet. For That Purpose The Actual Authentication Used Depends Of The Combination Of Parameters Provided To
The CmdLet. When Credentials Parameter Is Used The Authentication Is Performed Using It, The Rest Of The
Authentication Parameters Can Be Not Specified In That Case Whenever They Are Specified Will Be Ignored.
When No Credentials Object Is Provided And Both UserName And Password Are Provided In Clear Text As Parameter They
Will Be Used. The Connection From .NET SQL Client To The SQL Server Is Encrypted, Therefore Even Provided In Clear
Text To The CmdLet The Credentials Cannot Be Intercepted.
When No Credential Object Is Provided And When No UserName And Password Are Provided Or Incompletely Provided, The
CmdLet Will Connect To The SQL Server Using The Single Sign On And The Session Of The Currently Logged User. This
Is The Most Appropriate And Recommended When The CmdLet Is Used In Scripts Run By A Person On Run Via Scheduled
Task By User Who Have The Needed SQL Access Rights.
Whenever Actual Insert Into The SQL DataBase Is Used The CmdLet Will Retrieve The Actual Column Names From The
Destination SQL Table, And Will Automatically Filter Out Any Auto Increment Columns. Afterward It Will Select Only
The Properties From The InputObject That Match The Column Names. In Case The Column Names Does Not Match The
Corresponding SQL Columns Will Have NULL Value In The Generated SQL Queries. Going One Step Further The CmdLet
Will Verify Whether All Not Nullable Columns Have Values. From That Perspective If The Input Object Properties Are
Misspelled At Least The Mandatory Columns Will Be Verified.
In Case Actual Insert Is Not Used, The CmdLet Have No SQL Connection Information And Cannot Retrieve The Actual
Columns Of The Table. In That Case The SQL Queries Are Generated As Is Using The InputObject Properties. It Is
User Responsibility If The Property Names Are Misspelled.
.PARAMETER InputObject
Specifies An Object Collection Which Have To Be Converted To SQL Queries.
Parameter Set: InputObject
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Path
Specifies The Path To The CSV File To Import.
Parameter Set: FileImport
Parameter Alias: N/A
Parameter Validation: Yes, Using Path Validation
.PARAMETER Delimiter
Specifies The Delimiter That Separates The Property Values In The CSV File. The Default Is A Comma (,). Enter
A Character, Such As A Colon (:). To Specify A Semicolon (;), Enclose It In Quotation Marks.
If You Specify A Character Other Than The Actual String Delimiter In The File, Import-Csv Cannot Create
Objects From The CSV Strings. Instead, It Returns The Strings.
Parameter Set: FileImport
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Encoding
Specifies The Type Of Character Encoding That Was Used In The CSV File. The Acceptable Values For This
Parameter Are:
- Unicode
- UTF7
- UTF8
- ASCII
- UTF32
- BigEndianUnicode
- Default
- OEM
The default is ASCII.
Parameter Set: FileImport
Parameter Alias: N/A
Parameter Validation: Validation Using Enumeration
.PARAMETER Header
Specifies An Alternate Column Header Row For The Imported File. The Column Header Determines The Names Of The
Properties Of The Object That Import-Csv Creates.
Enter A Comma-Separated List Of The Column Headers. Enclose Each Item In Quotation Marks (Single Or Double).
Do Not Enclose The Header String In Quotation Marks. If You Enter Fewer Column Headers Than There Are Columns,
The Remaining Columns Will Have No Header. If You Enter More Headers Than There Are Columns, The Extra Headers
Are Ignored.
When Using The Header Parameter, Delete The Original Header Row From The CSV File. Otherwise, Import-Csv
Creates An Extra Object From The Items In The Header Row.
Parameter Set: FileImport
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Computer
Specifies A SQL Server And SQL Instance In Format:
<DataBase Server>
<DataBase Server>\<DataBase Instance>
<DataBase Server>,<Port Number>
When The Parameter Is Not Provided The CmdLet Will Skip The Input Objects Verifications And Will Not Insert
The Generated Queries Into The DataBase. Instead Will Revert The Generated SQL Queries As Output String
Collection.
Parameter Set: All
Parameter Alias: ComputerName, SqlServer, SqlServerName, DbServer, DbServerName, Server, ServerName
Parameter Validation: Yes, Using DNS Resolution
.PARAMETER DatabaseName
Specifies A DataBase Name
Parameter Set: All
Parameter Alias: DbName, DataBase, SqlDatabaseName, SqlDbName, SqlDb
Parameter Validation: N/A
.PARAMETER DatabaseTable
Specifies A DataBase Table Name Used To Insert In The Objects
The CmdLet Will Expect The Full Table Name Along With The DataBase Schema
For Example [<dbo>].[<TableName>]
The Square Brackets Are Not Required They Are Characters Used To Close The Names Whenever They Contain Spaces
Parameter Set: All
Parameter Alias: TableName, Table, SqlTableName
Parameter Validation: Yes Using Syntax Validation
.PARAMETER UserName
Specifies A UserName In Clear Text
Parameter Set: All
Parameter Alias: SqlUser, User, Usr, UID, DbUser
Parameter Validation: N/A
.PARAMETER Password
Specifies A Password In Clear Text
Parameter Set: All
Parameter Alias: SqlPassword, DbPassword, pwd, Pass
Parameter Validation: N/A
.PARAMETER Credentials
Specifies A [System.Management.Automation.PSCredential] Object
Parameter Set: All
Parameter Alias: SqlCredentials, SqlCred, Cred
Parameter Validation: N/A
.PARAMETER SqlDelimiter
Specifies The Character Used To Join A Collection Of Strings In Multivalued Object Property To A String Value
Required For SQL Cell Object.
Parameter Set: InputObject
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER PassThru
Specifies That The CmdLet Have To Revert A Verification Boolean In Case Of Actual SQL Insert.
If No SQL Insert Is Performed The Parameter Have No Impact.
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.INPUTS
Pipeline Input -InputObject [System.Object[]]
.OUTPUTS
Pipeline Output [System.String[]] Which Contains The Generated SQL Queries
.NOTES
AUTHOR:    Svetoslav Nedyalkov Savov (svesavov@hotmail.com)
COPYRIGHT: (c) 2020 Svetoslav Nedyalkov Savov, all rights reserved.
THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
.EXAMPLE
[System.String[]]$arrSqlQry = Convert-SnsObjectToSQLInsertQuery -InputObject $arrCollection `
-DatabaseName "MyDataBase" -DatabaseTable "[dbo].[MyTable]" -SqlDelimiter '~';
.EXAMPLE
Convert-SnsObjectToSQLInsertQuery -Path 'C:\Test.csv' -Delimiter '~' -Encoding 'Unicode' `
-Computer 'computer.contoso.com' -DatabaseName "MyDataBase" -DatabaseTable "[dbo].[MyTable]" `
-UserName "JohnSmith" -Password "Pa$$w0rd";
#>
[CmdletBinding(PositionalBinding = $false, DefaultParameterSetName = "InputObject")]
Param(
	[Parameter(Mandatory = $true, ParameterSetName = 'InputObject', `
		ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $false)]
	[ValidateCount(1, [System.Int32]::MaxValue)]
	[ValidateNotNullOrEmpty()][System.Object[]]$InputObject,
	
	[Parameter(Mandatory = $false, ParameterSetName = 'InputObject', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateNotNullOrEmpty()][System.Char]$SqlDelimiter = '~',
	
	[Parameter(Mandatory = $true, ParameterSetName = 'FileImport', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateScript({("$($_)" -eq "$($_.Trim())")})]
	[ValidateScript({Test-Path -Path "$($_)" -PathType 'Leaf'})]
	[ValidateNotNullOrEmpty()][System.String]$Path,
	
	[Parameter(Mandatory = $false, ParameterSetName = 'FileImport', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateNotNullOrEmpty()][System.Char]$Delimiter = ',',
	
	[Parameter(Mandatory = $false, ParameterSetName = 'FileImport', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateSet('Unicode', 'UTF7', 'UTF8', 'ASCII', 'UTF32', 'BigEndianUnicode', 'Default', 'OEM')]
	[ValidateNotNullOrEmpty()][System.String]$Encoding = 'ASCII',
	
	[Parameter(Mandatory = $false, ParameterSetName = 'FileImport', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateCount(2, [System.Int32]::MaxValue)]
	[ValidateScript({("$($_)" -eq "$($_.Trim())")})]
	[ValidateNotNullOrEmpty()][System.String[]]$Header,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Alias('ComputerName','SqlServer','SqlServerName','DbServer','DbServerName','Server','ServerName')]
	[ValidateScript({("$($_)" -eq "$($_.Trim())")})]
	[ValidateScript({("$([Net.DNS]::GetHostEntry(""$(((($_.Split('\'))[0]).Split(','))[0])"").HostName)" `
		-like "$(((($_.Split('\'))[0]).Split(','))[0])")})]
	[ValidateNotNullOrEmpty()][System.String]$Computer,
	
	[Parameter(Mandatory = $true, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Alias('DbName','DataBase','SqlDatabaseName','SqlDbName','SqlDb')]
	[ValidateScript({("$($_)" -eq "$($_.Trim())")})]
	[ValidateNotNullOrEmpty()][System.String]$DatabaseName,
	
	[Parameter(Mandatory = $true, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Alias('TableName','Table','SqlTableName')]
	[ValidateScript({("$($_)" -eq "$($_.Trim())")})]
	[ValidateScript({"$($_)" -match '^\[?\w{1,10}\]?\.\[?\w{1,}\]?$'})]
	[ValidateNotNullOrEmpty()][System.String]$DatabaseTable,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Alias('SqlUser','User','Usr','UID','DbUser')]
	[ValidateScript({("$($_)" -eq "$($_.Trim())")})]
	[ValidateNotNullOrEmpty()][System.String]$UserName,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Alias('SqlPassword','DbPassword','pwd','Pass')]
	[ValidateScript({("$($_)" -eq "$($_.Trim())")})]
	[ValidateNotNullOrEmpty()][System.String]$Password,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Alias('SqlCredentials','SqlCred','Cred')]
	[ValidateNotNullOrEmpty()][System.Management.Automation.PSCredential]$Credentials,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Switch]$PassThru
)
	##### Override The Begin Method
	Begin
	{
		Write-Verbose '';
		Write-Verbose "Convert-SnsObjectToSQLInsertQuery";
		Write-Debug 'Override Begin Method';
		
		##### Initialize New Measure Watch
		[System.Diagnostics.Stopwatch]$objCmdStopWatch = [System.Diagnostics.Stopwatch]::StartNew();
		
		If ("$((Get-FileHash -Path $PSCommandPath -Algorithm 'SHA256' -Verbose:$false -Debug:$false).Hash)" -ne "$($global:SnsModuleCfg.ModuleHash)")
		{Write-Warning 'There Is New Version Of SnsPsModule Module Released. Please Restart The PowerShell Session.'};
		
		Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName)`r`n";
		
		##### Initialize The Variables
		[System.Collections.Hashtable]$hshSplatting = @{};
		[System.String]$strSqlQry = '';
		[System.String[]]$arrProperties = @();
		[System.String]$strProp = '';
		[System.UInt32]$intIndex = 0;
		[System.String]$arrQryes = @();
		[System.Data.DataRow[]]$arrRows = @();
		[System.Object[]]$arrVerif = @();
		[System.UInt32]$intInd = 0;
		[System.Boolean]$bolOut = $true;
		
		#==================================================================================
		#region Import A CSV File
		#==================================================================================
		
		##### Verify The Parameter Set
		Write-Debug 'Verify The Parameter Set';
		If ("$($PSCmdlet.ParameterSetName)" -eq 'FileImport')
		{
			##### Generate The Splatting HashTable
			Write-Debug 'Generate The Splatting HashTable';
			[System.Collections.Hashtable]$hshSplatting = @{};
			$hshSplatting.Add('Path', "$($Path)");
			$hshSplatting.Add('Delimiter', $Delimiter);
			$hshSplatting.Add('Encoding', "$($Encoding)");
			$hshSplatting.Add('Verbose', $false);
			$hshSplatting.Add('Debug', $false);
			If ($Header.Count -gt 0) {$hshSplatting.Add('Header', $Header);};
			
			##### Import The Provided CSV File
			Write-Debug 'Import The Provided CSV File';
			[System.Object[]]$InputObject = @();
			[System.Object[]]$InputObject = Import-Csv @hshSplatting;
			
			##### Verify The CSV File Import
			Write-Debug 'Verify The CSV File Import';
			If (($InputObject.Count -le 0) -or (($InputObject[0] | Get-Member -MemberType "*Property" -Verbose:$false -Debug:$false).Count -eq 1))
			{
				Write-Error "Failed To Read ""$($Path)""" -ErrorAction 'Continue';
				Return
			};
			Write-Verbose "Imported ""$($Path)""`r`n";
		}
		
		#==================================================================================
		#endregion Import A CSV File
		#==================================================================================
		
		#==================================================================================
		#region Generate The Object Properties / Column Names
		#==================================================================================
		
		##### Verify Whether The DataBase Server Is Provided
		Write-Debug 'Verify Whether The DataBase Server Is Provided';
		If (-not -not "$($Computer)")
		{
			##### Generate Columns Retrieval SQL Query
			##### Auto-Increment Columns Will Be Automatically Excluded
			Write-Debug 'Generate Columns Retrieval SQL Query';
			[System.String]$strSqlQry = '';
			[System.String]$strSqlQry += "SELECT [COLUMN_NAME], [IS_NULLABLE]`r`n";
			[System.String]$strSqlQry += "FROM [INFORMATION_SCHEMA].[COLUMNS]`r`n";
			[System.String]$strSqlQry += "WHERE`r`n";
			[System.String]$strSqlQry += "`t[TABLE_CATALOG] = '$($DatabaseName)'`r`n";
			[System.String]$strSqlQry += "`tAND`r`n";
			[System.String]$strSqlQry += "`t[TABLE_SCHEMA] = '";
			[System.String]$strSqlQry += "$($DatabaseTable.Split('.')[0].Replace('[', '').Replace(']', ''))'`r`n";
			[System.String]$strSqlQry += "`tAND`r`n";
			[System.String]$strSqlQry += "`t[TABLE_NAME] = '";
			[System.String]$strSqlQry += "$($DatabaseTable.Split('.')[1].Replace('[', '').Replace(']', ''))'`r`n";
			[System.String]$strSqlQry += "`tAND`r`n";
			[System.String]$strSqlQry += "`tNOT [COLUMN_NAME] IN`r`n";
			[System.String]$strSqlQry += "`t(`r`n";
			[System.String]$strSqlQry += "`t`tSELECT [name]`r`n";
			[System.String]$strSqlQry += "`t`tFROM [sys].[identity_columns]`r`n";
			[System.String]$strSqlQry += "`t`tWHERE [object_id] = OBJECT_ID('";
			[System.String]$strSqlQry += "$($DatabaseTable.Split('.')[1].Replace('[', '').Replace(']', ''))')`r`n";
			[System.String]$strSqlQry += "`t);";
			
			##### Generate The Splatting HashTable
			Write-Debug 'Generate The Splatting HashTable';
			[System.Collections.Hashtable]$hshSplatting = @{};
			$hshSplatting.Add('Query', "$($strSqlQry)");
			$hshSplatting.Add('Computer', "$($Computer)");
			$hshSplatting.Add('DatabaseName', "$($DataBaseName)");
			$hshSplatting.Add('Verbose', $false);
			$hshSplatting.Add('Debug', $false);
			If (-not -not "$($Credentials.UserName)")
			{
				##### Credentials Are Provided
				Write-Verbose "Connecting To ""$($DataBaseName)"" Using Provided Credential Object`r`n";
				$hshSplatting.Add('Credentials', $Credentials);
			}
			ElseIf ((-not -not "$($UserName)") -and (-not -not "$($Password)"))
			{
				##### UserName And Password Are Provided
				Write-Verbose "Connecting To ""$($DataBaseName)"" Using Provided UserName And Password`r`n";
				$hshSplatting.Add('UserName', $UserName);
				$hshSplatting.Add('Password', $Password);
			}
			Else
			{
				##### Neither Credential Object Nor UserName And Password Are Provided
				##### Using Current User Session
				Write-Verbose "Connecting To ""$($DataBaseName)"" Using Current User Session`r`n";
				$hshSplatting.Add('UseCurrentLogOnSession', $true);
			}
			
			##### Query The DataBase About The Table Columns
			Write-Debug 'Query The DataBase About The Table Columns';
			[System.Object[]]$arrProperties = @();
			[System.Object[]]$arrProperties = Invoke-SnsSQLQuery @hshSplatting | `
				Select-Object `
				-ExpandProperty 'Tables' `
				-Verbose:$false -Debug:$false `
				-ErrorAction 'SilentlyContinue' `
				-WarningAction 'SilentlyContinue' `
				-First 1 | `
				Select-Object `
				-ExpandProperty 'Rows' `
				-Verbose:$false -Debug:$false `
				-ErrorAction 'SilentlyContinue' `
				-WarningAction 'SilentlyContinue' | `
				Select-Object -Property `
				@(
					@{'n' = 'Name'; 'e' = {"$($_.'COLUMN_NAME')"}};
					@{'n' = 'Mandatory'; 'e' = {"$($_.'IS_NULLABLE')" -eq 'NO'}};
				) `
				-Verbose:$false -Debug:$false;
			#####
			
			##### Verify The Columns Retrieval
			Write-Debug 'Verify The Columns Retrieval';
			If ($arrProperties.Count -le 0)
			{
				Write-Error "Failed To Get Column Names From ""$($DatabaseTable)""" -ErrorAction 'Continue';
				Return
			}
			Else
			{
				##### Process Each Not Nullable Column
				Write-Debug 'Process Each Not Nullable Column';
				[System.String]$strProp = '';
				ForEach ($strProp in [System.String[]]@(($arrProperties | Where-Object {$_.Mandatory} -Verbose:$false -Debug:$false).Name))
				{
					##### Verify Whether The Current Not Nullable Column Have Value
					Write-Debug 'Verify Whether The Current Not Nullable Column Have Value';
					If (-not -not ($InputObject."$($strProp)" | Where-Object {-not "$($_)"} -Verbose:$false -Debug:$false))
					{
						Write-Error "Property ""$($strProp)"" Does Not Match The Criteria" -ErrorAction 'Continue';
						Return
					};
				}
				
				##### Convert The Properties Array
				Write-Debug 'Convert The Properties Array';
				[System.String[]]$arrProperties = $arrProperties | Select-Object -ExpandProperty 'Name' -Verbose:$false -Debug:$false;
				
				Write-Verbose "Column Names Which Will Be Used For Object To Query Conversion:";
				$arrProperties | ForEach {Write-Verbose "$($_)"};
				Write-Verbose '';
			}
		}
		Else
		{
			##### Retrieve The Properties Of The Input Object
			Write-Verbose "Using InputObject Properties Without Verification`r`n";
			[System.String[]]$arrProperties = @();
			[System.String[]]$arrProperties = $InputObject[0] | `
				Get-Member -MemberType "*Property" `
				-Verbose:$false -Debug:$false `
				-ErrorAction 'SilentlyContinue' `
				-WarningAction 'SilentlyContinue' | `
				Select-Object -ExpandProperty 'Name' `
				-Verbose:$false -Debug:$false `
				-ErrorAction 'SilentlyContinue' `
				-WarningAction 'SilentlyContinue';
			#####
		}
		
		##### Verify The Properties Collection Generation
		If ($arrProperties.Count -le 0)
		{
			Write-Error 'Failed To Generate The Object Properties' -ErrorAction 'Continue';
			Return
		};
		
		#==================================================================================
		#endregion Generate The Object Properties / Column Names
		#==================================================================================
	}
	
	##### Override The Process Method
	Process
	{
		Write-Verbose '';
		Write-Debug 'Override Process Method';
		
		##### Convert Each Object To SQL Query
		Write-Debug 'Convert Each Object To SQL Query';
		[System.UInt32]$intIndex = 0;
		For ([System.UInt32]$intIndex = 0; $intIndex -lt $InputObject.Count; $intIndex++)
		{
			If ($InputObject.Count -gt 5)
			{
				Write-Progress -Activity 'Convert-SnsObjectToSQLInsertQuery' -Id 1 `
					-PercentComplete (($intIndex / $InputObject.Count) * 100) `
					-Verbose:$false -Debug:$false;
				#####
			}
			
			#==================================================================================
			#region Convert The Current Object To SQL Query
			#==================================================================================
			
			##### Convert The Current Object To SQL Query
			Write-Debug 'Convert The Current Object To SQL Query';
			[System.String]$strSqlQry = '';
			[System.String]$strSqlQry += "INSERT INTO [$($DatabaseName)].$($DatabaseTable)`r`n";
			[System.String]$strSqlQry += "(`r`n";
			
			##### Process All Property Names
			Write-Debug 'Process All Property Names';
			[System.String]$strProp = '';
			ForEach ($strProp in $arrProperties)
			{[System.String]$strSqlQry += "`t[$($strProp)],`r`n";};
			[System.String]$strSqlQry = "$($strSqlQry.TrimEnd(""`r`n"").TrimEnd(','))`r`n";
			[System.String]$strSqlQry += ")`r`n";
			
			##### Process All Property Values
			Write-Debug 'Process All Property Values';
			[System.String]$strSqlQry += "VALUES`r`n";
			[System.String]$strSqlQry += "(`r`n";
			[System.String]$strProp = '';
			ForEach ($strProp in $arrProperties)
			{
				##### Verify Whether The Current Property Have Value
				If ( `
					(-not -not $InputObject[$intIndex]."$($strProp)") `
					-and `
					("$($InputObject[$intIndex].""$($strProp)"")" -ne 'NULL') `
				)
				{
					##### There Is A Value Add It To SQL Query
					[System.String]$strSqlQry += "`t'$(""$( `
						[System.String]::Join($SqlDelimiter, $InputObject[$intIndex].""$($strProp)"") `
						)"".Replace(""'"", ""''""))',`r`n";
					#####
				}
				Else
				{
					##### There Is No Value Add NULL As Value (It Is Mandatory)
					[System.String]$strSqlQry += "`tNULL,`r`n";
				}
			}
			[System.String]$strSqlQry = "$($strSqlQry.TrimEnd(""`r`n"").TrimEnd(','))`r`n";
			[System.String]$strSqlQry += ");`r`n";
			
			#==================================================================================
			#endregion Convert The Current Object To SQL Query
			#==================================================================================
			
			#==================================================================================
			#region Process The Generated Query
			#==================================================================================
			
			##### Verify Whether The SQL Server Is Provided
			Write-Debug 'Verify Whether The SQL Server Is Provided';
			If (-not -not "$($Computer)")
			{
				##### Add The Generated SQL Query To The Collection For Inserting
				[System.String]$arrQryes += $strSqlQry;
			}
			Else
			{
				##### Pass The Output Object To The Pipeline
				Write-Debug "Pass Output Object To The Pipeline";
				$PSCmdlet.WriteObject($strSqlQry);
			}
			
			Write-Verbose "$($strSqlQry)`r`n";
			
			#==================================================================================
			#endregion Process The Generated Query
			#==================================================================================
		}
		
		##### Close The Progress Bar
		Write-Debug 'Close The Progress Bar';
		If ($InputObject.Count -gt 5)
		{
			Write-Progress -Activity 'Convert-SnsObjectToSQLInsertQuery' -Id 1 -PercentComplete 100 -Verbose:$false -Debug:$false;
			Write-Progress -Activity 'Convert-SnsObjectToSQLInsertQuery' -Id 1 -Completed -Verbose:$false -Debug:$false;
		}
		
		##### Check Whether Queries Are Generated And SQL Server Is Provided
		Write-Debug 'Check Whether Queries Are Generated And SQL Server Is Provided';
		If (($arrQryes.Count -gt 0) -and (-not -not "$($Computer)"))
		{
			#==================================================================================
			#region Insert The Generated SQL Queries Into The SQL DataBase
			#==================================================================================
			
			##### Generate The Splatting HashTable
			Write-Debug 'Generate The Splatting HashTable';
			[System.Collections.Hashtable]$hshSplatting = @{};
			$hshSplatting.Add('Query', $arrQryes);
			$hshSplatting.Add('Computer', "$($Computer)");
			$hshSplatting.Add('DatabaseName', "$($DataBaseName)");
			$hshSplatting.Add('Verbose', $false);
			$hshSplatting.Add('Debug', $false);
			If (-not -not "$($Credentials.UserName)")
			{
				##### Credentials Are Provided
				Write-Verbose "Connecting To ""$($DataBaseName)"" Using Provided Credential Object`r`n";
				$hshSplatting.Add('Credentials', $Credentials);
			}
			ElseIf ((-not -not "$($UserName)") -and (-not -not "$($Password)"))
			{
				##### UserName And Password Are Provided
				Write-Verbose "Connecting To ""$($DataBaseName)"" Using Provided UserName And Password`r`n";
				$hshSplatting.Add('UserName', $UserName);
				$hshSplatting.Add('Password', $Password);
			}
			Else
			{
				##### Neither Credential Object Nor UserName And Password Are Provided
				##### Using Current User Session
				Write-Verbose "Connecting To ""$($DataBaseName)"" Using Current User Session`r`n";
				$hshSplatting.Add('UseCurrentLogOnSession', $true);
			}
			
			##### Insert Into The DataBase Table The Generated Queries
			Write-Debug 'Insert Into The DataBase Table The Generated Queries';
			Invoke-SnsSQLQuery @hshSplatting | Out-Null;
			
			#==================================================================================
			#endregion Insert The Generated SQL Queries Into The SQL DataBase
			#==================================================================================
			
			#==================================================================================
			#region Verify The Insert
			#==================================================================================
			
			##### Check Whether Verification Is Requested
			If ($PassThru.IsPresent)
			{
				##### Generate The InputObject Properties
				Write-Debug 'Generate The InputObject Properties';
				[System.String[]]$arrProperties = @();
				[System.String[]]$arrProperties = $InputObject[0] | `
					Get-Member -MemberType "*Property" `
					-Verbose:$false -Debug:$false `
					-ErrorAction 'SilentlyContinue' `
					-WarningAction 'SilentlyContinue' | `
					Select-Object -ExpandProperty 'Name' `
					-Verbose:$false -Debug:$false `
					-ErrorAction 'SilentlyContinue' `
					-WarningAction 'SilentlyContinue';
				#####
				
				##### Generate The Splatting HashTable
				Write-Debug 'Generate The Splatting HashTable';
				[System.Collections.Hashtable]$hshSplatting = @{};
				$hshSplatting.Add('Query', "SELECT * FROM [$($DatabaseName)].$($DatabaseTable);");
				$hshSplatting.Add('Computer', "$($Computer)");
				$hshSplatting.Add('DatabaseName', "$($DataBaseName)");
				$hshSplatting.Add('Verbose', $false);
				$hshSplatting.Add('Debug', $false);
				If (-not -not "$($Credentials.UserName)")
				{
					##### Credentials Are Provided
					Write-Debug "Connecting To ""$($DataBaseName)"" Using Provided Credential Object`r`n";
					$hshSplatting.Add('Credentials', $Credentials);
				}
				ElseIf ((-not -not "$($UserName)") -and (-not -not "$($Password)"))
				{
					##### UserName And Password Are Provided
					Write-Debug "Connecting To ""$($DataBaseName)"" Using Provided UserName And Password`r`n";
					$hshSplatting.Add('UserName', $UserName);
					$hshSplatting.Add('Password', $Password);
				}
				Else
				{
					##### Neither Credential Object Nor UserName And Password Are Provided
					##### Using Current User Session
					Write-Debug "Connecting To ""$($DataBaseName)"" Using Current User Session`r`n";
					$hshSplatting.Add('UseCurrentLogOnSession', $true);
				}
				
				##### Retrieve The Data From The SQL Table
				Write-Verbose 'Query The SQL Table About The Inserted Data';
				[System.Data.DataRow[]]$arrRows = @();
				[System.Data.DataRow[]]$arrRows = Invoke-SnsSQLQuery @hshSplatting | `
					Select-Object -ExpandProperty 'Tables' `
					-Verbose:$false -Debug:$false `
					-ErrorAction 'SilentlyContinue' `
					-WarningAction 'SilentlyContinue' | `
					Select-Object -ExpandProperty 'Rows' `
					-Verbose:$false -Debug:$false `
					-ErrorAction 'SilentlyContinue' `
					-WarningAction 'SilentlyContinue';
				#####
				
				##### Verify Each Input Object
				Write-Debug 'Verify Each Input Object';
				[System.UInt32]$intIndex = 0;
				For ([System.UInt32]$intIndex = 0; $intIndex -lt $InputObject.Count; $intIndex++)
				{
					If ($InputObject.Count -gt 5)
					{
						Write-Progress -Activity 'Verify-SnsObjectToSQLInsertQuery' -Id 1 `
							-PercentComplete (($intIndex / $InputObject.Count) * 100) `
							-Verbose:$false -Debug:$false;
						#####
					}
					
					##### Assign The SQL Data To A Temp Collection
					Write-Debug 'Assign The SQL Data To A Temp Collection';
					[System.Object[]]$arrVerif = @();
					[System.Object[]]$arrVerif = $arrRows | Select-Object -Property "*" -Verbose:$false -Debug:$false;
					
					##### Verify Each Property Of The Current Object
					Write-Debug 'Verify Each Property Of The Current Object';
					[System.UInt32]$intInd = 0;
					For ([System.UInt32]$intInd = 0; $intInd -lt $arrProperties.Count; $intInd++)
					{
						##### Filter The Verification Collection To Objects That Have The Same Value
						##### In The Same Property As The Input Object
						Write-Debug 'Filter The Verification Collection To Objects That Match The Current Property Value';
						[System.Object[]]$arrVerif = $arrVerif | Where-Object `
						{ `
							"$($_.""$($arrProperties[$intInd])"")" `
							-eq `
							"$($InputObject[$intIndex].""$($arrProperties[$intInd])"")" `
						} `
						-Verbose:$false -Debug:$false;
					}
					
					##### Verify Whether The Verification Collection Contains Objects
					##### That Have All The Property Values Matching With The InputObject
					Write-Debug 'Verify Whether The Verification Collection Contains Objects';
					If ($arrVerif.Count -le 0)
					{
						Write-Verbose "Input Object ""$($intIndex)"" Was Not Found In The SQL Table";
						[System.Boolean]$bolOut = $false;
						[System.UInt32]$intIndex = $InputObject.Count + 1;
					}
				}
				
				##### Close The Progress Bar
				Write-Debug 'Close The Progress Bar';
				If ($InputObject.Count -gt 5)
				{
					Write-Progress -Activity 'Verify-SnsObjectToSQLInsertQuery' -Id 1 -PercentComplete 100 -Verbose:$false -Debug:$false;
					Write-Progress -Activity 'Verify-SnsObjectToSQLInsertQuery' -Id 1 -Completed -Verbose:$false -Debug:$false;
				}
				
				##### Pass The Output Object To The Pipeline
				Write-Debug "Pass Output Object To The Pipeline";
				$PSCmdlet.WriteObject($bolOut);
			}
			
			#==================================================================================
			#endregion Verify The Insert
			#==================================================================================
		}
	}
	
	##### Override The End Method
	End
	{
		Write-Verbose '';
		Write-Debug 'Override End Method';
		
		##### Reset The Variables
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'bolOut';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'intInd';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'arrVerif';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'arrRows';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'intIndex';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strProp';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'arrProperties';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strSqlQry';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'hshSplatting';
		
		$PSCmdlet.MyInvocation.BoundParameters | Select-Object -ExpandProperty 'Keys' -Verbose:$false -Debug:$false | ForEach `
		{Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name "$($_)"};
		
		##Stop The StopWatch
		$objCmdStopWatch.Stop();
		Write-Verbose "Command Elapsed: ""$($objCmdStopWatch.ElapsedMilliseconds)"" Milliseconds." ;
		Write-Verbose "End!";
	}
}

##### Prepare-SnsHostForRemoteSessions ============================================
Function Prepare-SnsHostForRemoteSessions ()
{
<#
.SYNOPSIS
This CmdLet Modify The Host Machine Settings To Allow Remote PSSession To Office365.
.DESCRIPTION
This CmdLet Modify The Host Machine Settings To Allow Remote PSSession To Office365.
The CmdLet Performs The Following Actions In Sequence:
-- Check WinRM Service Existence
-- Check Whether WinRM Service Is Set As Automatic And Modify It If Needed.
-- Check Whether WinRM Service Is Running And Start It If Needed.
-- Check AllowBasic Registry Key Existence
-- Check Whether AllowBasic Registry Key Have Value 1 And Modify It If Needed.
This CmdLet Is Internal For The Module And Will Not Be Exported To The User.
.PARAMETER EventSource
Specifies The Application Log Event Source To Be Used For The Error Event Logging
Parameter Set: All
Parameter Alias: ScriptName
Parameter Validation: N/A
.INPUTS
Pipeline Input None
.OUTPUTS
[System.Boolean[]] Which Revert Information Whether All Required Settings Are Correct
.NOTES
AUTHOR:    Svetoslav Nedyalkov Savov (svesavov@hotmail.com)
COPYRIGHT: (c) 2020 Svetoslav Nedyalkov Savov, all rights reserved.
THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
.EXAMPLE
[System.Boolean[]]$bolSuccess = Prepare-SnsHostForRemoteSessions "$($EventSource)";
#>
[CmdletBinding(PositionalBinding = $false, `
	SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
Param (
	[Parameter(Mandatory = $false, Position = 0, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateScript({("$($_)" -eq "$($_.Trim())")})]
	[AllowNull()][AllowEmptyString()][System.String]$EventSource
)
	##### Override The Begin Method
	Begin
	{
		Write-Verbose '';
		Write-Verbose "Prepare-SnsHostForRemoteSessions";
		Write-Debug 'Override Begin Method';
		
		##### Initialize New Measure Watch
		[System.Diagnostics.Stopwatch]$objCmdStopWatch = [System.Diagnostics.Stopwatch]::StartNew();
		
		If ("$((Get-FileHash -Path $PSCommandPath -Algorithm 'SHA256' -Verbose:$false -Debug:$false).Hash)" -ne "$($global:SnsModuleCfg.ModuleHash)")
		{Write-Warning 'There Is New Version Of SnsPsModule Module Released. Please Restart The PowerShell Session.'};
		
		#Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName)`r`n";
		
		##### Initialize The Variables
		[System.Object[]]$arrSrvc = @();
		[System.Object[]]$arrRgstr = @();
		
		#==================================================================================
		#region Set WinRM Service To Automatic And Start It
		#==================================================================================
		
		##### Get WinRM Service
		Write-Debug "Get WinRM Service";
		[System.Object[]]$arrSrvc = @();
		[System.Object[]]$arrSrvc = Get-Service -Name 'WinRM' -Verbose:$false -Debug:$false -ErrorAction 'SilentlyContinue';
		
		
		##### Verify WinRM Service Existence
		Write-Debug "Verify WinRM Service Existence";
		If (($arrSrvc.Count -eq 1) -and ("$($arrSrvc[0].Name)" -eq 'WinRM'))
		{
			#==================================================================================
			#region Set WinRM Service To Automatic
			#==================================================================================
			
			##### Verify Whether WinRM Service Is Automatic
			Write-Debug 'Verify Whether WinRM Service Is Automatic';
			If ("$($arrSrvc[0].StartType)" -ne 'Automatic')
			{
				##### Check If The CmdLet Should Process
				If ($PSCmdlet.ShouldProcess("Set-Service WinRM To Automatic"))
				{
					##### Set WinRM Service To Automatic
					Write-Debug 'Set-Service WinRM To Automatic'; 
					Set-Service -Name 'WinRM' -StartupType 'Automatic' `
						-Confirm:$false -Verbose:$false -Debug:$false | Out-Null;
					#####
					
					##### Time Out
					Start-Sleep -Seconds 5 -Verbose:$false -Debug:$false;
					
					##### Get WinRM Service
					Write-Debug "Get WinRM Service";
					[System.Object[]]$arrSrvc = @();
					[System.Object[]]$arrSrvc = Get-Service -Name 'WinRM' -Verbose:$false -Debug:$false -ErrorAction 'SilentlyContinue';
					
					##### Verify Whether WinRM Is Properly Reconfigured
					Write-Debug 'Verify Whether WinRM Is Properly Reconfigured';
					If ("$($arrSrvc[0].StartType)" -ne 'Automatic')
					{
						[System.String]$strEventMessage = 'Failed To Set WinRM To Automatic';
						Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
						
						##### Write Into The Event Log If The Source Is Provided And Exists
						If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
						{
							Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
								-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
							#####
							
							##### Wait A Minute And Kill The Script Process
							Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
							Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
						}
						
						##### Reset the Variable
						Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
						Return $false
					}
				}
			}
			
			#==================================================================================
			#endregion Set WinRM Service To Automatic
			#==================================================================================
			
			#==================================================================================
			#region Start WinRM Service
			#==================================================================================
			
			##### Verify Whether WinRM Service Is Running
			Write-Debug 'Verify Whether WinRM Service Is Running';
			If ("$($arrSrvc[0].Status)" -notlike 'Running')
			{
				##### Check If The CmdLet Should Process
				If ($PSCmdlet.ShouldProcess("Start-Service WinRM"))
				{
					##### Start WinRM Service
					Write-Debug 'Start WinRM Service'; 
					Start-Service -Name 'WinRM' -Confirm:$false -Verbose:$false -Debug:$false | Out-Null;
					
					##### Time Out
					Start-Sleep -Seconds 5 -Verbose:$false -Debug:$false;
					
					##### Get WinRM Service
					Write-Debug "Get WinRM Service";
					[System.Object[]]$arrSrvc = @();
					[System.Object[]]$arrSrvc = Get-Service -Name 'WinRM' -Verbose:$false -Debug:$false -ErrorAction 'SilentlyContinue';
					
					##### Verify Whether WinRM Is Properly Started
					Write-Debug 'Verify Whether WinRM Is Properly Started';
					If ("$($arrSrvc[0].Status)" -notlike 'Running')
					{
						[System.String]$strEventMessage = 'Failed To Start WinRM Service';
						Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
						
						##### Write Into The Event Log If The Source Is Provided And Exists
						If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
						{
							Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
								-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
							#####
							
							##### Wait A Minute And Kill The Script Process
							Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
							Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
						}
						
						##### Reset the Variable
						Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
						Return $false
					}
				}
			}
			
			#==================================================================================
			#endregion Start WinRM Service
			#==================================================================================
		}
		
		#==================================================================================
		#endregion Set WinRM Service To Automatic And Start It
		#==================================================================================
		
		#==================================================================================
		#region Allow Basic Authnetication
		#==================================================================================
		
		##### Get AllowBasic Registry Key Value
		Write-Debug "Get AllowBasic Registry Key Value";
		[System.Object]$objRgstr = @();
		Try
		{
			[System.Object]$objRgstr = Set-SnsRegistry `
				-RegistryPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' `
				-RegistryName 'AllowBasic' `
				-RegistryType 'DWord' `
				-RegistryValue "1" `
				-WhatIf:$true `
				-PassThru:$true `
				-Verbose:$false -Debug:$false `
				-ErrorAction 'SilentlyContinue' `
				-WarningAction 'SilentlyContinue';
			#####
		}
		Catch {}
		
		##### Verify Whether AllowBasic Registry Key Value Exists And The Value Is Correct
		Write-Debug "Verify Whether AllowBasic Registry Key Value Exists And The Value Is Correct";
		If (("$($objRgstr[0].RegistryName)" -eq 'AllowBasic') -and (-not $objRgstr[0].ValueCorrect))
		{
			##### Check If The CmdLet Should Process
			If ($PSCmdlet.ShouldProcess("Enable WinRM Basic Authentication"))
			{
				##### Enable WinRM Basic Authentication
				Write-Debug 'Enable WinRM Basic Authentication';
				[System.Object]$objRgstr = @();
				[System.Object]$objRgstr = Set-SnsRegistry `
					-RegistryPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' `
					-RegistryName 'AllowBasic' `
					-RegistryType 'DWord' `
					-RegistryValue '1' `
					-Confirm:$false -WhatIf:$false `
					-PassThru:$true -Force:$true `
					-Verbose:$false -Debug:$false;
				#####
				
				##### Verify WinRM Basic Authentication Enablement
				Write-Debug 'Verify WinRM Basic Authentication Enablement';
				If (-not $objRgstr[0].ValueCorrect)
				{
					[System.String]$strEventMessage = 'Failed To Enable WinRM Basic Authentication';
					Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
					
					##### Write Into The Event Log If The Source Is Provided And Exists
					If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
					{
						Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
							-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
						#####
						
						##### Wait A Minute And Kill The Script Process
						Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
						Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
					}
					
					##### Reset the Variable
					Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
					Return $false
				}
			}
		}
		
		#==================================================================================
		#endregion Allow Basic Authnetication
		#==================================================================================
		
		##### Pass The Output Object To The Pipeline
		Write-Debug "Pass Output Object To The Pipeline";
		$PSCmdlet.WriteObject($true);
		
		##### Reset The Variables
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objRgstr';
		
		$PSCmdlet.MyInvocation.BoundParameters | Select-Object -ExpandProperty 'Keys' -Verbose:$false -Debug:$false | ForEach `
		{Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name "$($_)"};
	}
	
	##### Override The End Method
	End
	{
		##Stop The StopWatch
		$objCmdStopWatch.Stop();
		Write-Verbose "Command Elapsed: ""$($objCmdStopWatch.ElapsedMilliseconds)"" Milliseconds." ;
		Write-Verbose "End!";
	}
}

##### Connect-SnsSkypeOnPremises ==================================================
Function Connect-SnsSkypeOnPremises ()
{
<#
.SYNOPSIS      
This CmdLet Establish Remote PowerShell Session To Skype For Business On Premises.
.DESCRIPTION      
This CmdLet Establish Remote PowerShell Session To Skype For Business On Premises.
In Case The Session Creation Fail The CmdLet Can Log An Event In The Windows Event Viewer Application Log And Kill
The Script Process. This Functionality Is Enabled Automatically When EventSource Parameter Is Provided. Simple
Throwing Terminating Error Will Keep The PowerShell Process Which Will Prevent The Next Script Instances From
Execution And Any Possible Script Monitoring Will Be Cheated That The Script Is Still Running.
Because Of A Bug In Microsoft Import-PSSession Command, The CmdLet Have No Any Parameter Validations
The Risk Of Providing Wrong Parameter Arguments Or Missing Arguments Remains Entirely With The User
The CmdLet Have Five Parameter Set:
-- FolderPath Here Have To Be Specified The UserName And The Full Absolute UNC Folder Path Where The Encrypted
Password File Resides
-- FilePath Here Have To Be Provided The Full Absolute UNC Path To The Credential File. The CmdLet Will Try To
Generate The UserName From The FileName
-- Credential Here Have To Be Provided System.Management.Automation.PSCredential Object
-- Interactive It Cannot Be Used Whenever The Script Or The Function Is Executed In As Service Mode
In This Parameter Set The CmdLet Opens A Window Where The User Can Specify His Credentials
Obviously When The CmdLet Is Executed As Service There Is No Real Person To Specify The Credentials
-- Kerberos Here The CmdLet Use The Windows Integrated Authentication With Kerberos In This Scenario Is Created A
Remote Session Within The Security Context Of The Currently Logged On User
Impersonalizing Is Not Possible In This Scenario.
.PARAMETER Registrar
Specifies The Fully Qualified Domain Name Of A Front End Server Or A Registrar Pool
It Will Be Used As PSSession Remote Host
It Is Not Good Idea To Be Used SBA Because They Cannot Handle The PSSession Load
If Not Provided The CmdLet Will Try To Retrieve The FrontEnd Pools From AD And Chose The Nearest One
The Automatic Retrieval Works Only When The Skype Is Installed In The Same AD Domain As The Logged User Account
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER UserName
Specifies The UserName
Parameter Set: FolderPath
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER FolderPath
Specifies The Full Absolute UNC Folder Path Where The Credential File Resides
Parameter Set: FolderPath
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER FilePath
Specifies The Full Absolute UNC Path To The Credential File
Parameter Set: FilePath
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Credential
Specifies [System.Management.Automation.PSCredential] Object
Parameter Set: Credential
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Interactive
Specifies That The User Have To Be Asked Interactively For Credentials
Parameter Set: Interactive
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER AuthenticationKerberos
Specifies Whether The Currently Logged On User Security Context Shall Be Used For The Remote Session
It Require The Kerberos Authentication To Be Enabled On The PowerShell Virtual Directory On The CAS Server
Parameter Set: Kerberos
Parameter Alias: Kerberos
Parameter Validation: N/A
.PARAMETER SkipSkypeModuleCheck
Force The CmdLet To Skip The SkypeForBusiness PowerShell Module Existence Verification
If Not Specified The CmdLet Will Try To Detect Whether SkypeForBusiness Module Is Installed And Imported
In Case It Is Installed And Not Imported The CmdLet Will Import It
When SkypeForBusiness Module Is Used There Is No Need Of Skype On Premises Remote PSSession
The CmdLet Is Intended To Be Used Only When Skype Management Tools Are Not Installed
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Protocol
Specifies Whether HTTP Or HTTPS Protocol Shall Be Used
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Prefix
Specifies The Prefix For The CmdLets In This Session
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Attempts
Specifies The Number Of Attempts That Have To Be Made To Establish The Remote Session
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER EventSource
Specifies The Application Log Event Source To Be Used For The Error Event Logging
Parameter Set: All
Parameter Alias: ScriptName
Parameter Validation: N/A
.PARAMETER PassThru
Specifies That The CmdLet Have To Revert A Verification Collection.
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.INPUTS
Pipeline Input None
.OUTPUTS
[System.Object[]] Which Contains A List With The Skype For Business On Premises SIP Domain Objects
.NOTES
AUTHOR:    Svetoslav Nedyalkov Savov (svesavov@hotmail.com)
COPYRIGHT: (c) 2020 Svetoslav Nedyalkov Savov, all rights reserved.
THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
.EXAMPLE
[System.Object[]]$arrSipDomains = Connect-SnsSkypeOnPremises -UserName 'john.smith@contoso.com' `
-FolderPath 'C:\';
.EXAMPLE
[System.Object[]]$arrSipDomains = Connect-SnsSkypeOnPremises -FilePath 'C:\john.smith@contoso.com.ini';
.EXAMPLE
[System.Object[]]$arrSipDomains = Connect-SnsSkypeOnPremises -Credential $objCredential;
.EXAMPLE
[System.Object[]]$arrSipDomains = Connect-SnsSkypeOnPremises;
.EXAMPLE
[System.Object[]]$arrSipDomains = Connect-SnsSkypeOnPremises -AuthenticationKerberos;
#>
[Alias('New-SfbOnPremSession')]
[CmdletBinding(PositionalBinding = $false, DefaultParameterSetName = 'Interactive')]
Param (
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[AllowNull()][AllowEmptyString()][System.String]$Registrar,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'FolderPath', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.String]$UserName,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'FolderPath', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.String]$FolderPath,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'FilePath', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.String]$FilePath,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'Credential', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.Management.Automation.PSCredential]$Credential,
	
	[Parameter(Mandatory = $false, ParameterSetName = 'Interactive', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Switch]$Interactive = $false,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'Kerberos', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Alias('Kerberos')]
	[Switch]$AuthenticationKerberos = $false,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Switch]$SkipSkypeModuleCheck = $false,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateSet('https','http')]
	[System.String]$Protocol = 'https',
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[AllowNull()][AllowEmptyString()][System.String]$Prefix,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.Int32]$Attempts = 3,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Alias('ScriptName')]
	[AllowNull()][AllowEmptyString()][System.String]$EventSource,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Switch]$PassThru
)
	##### Override The Begin Method
	Begin
	{
		Write-Verbose '';
		Write-Verbose "Connect-SnsSkypeOnPremises";
		Write-Debug 'Override Begin Method';
		
		##### Initialize New Measure Watch
		[System.Diagnostics.Stopwatch]$objCmdStopWatch = [System.Diagnostics.Stopwatch]::StartNew();
		
		If ("$((Get-FileHash -Path $PSCommandPath -Algorithm 'SHA256' -Verbose:$false -Debug:$false).Hash)" -ne "$($global:SnsModuleCfg.ModuleHash)")
		{Write-Warning 'There Is New Version Of SnsPsModule Module Released. Please Restart The PowerShell Session.'};
		
		Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName)`r`n";
		
		##### Initialize The Variables
		[System.Net.NetworkInformation.Ping]$objPing = $null;
		[System.Management.Automation.ScriptBlock]$scrBlock = $null;
		[System.Object[]]$arrSipDomains = @();
		[System.Object[]]$arrFrontEndPools = @();
		[System.Management.Automation.PSCredential]$objCredential = $null;
		[System.Boolean]$bolTestCred = $false;
		[System.Collections.Specialized.OrderedDictionary]$hshSplat = [Ordered]@{};
		[System.Int32]$intCheckSum = 0;
		[System.Management.Automation.Runspaces.PSSession]$objPsSession = $null;
		
		##### Generate The Ping Object
		Write-Debug 'Generate The Ping Object';
		[System.Net.NetworkInformation.Ping]$objPing = $null;
		[System.Net.NetworkInformation.Ping]$objPing = New-Object -TypeName 'System.Net.NetworkInformation.Ping' -Verbose:$false -Debug:$false;
		#####
		
		##### Generate The Verification Script Block
		[System.Management.Automation.ScriptBlock]$scrBlock = $null;
		[System.Management.Automation.ScriptBlock]$scrBlock = `
			[System.Management.Automation.ScriptBlock]::Create("Get-$($Prefix)CsSipDomain");
		#####
		
		#==================================================================================
		#region Verify If The SkypeForBusiness Module Is Available And Loaded
		#==================================================================================
		
		##### Verify SkypeForBusiness PowerShell Module Load
		Write-Debug 'Verify SkypeForBusiness PowerShell Module Load';
		If ((-not $SkipSkypeModuleCheck.IsPresent) -and `
			(-not -not (Get-Module -Name 'SkypeForBusiness' -Verbose:$false -Debug:$false)))
		{
			##### Generate The Warning Message
			[System.String]$strEventMessage = '';
			[System.String]$strEventMessage += "`r`n$('*' * 100)`r`n*$(' ' * 98)*`r`n";
			[System.String]$strEventMessage += "*$(' ' * 27)Module ""SkypeForBusiness"" ";
			[System.String]$strEventMessage += "Is Already Loaded.$(' ' * 27)*`r`n";
			[System.String]$strEventMessage += "*$(' ' * 98)*`r`n";
			[System.String]$strEventMessage += "*$(' ' * 29)There Is No Need Of Remote ";
			[System.String]$strEventMessage += "Skype Session$(' ' * 29)*`r`n";
			[System.String]$strEventMessage += "*$(' ' * 98)*`r`n$('*' * 100)`r`n`r`n";
			Write-Warning "$($strEventMessage)";
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Warning' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			Return (Get-CsSipDomain -Verbose:$false -Debug:$false)
		}
		
		##### Verify SkypeForBusiness PowerShell Module Load
		Write-Debug 'Verify SkypeForBusiness PowerShell Module Load';
		If ((-not $SkipSkypeModuleCheck.IsPresent) -and `
			(-not -not (Get-Module -Name 'SkypeForBusiness' -ListAvailable -Verbose:$false -Debug:$false)))
		{
			##### Generate The Warning Message
			[System.String]$strEventMessage = '';
			[System.String]$strEventMessage += "`r`n$('*' * 100)`r`n*$(' ' * 98)*`r`n";
			[System.String]$strEventMessage += "*$(' ' * 20)Module ""SkypeForBusiness"" Is ";
			[System.String]$strEventMessage += "Already Present On The Server$(' ' * 20)*`r`n";
			[System.String]$strEventMessage += "*$(' ' * 98)*`r`n";
			[System.String]$strEventMessage += "*$(' ' * 34)Please Load The Module Instead$(' ' * 34)*`r`n";
			[System.String]$strEventMessage += "*$(' ' * 98)*`r`n$('*' * 100)`r`n`r`n";
			Write-Warning "$($strEventMessage)";
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Warning' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
			}
			
			##### Import SkypeForBusiness PowerShell Module
			If (-not (Get-Module -Name 'SkypeForBusiness' -Verbose:$false -Debug:$false))
			{
				##### Import SkypeForBusiness PowerShell Module
				Write-Host 'Import SkypeForBusiness PowerShell Module' -ForegroundColor 'Green';
				Import-Module -Name 'SkypeForBusiness' -Global:$true -Force:$true -Verbose:$false -Debug:$false;
			}
			
			##### Generate The On Premises SIP Domains Array
			[System.Object[]]$arrSipDomains = @();
			If (-not -not (Get-Module -Name 'SkypeForBusiness' -Verbose:$false -Debug:$false))
			{
				##### Generate The On Premises SIP Domains Array
				Write-Debug 'Generate The On Premises SIP Domains Array';
				[System.Object[]]$arrSipDomains = Get-CsSipDomain -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			Return ($arrSipDomains)
		}
		
		#==================================================================================
		#endregion Verify If The SkypeForBusiness Module Is Available And Loaded
		#==================================================================================
		
		#==================================================================================
		#region Generate The Session Target
		#==================================================================================
		
		##### Verify Whether Registrar Is Provided
		Write-Debug 'Verify Whether Registrar Is Provided';
		If (-not "$($Registrar)")
		{
			##### Retrieve Skype Registrar Pools From AD
			Write-Debug 'Retrieve Skype Registrar Pools From AD';
			[System.Object[]]$arrFrontEndPools = @();
			[System.Object[]]$arrFrontEndPools = Search-SnsAdObject `
				-LdapQuery "(&(objectClass=msRTCSIP-Pool)(objectCategory=CN=ms-RTC-SIP-Pool,$( `
					([ADSI]'LDAP://RootDSE').schemaNamingContext `
					))(msRTCSIP-PoolData=ExtendedType=CentralRegistrar))" `
				-SearchRoot "$(([ADSI]'LDAP://RootDSE').configurationNamingContext)" `
				-DomainController "$(([ADSI]'LDAP://RootDSE').dnsHostName)" `
				-ReturnProperties @('dNSHostName') `
				-Verbose:$false -Debug:$false;
			#####
			
			##### Ping All FrontEnd Pools And Take The Nearest One
			Write-Debug 'Ping All FrontEnd Pools And Take The Nearest One';
			[System.String]$Registrar = $arrFrontEndPools | Select-Object `
				-Property @{'n'='Fqdn';'e'={"$($_.Properties.dnshostname)"}} `
				-Verbose:$false -Debug:$false | `
				Select-Object -Property  `
				@(
					'Fqdn',
					@{'n'='TTL';'e'={"$($objPing.Send( `
						""$($_.Fqdn)"", `
						100, `
						[System.Text.Encoding]::ASCII.GetBytes('S') `
					).Options.Ttl)" -as [System.Int32]}}
				) `
				-Verbose:$false -Debug:$false | `
				Sort-Object -Property @('Ttl','Fqdn') -Descending:$true `
				-Verbose:$false -Debug:$false | `
				Select-Object -First 1 `
				-Verbose:$false -Debug:$false | `
				Select-Object -ExpandProperty 'Fqdn' `
				-Verbose:$false -Debug:$false;
			#####
		}
		
		##### Verify The Target Server Generation
		Write-Debug 'Verify The Target Server Generation';
		If (-not "$($Registrar)")
		{
			[System.String]$strEventMessage += "There Is No Destination Registrar Provided";
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			[System.String]$Registrar = '';
			Return
		}
		
		#==================================================================================
		#endregion Generate The Session Target
		#==================================================================================
		
		#==================================================================================
		#region Create The Credentials Object
		#==================================================================================
		
		##### Verify The Parameter Set Name
		Write-Debug 'Verify The Parameter Set Name';
		Switch ("$($PSCmdlet.ParameterSetName)")
		{
			'FolderPath'
			{
				##### Generate The Credential Object In FolderPath Parameter Set
				Write-Verbose 'Generate The Credential Object In FolderPath Parameter Set';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = Import-SnsCredentialFile `
					-UserName "$($UserName)" -FolderPath "$($FolderPath)" -EventSource "$($EventSource)" `
					-Verbose:$false -Debug:$false;
				#####
				
				Break;
			}
			
			'FilePath'
			{
				##### Generate The Credential Object In FilePath Parameter Set
				Write-Verbose 'Generate The Credential Object In FilePath Parameter Set';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = Import-SnsCredentialFile `
					-FilePath "$($FilePath)" -EventSource "$($EventSource)" `
					-Verbose:$false -Debug:$false;
				#####
				
				Break;
			}
			
			'Credential'
			{
				##### Assign The Provided Credential Object In Credential Parameter Set
				Write-Verbose 'Assign The Provided Credential Object In Credential Parameter Set';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = $Credential;
				#####
				
				Break;
			}
			
			Default
			{
				##### Do Nothing
			}
		}
		
		##### Verify The Provided Credentials
		Write-Debug 'Verify The Parameter Set Name';
		If ( `
			("$($PSCmdlet.ParameterSetName)" -like 'FolderPath') -or `
			("$($PSCmdlet.ParameterSetName)" -like 'FilePath') -or `
			("$($PSCmdlet.ParameterSetName)" -like 'Credential') `
		)
		{
			##### Retrieve An AD DNS Domain Name With Impersonated Credentials
			Write-Debug 'Retrieve An AD DNS Domain Object With Impersonated Credentials';
			[System.Boolean]$bolTestCred = $false;
			[System.Boolean]$bolTestCred = (-not -not `
				"$((New-Object -TypeName 'System.DirectoryServices.DirectoryEntry' -ArgumentList `
				(
					""LDAP://$(([ADSI]'').distinguishedName)"",
					""$($objCredential.UserName)"",
					""$($objCredential.GetNetworkCredential().Password)""
				) -Verbose:$false -Debug:$false).name)" `
			);
			
			##### Verify AD Object Retrieval
			Write-Debug 'Verify AD Object Retrieval';
			If (-not $bolTestCred)
			{
				##### Generate The Error Message
				[System.String]$strEventMessage = 'Provided Credential Are Invalid';
				Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
				
				##### Write Into The Event Log If The Source Is Provided And Exists
				If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
				{
					Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
						-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
					#####
					
					##### Wait A Minute And Kill The Script Process
					Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
					Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
				}
				
				##### Reset the Variable
				Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				Return
			}
		}
		
		##### Verify If It Is Interactive Session Kerberos Wont Be Used And There Are No Credentials
		Write-Debug 'Verify If It Is Interactive Session Kerberos Wont Be Used And There Are No Credentials';
		If ( `
			([Environment]::UserInteractive) `
			-and `
			("$($PSCmdlet.ParameterSetName)" -notlike 'Kerberos') `
			-and `
			((-not "$($objCredential.UserName)") -or (-not $bolTestCred)) `
		)
		{
			##### Loop Interactive Credentials Dialog With The User
			Write-Debug 'Loop Interactive Credentials Dialog With The User';
			Do
			{
				##### Ask The User About Credentials
				Write-Verbose 'Ask The User About Credentials';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = Get-Credential -Verbose:$false -Debug:$false;
				
				##### Check The Credentials
				Write-Debug 'Check The Credentials';
				[System.Boolean]$bolTestCred = $false;
				[System.Boolean]$bolTestCred = (-not -not `
					"$((New-Object -TypeName 'System.DirectoryServices.DirectoryEntry' -ArgumentList `
					(
						""LDAP://$(([ADSI]'').distinguishedName)"",
						""$($objCredential.UserName)"",
						""$($objCredential.GetNetworkCredential().Password)""
					) -Verbose:$false -Debug:$false).name)" `
				);
				
				##### Check The Imported Credentials
				Write-Debug 'Check The Imported Credentials';
				If (-not $bolTestCred)
				{
					##### Generate The Error Message
					Write-Error 'Provided Invalid Credentials' -ErrorAction 'Continue';
					[System.Management.Automation.PSCredential]$objCredential = $null;
				}
			}
			While (-not $bolTestCred)
		}
		
		##### Verify The Credentials Object
		Write-Debug 'Verify The Credentials Object';
		If (("$($PSCmdlet.ParameterSetName)" -notlike 'Kerberos') -and (-not "$($objCredential.UserName)"))
		{
			[System.String]$strEventMessage = 'Failed To Generate The Credential Object For Skype On Premises';
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			[System.Management.Automation.PSCredential]$objCredential = $null;
			Return
		}
		
		#==================================================================================
		#endregion Create The Credentials Object
		#==================================================================================
		
		#==================================================================================
		#region Create SfB On Premises Session
		#==================================================================================
		
		##### Verify Any Previous Sessions Existence
		Write-Debug "Verify Any Previous Sessions Existence";
		If (-not -not ( `
			Get-PSSession -Verbose:$false -Debug:$false | `
			Where-Object {"$($_.Name)" -like "$Registrar"} -Verbose:$false -Debug:$false `
		))
		{
			##### Disconnect The Previous Sessions
			Write-Verbose 'Removing Previous Sessions'; 
			Get-PSSession -Verbose:$false -Debug:$false | `
				Where-Object {"$($_.Name)" -like "$Registrar"} -Verbose:$false -Debug:$false | `
				Remove-PSSession -Confirm:$false -Verbose:$false -Debug:$false;
			#####
		}
		
		##### Verify The Prerequisites For Remote PSSession
		Write-Debug 'Verify The Prerequisites For Remote PSSession';
		If ( `
			(-not -not "$($Registrar)") `
			-and `
			( `
				("$($PSCmdlet.ParameterSetName)" -like 'Kerberos') `
				-or `
				(-not -not "$($objCredential.UserName)")
			) `
		)
		{
			##### Generate The New-PSSession Splatting HashTable
			Write-Debug "Generate The New-PSSession Splatting HashTable";
			[System.Collections.Specialized.OrderedDictionary]$hshSplat = [Ordered]@{};
			$hshSplat.Add('Name', "$($Registrar)");
			$hshSplat.Add('ConnectionUri', "$($Protocol)://$($Registrar)/OcsPowershell");
			$hshSplat.Add('AllowRedirection', $true);
			$hshSplat.Add('SessionOption', $( `
				New-PSSessionOption `
				-SkipCACheck:$true `
				-SkipCNCheck:$true `
				-SkipRevocationCheck:$true `
				-Verbose:$false -Debug:$false `
			));
			$hshSplat.Add('Verbose', $false);
			$hshSplat.Add('Debug', $false);
			
			##### Verify The Requested Authentication Method
			Write-Debug "Verify The Requested Authentication Method";
			If ("$($PSCmdlet.ParameterSetName)" -like 'Kerberos')
			{
				##### Create PSSession With Kerberos Authentication
				$hshSplat.Add('Authentication', 'Kerberos');
			}
			ElseIf (-not -not "$($objCredential.UserName)")
			{
				##### Create PSSession With Basic Authentication
				#$hshSplat.Add('Authentication', 'Basic');
				$hshSplat.Add('Credential', $objCredential);
			}
			
			##### Loop The Session Creation
			Write-Debug 'Loop The Session Creation';
			[System.Int32]$intCheckSum = 0;
			Do
			{
				##### Establish SfB On Premises Session
				Write-Verbose 'Establish SfB On Premises Session';
				[System.Management.Automation.Runspaces.PSSession]$objPsSession = $null;
				[System.Management.Automation.Runspaces.PSSession]$objPsSession = New-PSSession @hshSplat;
				
				##### Process The Loop Variable And TimeOut
				Start-Sleep -Seconds 2 -Verbose:$false -Debug:$false;
				[System.Int32]$intCheckSum = $intCheckSum + 1;
			}
			While (("$($objPsSession.Name)" -notlike "$Registrar") -and ($intCheckSum -lt $Attempts))
		}
		
		##### Verify Session Creation
		Write-Debug 'Verify Session Creation';
		If (-not "$($objPsSession.Name)")
		{
			[System.String]$strEventMessage = "Failed To Establish PowerShell Session To $($HostName)";
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			[System.Management.Automation.Runspaces.PSSession]$objPsSession = $null;
			Return
		}
		
		#==================================================================================
		#endregion Create SfB On Premises Session
		#==================================================================================
		
		#==================================================================================
		#region Import The SfB On Premises Session
		#==================================================================================
		
		##### Verify Whether The Session Is Established
		If (-not -not "$($objPsSession.Name)")
		{
			##### Verify Whether Prefix Is Provided
			Write-Debug 'Verify Whether Prefix Is Provided';
			[System.Collections.Specialized.OrderedDictionary]$hshSplat = [Ordered]@{};
			$hshSplat.Add('Session', $objPsSession);
			$hshSplat.Add('AllowClobber', $true);
			$hshSplat.Add('DisableNameChecking', $true);
			$hshSplat.Add('Verbose', $false);
			$hshSplat.Add('Debug', $false);
			$hshSplat.Add('ErrorAction', 'SilentlyContinue');
			$hshSplat.Add('WarningAction', 'SilentlyContinue');
			If (-not -not "$($Prefix)") {$hshSplat.Add('Prefix', "$($Prefix)"); }
			
			##### Import The SfB On Premises Session
			Write-Verbose 'Importing The SfB On Premises Session';
			[System.Management.Automation.PSModuleInfo]$objSesModule = $null;
			[System.Management.Automation.PSModuleInfo]$objSesModule = Import-Module `
				-ModuleInfo (Import-PSSession @hshSplat) `
				-Prefix "$($Prefix)" `
				-Global:$true `
				-DisableNameChecking:$true `
				-Force:$true `
				-PassThru:$true `
				-Verbose:$false -Debug:$false;
			#####
		}
		
		##### Verify The PSSession Import
		If (-not "$($objSesModule.Name)")
		{
			[System.String]$strEventMessage = 'Failed To Import The SfB On Premises PowerShell Session';
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			[System.Management.Automation.PSModuleInfo]$objSesModule = $null;
			Return
		}
		
		#==================================================================================
		#endregion Import The SfB On Premises Session
		#==================================================================================
		
		#==================================================================================
		#region Retrieve The SIP Domains Via The Remote Session
		#==================================================================================
		
		##### Verify The PSSession Import
		If (-not -not "$($objSesModule.Name)")
		{
			##### Verify Whether Get-CsSipDomain Command Is Among The Exported Commands
			Write-Debug 'Verify Whether Get-CsSipDomain Command Is Among The Exported Commands';
			If ($objSesModule.ExportedCommands.Keys -icontains "Get-$($Prefix)CsSipDomain")
			{
				##### Generate The On Premises SIP Domain Array
				Write-Debug 'Generate The On Premises SIP Domain Array';
				[System.Object[]]$arrSipDomains = @();
				[System.Object[]]$arrSipDomains = Invoke-Command -ScriptBlock $scrBlock -Verbose:$false -Debug:$false;
				
				##### Verify The SfB On Premises Session Import
				Write-Debug 'Verify The SfB On Premises Session Import';
				If (($arrSipDomains.Count) -eq 0)
				{
					[System.String]$strEventMessage = 'Failed To Retrieve The On Premises CsSipDomain';
					Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
					
					##### Write Into The Event Log If The Source Is Provided And Exists
					If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
					{
						Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
							-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
						#####
						
						##### Wait A Minute And Kill The Script Process
						Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
						Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
					}
					
					##### Reset the Variable
					Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
					Return
				}
				Else
				{
					##### Continue If Output Is Requested
					Write-Debug "Continue If Output Is Requested";
					If ($PassThru.IsPresent)
					{
						##### Pass The Output Object To The Pipeline
						Write-Debug "Pass Output Object To The Pipeline";
						$PSCmdlet.WriteObject($arrSipDomains);
					}
				}
			}
			Else
			{
				Return
			}
		}
		
		#==================================================================================
		#endregion Retrieve The SIP Domains Via The Remote Session
		#==================================================================================
		
		##### Reset The Variables
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objPsSession';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'intCheckSum';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'bolTestCred';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objCredential';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'arrFrontEndPools';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'arrSipDomains';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'scrBlock';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objPing';
		
		$PSCmdlet.MyInvocation.BoundParameters | Select-Object -ExpandProperty 'Keys' -Verbose:$false -Debug:$false | ForEach `
		{Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name "$($_)"};
	}
	
	##### Override The End Method
	End
	{
		##Stop The StopWatch
		$objCmdStopWatch.Stop();
		Write-Verbose "Command Elapsed: ""$($objCmdStopWatch.ElapsedMilliseconds)"" Milliseconds." ;
		Write-Verbose "End!";
	}
}

##### Connect-SnsSkypeOnline ======================================================
Function Connect-SnsSkypeOnline ()
{
<#
.SYNOPSIS
This CmdLet Establish Remote PowerShell Session To Skype For Business Online In Office 365.
.DESCRIPTION
This CmdLet Establish Remote PowerShell Session To Skype For Business Online In Office 365.
In Case The Session Creation Fail The CmdLet Can Log An Event In The Windows Event Viewer Application Log And Kill
The Script Process. This Functionality Is Enabled Automatically When EventSource Parameter Is Provided. Simple
Throwing Terminating Error Will Keep The PowerShell Process Which Will Prevent The Next Script Instances From
Execution And Any Possible Script Monitoring Will Be Cheated That The Script Is Still Running.
Because Of A Bug In Microsoft Import-PSSession Command, The CmdLet Have No Any Parameter Validations.
The Risk Of Providing Wrong Parameter Arguments Or Missing Arguments Remains Entirely With The User.
The CmdLet Have Four Parameter Sets:
-- FolderPath Here Have To Be Specified The UserName And The Full Absolute UNC Folder Path Where The Encrypted
Password File Resides.
-- FilePath Here Have To Be Provided The Full Absolute UNC Path To The Credential File. The CmdLet Will Try To
Generate The UserName From The FileName.
-- Credential Here Have To Be Provided System.Management.Automation.PSCredential Object.
-- Interactive This Is The Only Parameter Set Which Is Capable To Establish Remote PowerShell Session To Skype For
Business Online With Multifactor Authentication. However It Cannot Be Used Whenever The Script Or The Function Is
Executed In As Service Mode. In This Parameter Set The CmdLet Opens A Window Where The User Can Specify His
Credentials And Multi Factor Authentication Code Received On A SMS Or Inside A Phone App Or Phone Call And Etc.
Obviously When The CmdLet Is Executed As Service There Is No Real Person To Specify The Credentials And The MFA
Code. Depending Of The Configuration There Might Not Be PowerShell Host Console Window Either.
NOTE: The CmdLet Requires SkypeOnlineConnector PowerShell Module To Be Installed In Advance https://bit.ly/2Grvr1X
NOTE: The CmdLet Requires The Host To Be Prepared For Remote PowerShell with Enable-PSRemoting And Then
Disable-PSRemoting. Actually The Host Does Not Require To Accept Remote Sessions. However Without Preparing And
Then Removing The Remote Sessions Accepting The Generation Of Remote Sessions To Other Hosts Does Not Work As Well.
.PARAMETER UserName
Specifies The UserName
Parameter Set: FolderPath And Interactive
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER FolderPath
Specifies The Full Absolute UNC Folder Path Where The Credential File Resides
Parameter Set: FolderPath
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER FilePath
Specifies The Full Absolute UNC Path To The Credential File
Parameter Set: FilePath
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Credential
Specifies [System.Management.Automation.PSCredential] Object
Parameter Set: Credential
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Interactive
Specifies That The User Have To Be Asked Interactively For Credentials
Parameter Set: Interactive
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER OverrideAdminDomain
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Prefix
Specifies The Prefix For The CmdLets In This Session
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER ProxyAccessType
Specifies The ProxyAccessType
The Best Practice Require Direct Internet Access To Office 365
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: Yes Using Enumeration Validation
.PARAMETER Attempts
Specifies The Number Of Attempts That Have To Be Made To Establish The Remote Session
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER EventSource
Specifies The Application Log Event Source To Be Used For The Error Event Logging
Parameter Set: All
Parameter Alias: ScriptName
Parameter Validation: N/A
.PARAMETER PassThru
Specifies That The CmdLet Have To Revert A Verification Collection.
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.INPUTS
Pipeline Input None
.OUTPUTS
[System.Object[]] Which Contains A List With The Skype For Business Online SIP Domain Objects
.NOTES
AUTHOR:    Svetoslav Nedyalkov Savov (svesavov@hotmail.com)
COPYRIGHT: (c) 2020 Svetoslav Nedyalkov Savov, all rights reserved.
THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
.EXAMPLE
[System.Object[]]$arrSipDomains = Connect-SnsSkypeOnline -UserName 'john.smith@contoso.com' `
-FolderPath 'C:\';
.EXAMPLE
[System.Object[]]$arrSipDomains = Connect-SnsSkypeOnline -FilePath 'C:\john.smith@contoso.com.ini';
.EXAMPLE
[System.Object[]]$arrSipDomains = Connect-SnsSkypeOnline -Credential $objCredential;
.EXAMPLE
[System.Object[]]$arrSipDomains = Connect-SnsSkypeOnline -UserName 'john.smith@contoso.com' -Interactive;
#>
[Alias('New-SfbOnlineSession')]
[CmdletBinding(PositionalBinding = $false, DefaultParameterSetName = 'Interactive')]
Param (
	[Parameter(Mandatory = $true, ParameterSetName = 'FolderPath', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Parameter(Mandatory = $true, ParameterSetName = 'Interactive', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.String]$UserName,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'FolderPath', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.String]$FolderPath,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'FilePath', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.String]$FilePath,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'Credential', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.Management.Automation.PSCredential]$Credential,
	
	[Parameter(Mandatory = $false, ParameterSetName = 'Interactive', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Switch]$Interactive = $false,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.String]$OverrideAdminDomain,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.String]$Prefix,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateSet('IEConfig','WinHttpConfig','AutoDetect','NoProxyServer','None')]
	[System.String]$ProxyAccessType = 'NoProxyServer',
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.Int32]$Attempts = 3,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Alias('ScriptName')]
	[AllowNull()][AllowEmptyString()][System.String]$EventSource,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Switch]$PassThru
)
	##### Override The Begin Method
	Begin
	{
		Write-Verbose '';
		Write-Verbose "Connect-SnsSkypeOnline";
		Write-Debug 'Override Begin Method';
		
		##### Initialize New Measure Watch
		[System.Diagnostics.Stopwatch]$objCmdStopWatch = [System.Diagnostics.Stopwatch]::StartNew();
		
		If ("$((Get-FileHash -Path $PSCommandPath -Algorithm 'SHA256' -Verbose:$false -Debug:$false).Hash)" -ne "$($global:SnsModuleCfg.ModuleHash)")
		{Write-Warning 'There Is New Version Of SnsPsModule Module Released. Please Restart The PowerShell Session.'};
		
		Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName)`r`n";
		
		##### Initialize The Variables
		[System.Management.Automation.ScriptBlock]$scrBlock = $null;
		[System.Management.Automation.PSCredential]$objCredential = $null;
		[System.Management.Automation.Remoting.PSSessionOption]$objSessionOption = $null;
		[System.Collections.Specialized.OrderedDictionary]$hshSplat = [Ordered]@{};
		[System.Int32]$intCheckSum = 0;
		[System.Management.Automation.Runspaces.PSSession]$objPsSession = $null;
		[System.Management.Automation.PSModuleInfo]$objSesModule = $null;
		[System.Object[]]$arrSipDomains = @();
		
		##### Generate The Verification Script Block
		[System.Management.Automation.ScriptBlock]$scrBlock = `
			[System.Management.Automation.ScriptBlock]::Create("Get-$($Prefix)CsOnlineSipDomain");
		#####
		
		#==================================================================================
		#region Load SkypeOnlineConnector PowerShell Module
		#==================================================================================
		
		##### Verify SkypeOnlineConnector PowerShell Module Existence
		Write-Debug 'Verify SkypeOnlineConnector PowerShell Module Existence';
		If (-not (Get-Module -Name 'SkypeOnlineConnector' -ListAvailable -Verbose:$false -Debug:$false))
		{
			[System.String]$strEventMessage = 'PowerShell Module SkypeOnlineConnector Is Not Installed';
			[System.String]$strEventMessage += "`r`nPlease Refer To https://bit.ly/2PlKooj";
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			Return
		}
		
		##### Load SkypeOnlineConnector PowerShell Module
		Write-Debug 'Load SkypeOnlineConnector PowerShell Module';
		If ((-not (Get-Module -Name 'SkypeOnlineConnector' -Verbose:$false -Debug:$false)) -and `
			(-not -not (Get-Module -Name 'SkypeOnlineConnector' -ListAvailable -Verbose:$false -Debug:$false)))
		{
			Write-Host 'Import SkypeOnlineConnector Module' -ForegroundColor 'Green';
			Import-Module -Name 'SkypeOnlineConnector' -Global:$true -Force:$true -Verbose:$false -Debug:$false;
		}
		
		##### Verify SkypeOnlineConnector PowerShell Module Load
		Write-Debug 'Verify SkypeOnlineConnector PowerShell Module Load';
		If (-not (Get-Module -Name 'SkypeOnlineConnector' -Verbose:$false -Debug:$false))
		{
			[System.String]$strEventMessage = 'Failed To Load PowerShell Module SkypeOnlineConnector';
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			Return
		}
		
		#==================================================================================
		#endregion Load SkypeOnlineConnector PowerShell Module
		#==================================================================================
		
		#==================================================================================
		#region Create The Credentials Object
		#==================================================================================
		
		###### Generate The Credential Object In FolderPath Parameter Set
		Write-Debug 'Verify The Parameter Set Name';
		Switch ("$($PSCmdlet.ParameterSetName)")
		{
			'FolderPath'
			{
				##### Generate The Credential Object In FolderPath Parameter Set
				Write-Verbose 'Generate The Credential Object In FolderPath Parameter Set';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = Import-SnsCredentialFile `
					-UserName "$($UserName)" -FolderPath "$($FolderPath)" -EventSource "$($EventSource)" `
					-Verbose:$false -Debug:$false;
				#####
			}
			
			'FilePath'
			{
				##### Generate The Credential Object In FilePath Parameter Set
				Write-Verbose 'Generate The Credential Object In FilePath Parameter Set';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = Import-SnsCredentialFile `
					-FilePath "$($FilePath)" -EventSource "$($EventSource)" `
					-Verbose:$false -Debug:$false;
				#####
			}
			
			'Credential'
			{
				##### Assign The Provided Credential Object In Credential Parameter Set
				Write-Verbose 'Assign The Provided Credential Object In Credential Parameter Set';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = $Credential;
				#####
			}
		}
		
		##### Verify The Credential Object
		Write-Debug 'Verify The Credential Object';
		If ((-not [Environment]::UserInteractive) -and (-not "$($objCredential.UserName)"))
		{
			[System.String]$strEventMessage = 'Failed To Generate The Credential For SfB Online';
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			[System.Management.Automation.PSCredential]$objCredential = $null;
			Return
		}
		
		#==================================================================================
		#endregion Create The Credentials Object
		#==================================================================================
		
		#==================================================================================
		#region Create SfB Online Session
		#==================================================================================
		
		##### Verify Any Previous Sessions Existence
		Write-Debug "Verify Any Previous Sessions Existence";
		If (-not -not ( `
			Get-PSSession -Verbose:$false -Debug:$false | `
			Where-Object {"$($_.ComputerName)" -like "*online.lync.com"} -Verbose:$false -Debug:$false `
		))
		{
			##### Disconnect The Previous Sessions
			Write-Verbose 'Removing Previous Sessions'; 
			Get-PSSession -Verbose:$false -Debug:$false | `
				Where-Object {"$($_.ComputerName)" -like "*online.lync.com"} -Verbose:$false -Debug:$false | `
				Remove-PSSession -Confirm:$false -Verbose:$false -Debug:$false;
			#####
		}
		
		##### Prepare The Host Machine For Remote PSSession
		Write-Debug "Prepare The Host Machine For Remote PSSession";
		If (-not ( `
			Prepare-SnsHostForRemoteSessions "$($EventSource)" `
			-WhatIf:$false -Confirm:$false `
			-Verbose:$false -Debug:$false `
		))
		{
			Return
		}
		
		##### Generate The Session Option Object
		Write-Debug "Generate The Session Option Object";
		[System.Management.Automation.Remoting.PSSessionOption]$objSessionOption = $null;
		[System.Management.Automation.Remoting.PSSessionOption]$objSessionOption = New-PSSessionOption `
			-SkipRevocationCheck:$true `
			-SkipCACheck:$true `
			-SkipCNCheck:$true `
			-ProxyAccessType "$($ProxyAccessType)" `
			-Verbose:$false -Debug:$false;
		#####
		
		##### Generate The Splatting HashTable
		Write-Debug "Generate The Splatting HashTable For New-CsOnlineSession";
		[System.Collections.Specialized.OrderedDictionary]$hshSplat = [Ordered]@{};
		$hshSplat.Add('SessionOption', $objSessionOption);
		$hshSplat.Add('Verbose', $false);
		$hshSplat.Add('Debug', $false);
		
		##### Check Credential Object Existence
		Write-Debug 'Check Credential Object Existence';
		If (-not -not "$($objCredential.UserName)") {$hshSplat.Add('Credential', $objCredential);}
		
		##### Check Whether OverrideAdminDomain Is Specified
		Write-Debug 'Check Whether OverrideAdminDomain Is Specified';
		If (-not -not "$($OverrideAdminDomain)") {$hshSplat.Add('OverrideAdminDomain', "$($OverrideAdminDomain)");}
		
		##### Check Whether The ParameterSetName Is Interactive
		Write-Debug 'Check Whether The ParameterSetName Is Interactive';
		If ("$($PSCmdlet.ParameterSetName)" -eq 'Interactive') {$hshSplat.Add('UserName', "$($UserName)");}
		
		##### Loop The Session Creation
		Write-Debug 'Loop The Session Creation';
		[System.Int32]$intCheckSum = 0;
		Do
		{
			##### Establish The SfB Online Session
			Write-Verbose 'Establish The SfB Online Session';
			[System.Management.Automation.Runspaces.PSSession]$objPsSession = $null;
			[System.Management.Automation.Runspaces.PSSession]$objPsSession = New-CsOnlineSession @hshSplat;
			#####
			
			##### Process The Loop Variable And TimeOut
			Start-Sleep -Seconds 2; [System.Int32]$intCheckSum = $intCheckSum + 1;
		}
		While (("$($objPsSession.ComputerName)" -notlike "*online.lync.com") -and ($intCheckSum -lt $Attempts))
		
		##### Verify Session Creation
		Write-Debug 'Verify Session Creation';
		If ("$($objPsSession.ComputerName)" -notlike "*online.lync.com")
		{
			[System.String]$strEventMessage = 'Failed To Establish PowerShell Session To SfB Online';
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			[System.Management.Automation.Runspaces.PSSession]$objPsSession = $null;
			Return
		}
		
		#==================================================================================
		#endregion Create SfB Online Session
		#==================================================================================
		
		#==================================================================================
		#region Import The SfB Online Session
		#==================================================================================
		
		##### Verify Whether The Session Is Established
		Write-Debug "Verify Whether The Session Is Established";
		If ("$($objPsSession.ComputerName)" -like "*online.lync.com")
		{
			##### Generate Import-PSSession Splat Hash
			Write-Debug "Generate Import-PSSession Splat Hashtable";
			[System.Collections.Specialized.OrderedDictionary]$hshSplat = [Ordered]@{};
			$hshSplat.Add('Session', $objPsSession);
			$hshSplat.Add('AllowClobber', $true);
			$hshSplat.Add('DisableNameChecking', $true);
			$hshSplat.Add('Verbose', $false);
			$hshSplat.Add('Debug', $false);
			$hshSplat.Add('ErrorAction', 'SilentlyContinue');
			$hshSplat.Add('WarningAction', 'SilentlyContinue');
			If (-Not -Not "$($Prefix)") { $hshSplat.Add('Prefix', "$($Prefix)"); }
			
			##### Import The SfB Online Session
			Write-Verbose "Importing The SfB Online Session With Prefix ""$($Prefix)""";
			[System.Management.Automation.PSModuleInfo]$objSesModule = $null;
			[System.Management.Automation.PSModuleInfo]$objSesModule = Import-Module `
				-ModuleInfo ( Import-PSSession @hshSplat ) `
				-Prefix "$($Prefix)" `
				-Global:$true `
				-DisableNameChecking:$true `
				-Force:$true `
				-PassThru:$true;
			#####
		}
		
		##### Verify The PSSession Import
		Write-Debug "Verify The PSSession Import";
		If (-not "$($objSesModule.Name)")
		{
			[System.String]$strEventMessage = 'Failed To Import The SfB Online PowerShell Session';
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			[System.Management.Automation.PSModuleInfo]$objSesModule = $null;
			Return
		}
		
		#==================================================================================
		#endregion Import The SfB Online Session
		#==================================================================================
		
		#==================================================================================
		#region Retrieve The SIP Domains Via The Remote Session
		#==================================================================================
		
		##### Verify The PSSession Import
		Write-Debug "Verify The PSSession Import";
		If (-not -not "$($objSesModule.Name)")
		{
			##### Verify Whether Get-CsOnlineSipDomain Command Is Among The Exported Commands
			Write-Debug 'Verify Whether Get-CsOnlineSipDomain Command Is Among The Exported Commands';
			If ($objSesModule.ExportedCommands.Keys -icontains "Get-$($Prefix)CsOnlineSipDomain")
			{
				##### Generate The SfB Online SIP Domain Array
				Write-Debug 'Generate The SfB Online SIP Domain Array';
				[System.Object[]]$arrSipDomains = @();
				[System.Object[]]$arrSipDomains = Invoke-Command -ScriptBlock $scrBlock -Verbose:$false -Debug:$false;
				
				##### Verify The SfB Online Session Import
				Write-Debug 'Verify The SfB Online Session Import';
				If (($arrSipDomains.Count) -eq 0)
				{
					[System.String]$strEventMessage = 'Failed To Retrieve The CsOnlineSipDomain';
					Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
					
					##### Write Into The Event Log If The Source Is Provided And Exists
					If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
					{
						Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
							-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
						#####
						
						##### Wait A Minute And Kill The Script Process
						Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
						Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
					}
					
					##### Reset the Variable
					Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
					Return
				}
				Else
				{
					##### Continue If Output Is Requested
					Write-Debug "Continue If Output Is Requested";
					If ($PassThru.IsPresent)
					{
						##### Pass The Output Object To The Pipeline
						Write-Debug "Pass Output Object To The Pipeline";
						$PSCmdlet.WriteObject($arrSipDomains);
					}
				}
			}
			Else
			{
				Return
			}
		}
		
		#==================================================================================
		#endregion Retrieve The SIP Domains Via The Remote Session
		#==================================================================================
		
		##### Reset The Variables
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'arrSipDomains';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objSesModule';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objPsSession';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'intCheckSum';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'hshSplat';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objSessionOption';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objCredential';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'scrBlock';
		
		$PSCmdlet.MyInvocation.BoundParameters | Select-Object -ExpandProperty 'Keys' -Verbose:$false -Debug:$false | ForEach `
		{Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name "$($_)"};
	}
	
	##### Override The End Method
	End
	{
		##Stop The StopWatch
		$objCmdStopWatch.Stop();
		Write-Verbose "Command Elapsed: ""$($objCmdStopWatch.ElapsedMilliseconds)"" Milliseconds." ;
		Write-Verbose "End!";
	}
}

##### Connect-SnsExchangeOnPremises ===============================================
Function Connect-SnsExchangeOnPremises ()
{
<#
.SYNOPSIS
This CmdLet Establish Remote PowerShell Session To Exchange On Premises CAS Server.
.DESCRIPTION
This CmdLet Establish Remote PowerShell Session To Exchange On Premises CAS Server.
In Case The Session Creation Fail The CmdLet Can Log An Event In The Windows Event Viewer Application Log And Kill
The Script Process.
This Functionality Is Enabled Automatically When EventSource Parameter Is Provided.
Simple Throwing Of Terminating Error Will Keep The PowerShell Process Running Which Will Prevent The Next Script
Instances From Execution.
Additionally Any Possible Script Monitoring Will Be Cheated That The Script Is Still Running.
Because Of A Bug In Microsoft Import-PSSession Command, The CmdLet Have No Any Parameter Validations.
The Risk Of Providing Wrong Parameter Arguments Or Missing Arguments Remains Entirely With The User.
The CmdLet Have Five Parameter Set:
-- FolderPath Here Have To Be Specified The UserName And The Full Absolute UNC Folder Path Where The Encrypted
Password File Resides.
-- FilePath Here Have To Be Provided The Full Absolute UNC Path To The Credential File. The CmdLet Will Try To
Generate The UserName From The FileName.
-- Credential Here Have To Be Provided System.Management.Automation.PSCredential Object.
-- Interactive It Cannot Be Used Whenever The Script Or The Function Is Executed In As Service Mode.
In This Parameter Set The CmdLet Opens A Window Where The User Can Specify His Credentials.
Obviously When The CmdLet Is Executed As Service There Is No Real Person To Specify The Credentials.
-- Kerberos Here The CmdLet Use The Windows Integrated Authentication With Kerberos In This Scenario Is Created A
Remote Session Within The Security Context Of The Currently Logged On User.
Impersonalizing Is Not Possible In This Scenario.
.PARAMETER HostName
Specifies The Fully Qualified Domain Name Of An Exchange CAS Server Or a CAS Array.
In Case The CAS Array Is Created With Hardware Load Balancer And The PowerShell Virtual Directory Is Not
Published There The Connection Will Fail In This Scenario The Only Way To Connect Is Using CAS Server FQDN.
If Not Provided The CmdLet Will Try To Retrieve The CAS Servers From AD And Chose The Nearest One If ISMP
Protocol Is Enabled In The Environment.
In Case The ICMP Is Not Enabled The CmdLet Will Take The Last Server From The List Where The CAS Servers Are
Sorted Alphabetically.
In Oder The Automatic Finding Of CAS Servers To Work The Exchange Must Be Installed In The Same AD Domain As
The Currently Logged User. In Single Domain Environments It Always Work.
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER UserName
Specifies The UserName
Parameter Set: FolderPath
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER FolderPath
Specifies The Full Absolute UNC Folder Path Where The Credential File Resides
Parameter Set: FolderPath
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER FilePath
Specifies The Full Absolute UNC Path To The Credential File
Parameter Set: FilePath
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Credential
Specifies [System.Management.Automation.PSCredential] Object
Parameter Set: Credential
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Interactive
Specifies That The User Have To Be Asked Interactively For Credentials
Parameter Set: Interactive
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER AuthenticationKerberos
Specifies Whether The Currently Logged On User Security Context Shall Be Used For The Remote Session
It Require The Kerberos Authentication To Be Enabled On The PowerShell Virtual Directory On The CAS Server
Parameter Set: Kerberos
Parameter Alias: Kerberos
Parameter Validation: N/A
.PARAMETER Protocol
Specifies Whether HTTP Or HTTPS Protocol Shall Be Used
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Prefix
Specifies The Prefix For The CmdLets In This Session
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Attempts
Specifies The Number Of Attempts That Have To Be Made To Establish The Remote Session
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER EventSource
Specifies The Application Log Event Source To Be Used For The Error Event Logging
Parameter Set: All
Parameter Alias: ScriptName
Parameter Validation: N/A
.PARAMETER PassThru
Specifies That The CmdLet Have To Revert A Verification Collection.
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.INPUTS
Pipeline Input None
.OUTPUTS
[System.Object[]] Which Contains A List With The On Premises Accepted Domain Objects
.NOTES
AUTHOR:    Svetoslav Nedyalkov Savov (svesavov@hotmail.com)
COPYRIGHT: (c) 2020 Svetoslav Nedyalkov Savov, all rights reserved.
THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
.EXAMPLE
[System.Object[]]$arrAcceptedDomains = Connect-SnsExchangeOnPremises -UserName 'john.smith@contoso.com' `
-FolderPath 'C:\';
.EXAMPLE
[System.Object[]]$arrAcceptedDomains = Connect-SnsExchangeOnPremises `
-FilePath 'C:\john.smith@contoso.com.ini';
.EXAMPLE
[System.Object[]]$arrAcceptedDomains = Connect-SnsExchangeOnPremises -Credential $objCredential;
.EXAMPLE
[System.Object[]]$arrAcceptedDomains = Connect-SnsExchangeOnPremises -Interactive;
.EXAMPLE
[System.Object[]]$arrAcceptedDomains = Connect-SnsExchangeOnPremises -AuthenticationKerberos;
#>
[Alias('New-ExchangeOnPremSession')]
[CmdletBinding(PositionalBinding = $false, DefaultParameterSetName = 'Interactive')]
Param (
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[AllowNull()][AllowEmptyString()][System.String]$HostName,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'FolderPath', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.String]$UserName,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'FolderPath', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.String]$FolderPath,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'FilePath', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.String]$FilePath,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'Credential', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.Management.Automation.PSCredential]$Credential,
	
	[Parameter(Mandatory = $false, ParameterSetName = 'Interactive', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Switch]$Interactive = $false,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'Kerberos', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Alias('Kerberos')]
	[Switch]$AuthenticationKerberos = $false,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateSet('https','http')]
	[System.String]$Protocol = 'https',
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[AllowNull()][AllowEmptyString()][System.String]$Prefix,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.Int32]$Attempts = 3,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Alias('ScriptName')]
	[AllowNull()][AllowEmptyString()][System.String]$EventSource,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Switch]$PassThru
)
	##### Override The Begin Method
	Begin
	{
		Write-Verbose '';
		Write-Verbose "Connect-SnsExchangeOnPremises";
		Write-Debug 'Override Begin Method';
		
		##### Initialize New Measure Watch
		[System.Diagnostics.Stopwatch]$objCmdStopWatch = [System.Diagnostics.Stopwatch]::StartNew();
		
		If ("$((Get-FileHash -Path $PSCommandPath -Algorithm 'SHA256' -Verbose:$false -Debug:$false).Hash)" -ne "$($global:SnsModuleCfg.ModuleHash)")
		{Write-Warning 'There Is New Version Of SnsPsModule Module Released. Please Restart The PowerShell Session.'};
		
		Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName)`r`n";
		
		##### Initialize The Variables
		[System.Net.NetworkInformation.Ping]$objPing = $null;
		[System.Management.Automation.ScriptBlock]$scrBlock = $null;
		[System.Object[]]$arrCasSrvs = @();
		[System.Management.Automation.PSCredential]$objCredential = $null;
		[System.Boolean]$bolTestCred = $false;
		[System.Collections.Specialized.OrderedDictionary]$hshSplat = [Ordered]@{};
		[System.Int32]$intCheckSum = 0;
		[System.Management.Automation.Runspaces.PSSession]$objPsSession = $null;
		[System.Management.Automation.PSModuleInfo]$objSesModule = $null;
		[System.Object[]]$arrAcceptedDomains = @();
		
		##### Generate The Ping Objects
		Write-Debug 'Generate The Ping Objects';
		[System.Net.NetworkInformation.Ping]$objPing = $null;
		[System.Net.NetworkInformation.Ping]$objPing = New-Object -TypeName 'System.Net.NetworkInformation.Ping' -Verbose:$false -Debug:$false;
		
		##### Generate The Verification Script Block
		[System.Management.Automation.ScriptBlock]$scrBlock = $null;
		[System.Management.Automation.ScriptBlock]$scrBlock = `
			[System.Management.Automation.ScriptBlock]::Create("Get-$($Prefix)AcceptedDomain");
		#####
		
		#==================================================================================
		#region Generate The Session Target
		#==================================================================================
		
		##### Verify Whether HostName Is Provided
		Write-Debug 'Verify Whether HostName Is Provided';
		If (-not "$($HostName)")
		{
			##### Retrieve CAS Servers HostName From AD
			Write-Debug 'Retrieve CAS Servers HostName From AD';
			[System.Object[]]$arrCasSrvs = @();
			[System.Object[]]$arrCasSrvs = Search-SnsAdObject `
				-LdapQuery "(&(objectClass=serviceConnectionPoint)(objectCategory=CN=Service-Connection-Point,$( `
					([ADSI]'LDAP://RootDSE').schemaNamingContext `
					))(serviceClassName=ms-Exchange-AutoDiscover-Service))" `
				-SearchRoot "$(([ADSI]'LDAP://RootDSE').configurationNamingContext)" `
				-DomainController "$(([ADSI]'LDAP://RootDSE').dnsHostName)" `
				-ReturnProperties @('serviceDNSName') `
				-Verbose:$false -Debug:$false;
			#####
			
			##### Ping All CAS Servers And Take The Nearest One
			Write-Debug 'Ping All CAS Servers And Take The Nearest One';
			[System.String]$HostName = $arrCasSrvs | Select-Object `
				-Property @{'n'='Fqdn';'e'={"$($_.Properties.servicednsname).$( `
					""$($_.Properties.adspath)"".Substring( `
					""$($_.Properties.adspath)"".IndexOf('DC=')).Replace('DC=', '').Replace(',', '.'))"}} `
				-Verbose:$false -Debug:$false | `
				Select-Object -Property  `
				@(
					'Fqdn',
					@{'n'='TTL';'e'={"$($objPing.Send( `
						""$($_.Fqdn)"", `
						1000, `
						[System.Text.Encoding]::ASCII.GetBytes('S') `
					).Options.Ttl)" -as [System.Int32]}}
				) `
				-Verbose:$false -Debug:$false | `
				Sort-Object -Property @('Ttl','Fqdn') -Descending:$true -Verbose:$false -Debug:$false | `
				Select-Object -First 1 -Verbose:$false -Debug:$false | `
				Select-Object -ExpandProperty 'Fqdn' -Verbose:$false -Debug:$false;
			#####
		}
		
		##### Verify The Target Server Generation
		Write-Debug 'Verify The Target Server Generation';
		If (-not "$($HostName)")
		{
			[System.String]$strEventMessage += "There Is No Destination HostName Provided";
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			[System.String]$HostName = '';
			Return
		}
		
		#==================================================================================
		#endregion Generate The Session Target
		#==================================================================================
		
		#==================================================================================
		#region Create The Credentials Object
		#==================================================================================
		
		###### Verify The Parameter Set Name
		Write-Debug 'Verify The Parameter Set Name';
		Switch ("$($PSCmdlet.ParameterSetName)")
		{
			'FolderPath'
			{
				##### Generate The Credential Object In FolderPath Parameter Set
				Write-Verbose 'Generate The Credential Object In FolderPath Parameter Set';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = Import-SnsCredentialFile `
					-UserName "$($UserName)" -FolderPath "$($FolderPath)" -EventSource "$($EventSource)" `
					-Verbose:$false -Debug:$false;
				#####
				
				Break;
			}
			
			'FilePath'
			{
				##### Generate The Credential Object In FilePath Parameter Set
				Write-Verbose 'Generate The Credential Object In FilePath Parameter Set';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = Import-SnsCredentialFile `
					-FilePath "$($FilePath)" -EventSource "$($EventSource)" `
					-Verbose:$false -Debug:$false;
				#####
				
				Break;
			}
			
			'Credential'
			{
				##### Assign The Provided Credential Object In Credential Parameter Set
				Write-Verbose 'Assign The Provided Credential Object In Credential Parameter Set';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = $Credential;
				#####
				
				Break;
			}
			
			Default
			{
				##### Do Nothing
			}
		}
		
		##### Verify The Provided Credentials
		Write-Debug 'Verify The Parameter Set Name';
		If ( `
			("$($PSCmdlet.ParameterSetName)" -like 'FolderPath') -or `
			("$($PSCmdlet.ParameterSetName)" -like 'FilePath') -or `
			("$($PSCmdlet.ParameterSetName)" -like 'Credential') `
		)
		{
			##### Retrieve An AD DNS Domain Name With Impersonated Credentials
			Write-Debug 'Retrieve An AD DNS Domain Object With Impersonated Credentials';
			[System.Boolean]$bolTestCred = $false;
			[System.Boolean]$bolTestCred = (-not -not `
				"$((New-Object -TypeName 'System.DirectoryServices.DirectoryEntry' -ArgumentList `
				(
					""LDAP://$(([ADSI]'').distinguishedName)"",
					""$($objCredential.UserName)"",
					""$($objCredential.GetNetworkCredential().Password)""
				) -Verbose:$false -Debug:$false).name)" `
			);
			
			##### Verify AD Object Retrieval
			Write-Debug 'Verify AD Object Retrieval';
			If (-not $bolTestCred)
			{
				##### Generate The Error Message
				[System.String]$strEventMessage = 'Provided Credential Are Invalid';
				Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
				
				##### Write Into The Event Log If The Source Is Provided And Exists
				If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
				{
					Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
						-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
					#####
					
					##### Wait A Minute And Kill The Script Process
					Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
					Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
				}
				
				##### Reset the Variable
				Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				Return
			}
		}
		
		##### Verify If It Is Interactive Session Kerberos Wont Be Used And There Are No Credentials
		Write-Debug 'Verify If It Is Interactive Session Kerberos Wont Be Used And There Are No Credentials';
		If ( `
			([Environment]::UserInteractive) -and `
			("$($PSCmdlet.ParameterSetName)" -notlike 'Kerberos') -and `
			((-not "$($objCredential.UserName)") -or (-not $bolTestCred)) `
		)
		{
			##### Loop Interactive Credentials Dialog With The User
			Write-Debug 'Loop Interactive Credentials Dialog With The User';
			Do
			{
				##### Ask The User About Credentials
				Write-Verbose 'Ask The User About Credentials';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = Get-Credential -Verbose:$false -Debug:$false;
				
				##### Check The Credentials
				Write-Debug 'Check The Credentials';
				[System.Boolean]$bolTestCred = $false;
				[System.Boolean]$bolTestCred = (-not -not `
					"$((New-Object -TypeName 'System.DirectoryServices.DirectoryEntry' -ArgumentList `
					(
						""LDAP://$(([ADSI]'').distinguishedName)"",
						""$($objCredential.UserName)"",
						""$($objCredential.GetNetworkCredential().Password)""
					) -Verbose:$false -Debug:$false).name)" `
				);
				
				##### Check The Imported Credentials
				Write-Debug 'Check The Imported Credentials';
				If (-not $bolTestCred)
				{
					##### Generate The Error Message
					Write-Error 'Provided Invalid Credentials' -ErrorAction 'Continue';
					[System.Management.Automation.PSCredential]$objCredential = $null;
				}
			}
			While (-not $bolTestCred)
		}
		
		##### Verify The Credentials Object
		Write-Debug 'Verify The Credentials Object';
		If (("$($PSCmdlet.ParameterSetName)" -notlike 'Kerberos') -and (-not "$($objCredential.UserName)"))
		{
			[System.String]$strEventMessage = 'Failed To Generate The Credential Object For Exchange On Premises';
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			[System.Management.Automation.PSCredential]$objCredential = $null;
			Return
		}
		
		#==================================================================================
		#endregion Create The Credentials Object
		#==================================================================================
		
		#==================================================================================
		#region Create Exchange On Premises Session
		#==================================================================================
		
		##### Verify Any Previous Sessions Existence
		Write-Debug "Verify Any Previous Sessions Existence";
		If (-not -not ( `
			Get-PSSession -Verbose:$false -Debug:$false | `
			Where-Object {"$($_.Name)" -like "$HostName"} -Verbose:$false -Debug:$false `
		))
		{
			##### Disconnect The Previous Sessions
			Write-Verbose 'Removing Previous Sessions'; 
			Get-PSSession -Verbose:$false -Debug:$false | `
				Where-Object {"$($_.Name)" -like "$HostName"} -Verbose:$false -Debug:$false | `
				Remove-PSSession -Confirm:$false -Verbose:$false -Debug:$false;
			#####
		}
		
		##### Verify The Prerequisites For Remote PSSession
		Write-Debug 'Verify The Prerequisites For Remote PSSession';
		If ( `
			(-not -not "$($HostName)") -and `
			( `
				("$($PSCmdlet.ParameterSetName)" -like 'Kerberos') -or `
				(-not -not "$($objCredential.UserName)")
			) `
		)
		{
			##### Create The New-PSSession Splatting HashTable
			Write-Debug "Create The New-PSSession Splatting HashTable";
			[System.Collections.Specialized.OrderedDictionary]$hshSplat = [Ordered]@{};
			$hshSplat.Add('Name', "$($HostName)");
			$hshSplat.Add('ConfigurationName', 'Microsoft.Exchange');
			$hshSplat.Add('ConnectionUri', "$($Protocol)://$($HostName)/PowerShell/");
			$hshSplat.Add('AllowRedirection', $true);
			$hshSplat.Add('SessionOption', $( `
				New-PSSessionOption `
				-SkipCACheck:$true `
				-SkipCNCheck:$true `
				-SkipRevocationCheck:$true `
				-Verbose:$false -Debug:$false `
			));
			$hshSplat.Add('Verbose', $false);
			$hshSplat.Add('Debug', $false);
			
			##### Check The Requested Authentication Type
			Write-Debug "Check The Requested Authentication Type";
			If ("$($PSCmdlet.ParameterSetName)" -like 'Kerberos')
			{
				$hshSplat.Add('Authentication', 'Kerberos');
			}
			Else
			{
				$hshSplat.Add('Authentication', 'Basic');
				$hshSplat.Add('Credential', $objCredential);
			}
			
			##### Loop The Session Creation
			Write-Debug 'Loop The Session Creation';
			[System.Int32]$intCheckSum = 0;
			Do
			{
				##### Establish Exchange On Premises Session
				Write-Verbose "Establish Exchange On Premises Session";
				[System.Management.Automation.Runspaces.PSSession]$objPsSession = $null;
				[System.Management.Automation.Runspaces.PSSession]$objPsSession = New-PSSession @hshSplat;
				#####
				
				##### Process The Loop Variable And TimeOut
				Start-Sleep -Seconds 2 -Verbose:$false -Debug:$false;
				[System.Int32]$intCheckSum = $intCheckSum + 1;
			}
			While (("$($objPsSession.Name)" -notlike "$HostName") -and ($intCheckSum -lt $Attempts))
		}
		
		##### Verify Session Creation
		Write-Debug 'Verify Session Creation';
		If (-not "$($objPsSession.Name)")
		{
			[System.String]$strEventMessage = "Failed To Establish PowerShell Session To $($HostName)";
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			[System.Management.Automation.Runspaces.PSSession]$objPsSession = $null;
			Return
		}
		
		#==================================================================================
		#endregion Create Exchange On Premises Session
		#==================================================================================
		
		#==================================================================================
		#region Import The Exchange On Premises Session
		#==================================================================================
		
		##### Verify Whether The Session Is Established
		Write-Debug "Verify Whether The Session Is Established";
		If (-not -not "$($objPsSession.Name)")
		{
			##### Generate The Import-PSSession Splatting HashTable
			Write-Debug "Generate The Import-PSSession Splatting HashTable";
			[System.Collections.Specialized.OrderedDictionary]$hshSplat = [Ordered]@{};
			$hshSplat.Add('Session', $objPsSession);
			$hshSplat.Add('AllowClobber', $true);
			$hshSplat.Add('DisableNameChecking', $true);
			$hshSplat.Add('Verbose', $false);
			$hshSplat.Add('Debug', $false);
			$hshSplat.Add('ErrorAction', 'SilentlyContinue');
			$hshSplat.Add('WarningAction', 'SilentlyContinue');
			
			##### Check Whether Prefix Is Specified
			If (-not -not "$($Prefix)") { $hshSplat.Add('Prefix', "$($Prefix)"); }
			
			##### Import The Exchange On Premises Session
			Write-Verbose 'Importing The Exchange On Premises Session';
			[System.Management.Automation.PSModuleInfo]$objSesModule = $null;
			[System.Management.Automation.PSModuleInfo]$objSesModule = Import-Module `
				-ModuleInfo ( Import-PSSession @hshSplat ) `
				-Prefix "$($Prefix)" `
				-Global:$true `
				-DisableNameChecking:$true `
				-Force:$true `
				-PassThru:$true;
			#####
		}
		
		##### Verify The PSSession Import
		Write-Debug "Verify The PSSession Import";
		If (-not "$($objSesModule.Name)")
		{
			[System.String]$strEventMessage = 'Failed To Import The Exchange On Premises PowerShell Session';
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			[System.Management.Automation.PSModuleInfo]$objSesModule = $null;
			Return
		}
		
		#==================================================================================
		#endregion Import The Exchange On Premises Session
		#==================================================================================
		
		#==================================================================================
		#region Retrieve The Accepted Domains Via The Remote Session
		#==================================================================================
		
		##### Verify The PSSession Import
		Write-Debug "Verify The PSSession Import";
		If (-not -not "$($objSesModule.Name)")
		{
			##### Verify Whether Get-AcceptedDomain Command Is Among The Exported Commands
			Write-Debug 'Verify Whether Get-AcceptedDomain Command Is Among The Exported Commands';
			If ($objSesModule.ExportedCommands.Keys -icontains "Get-$($Prefix)AcceptedDomain")
			{
				##### Generate The On Premises Accepted Domain Array
				Write-Debug 'Generate The On Premises Accepted Domain Array';
				[System.Object[]]$arrAcceptedDomains = @();
				[System.Object[]]$arrAcceptedDomains = Invoke-Command -ScriptBlock $scrBlock -Verbose:$false -Debug:$false;
				
				##### Verify The Exchange On Premises Session Import
				Write-Debug 'Verify The Exchange On Premises Session Import';
				If (($arrAcceptedDomains.Count) -eq 0)
				{
					[System.String]$strEventMessage = 'Failed To Retrieve The Exchange On Premises AcceptedDomain';
					Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
					
					##### Write Into The Event Log If The Source Is Provided And Exists
					If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
					{
						Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
							-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
						#####
						
						##### Wait A Minute And Kill The Script Process
						Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
						Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
					}
					
					##### Reset the Variable
					Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
					Return
				}
				Else
				{
					##### Continue If Output Is Requested
					Write-Debug "Continue If Output Is Requested";
					If ($PassThru.IsPresent)
					{
						##### Pass The Output Object To The Pipeline
						Write-Debug "Pass Output Object To The Pipeline";
						$PSCmdlet.WriteObject($arrAcceptedDomains);
					}
				}
			}
			Else
			{
				Return
			}
		}
		
		#==================================================================================
		#endregion Retrieve The Accepted Domains Via The Remote Session
		#==================================================================================
		
		##### Reset The Variables
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'arrAcceptedDomains';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objSesModule';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objPsSession';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'intCheckSum';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'hshSplat';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'bolTestCred';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objCredential';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'arrCasSrvs';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'scrBlock';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objPing';
		
		$PSCmdlet.MyInvocation.BoundParameters | Select-Object -ExpandProperty 'Keys' -Verbose:$false -Debug:$false | ForEach `
		{Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name "$($_)"};
	}
	
	##### Override The End Method
	End
	{
		##Stop The StopWatch
		$objCmdStopWatch.Stop();
		Write-Verbose "Command Elapsed: ""$($objCmdStopWatch.ElapsedMilliseconds)"" Milliseconds." ;
		Write-Verbose "End!";
	}
}

##### Connect-SnsExchangeOnline ===================================================
Function Connect-SnsExchangeOnline ()
{
<#
.SYNOPSIS
This CmdLet Establish Remote PowerShell Session To ExchangeOnline In Office 365.
.DESCRIPTION
This CmdLet Establish Remote PowerShell Session To ExchangeOnline In Office 365.
In Case The Session Creation Fail The CmdLet Can Log An Event In The Windows Event Viewer Application Log And Kill
The Script Process. This Functionality Is Enabled Automatically When EventSource Parameter Is Provided. Simple
Throwing Terminating Error Will Keep The PowerShell Process. Which Will Prevent The Next Script Instances From
Execution. And Any Possible Script Monitoring Will Be Cheated That The Script Is Still Running.
Because Of A Bug In Microsoft Import-PSSession Command, The CmdLet Have No Any Parameter Validations.
The Risk Of Providing Wrong Parameter Arguments Or Missing Arguments Remains Entirely With The User.
The CmdLet Have Four Parameter Sets:
-- FolderPath Here Have To Be Specified The UserName And The Full Absolute UNC Folder Path Where The Encrypted
Password File Resides.
-- FilePath Here Have To Be Provided The Full Absolute UNC Path To The Credential File. The CmdLet Will Try To
Generate The UserName From The FileName.
-- Credential Here Have To Be Provided System.Management.Automation.PSCredential Object.
-- Interactive It Cannot Be Used Whenever The Script Or The CmdLet Is Executed In As Service Mode.
In This Parameter Set The CmdLet Opens A Window Where The User Can Specify His Credentials.
Obviously When The CmdLet Is Executed As Service There Is No Real Person To Specify The Credentials.
.PARAMETER UserName
Specifies The UserName
Parameter Set: FolderPath
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER FolderPath
Specifies The Full Absolute UNC Folder Path Where The Credential File Resides
Parameter Set: FolderPath
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER FilePath
Specifies The Full Absolute UNC Path To The Credential File
Parameter Set: FilePath
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Credential
Specifies [System.Management.Automation.PSCredential] Object
Parameter Set: Credential
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Interactive
Specifies That The User Have To Be Asked Interactively For Credentials
Parameter Set: Interactive
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Prefix
Specifies The Prefix For The CmdLets In This Session
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER ProxyAccessType
Specifies The ProxyAccessType
The Best Practice Require Direct Internet Access To Office 365
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: Yes Using Enumeration Validation
.PARAMETER Attempts
Specifies The Number Of Attempts That Have To Be Made To Establish The Remote Session
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER EventSource
Specifies The Application Log Event Source To Be Used For The Error Event Logging
Parameter Set: All
Parameter Alias: ScriptName
Parameter Validation: N/A
.PARAMETER PassThru
Specifies That The CmdLet Have To Revert A Verification Collection.
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.INPUTS
Pipeline Input None
.OUTPUTS
[System.Object[]] Which Contains A List With The ExchangeOnline Accepted Domain Objects
.NOTES
AUTHOR:    Svetoslav Nedyalkov Savov (svesavov@hotmail.com)
COPYRIGHT: (c) 2020 Svetoslav Nedyalkov Savov, all rights reserved.
THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
.EXAMPLE
[System.Object[]]$arrAcceptedDomains = Connect-SnsExchangeOnline -UserName 'john.smith@contoso.com' `
-FolderPath 'C:\';
.EXAMPLE
[System.Object[]]$arrAcceptedDomains = Connect-SnsExchangeOnline -FilePath 'C:\john.smith@contoso.com.ini';
.EXAMPLE
[System.Object[]]$arrAcceptedDomains = Connect-SnsExchangeOnline -Credential $objCredential;
.EXAMPLE
[System.Object[]]$arrAcceptedDomains = Connect-SnsExchangeOnline -Interactive;
#>
[Alias('New-ExoSession')]
[CmdletBinding(PositionalBinding = $false, DefaultParameterSetName = 'Interactive')]
Param (
	[Parameter(Mandatory = $true, ParameterSetName = 'FolderPath', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.String]$UserName,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'FolderPath', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.String]$FolderPath,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'FilePath', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.String]$FilePath,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'Credential', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.Management.Automation.PSCredential]$Credential,
	
	[Parameter(Mandatory = $false, ParameterSetName = 'Interactive', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Switch]$Interactive = $false,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.String]$Prefix,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateSet('IEConfig','WinHttpConfig','AutoDetect','NoProxyServer','None')]
	[System.String]$ProxyAccessType = 'NoProxyServer',
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.Int32]$Attempts = 3,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Alias('ScriptName')]
	[AllowNull()][AllowEmptyString()][System.String]$EventSource,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Switch]$PassThru
)
	##### Override The Begin Method
	Begin
	{
		Write-Verbose '';
		Write-Verbose "Connect-SnsExchangeOnline";
		Write-Debug 'Override Begin Method';
		
		##### Initialize New Measure Watch
		[System.Diagnostics.Stopwatch]$objCmdStopWatch = [System.Diagnostics.Stopwatch]::StartNew();
		
		If ("$((Get-FileHash -Path $PSCommandPath -Algorithm 'SHA256' -Verbose:$false -Debug:$false).Hash)" -ne "$($global:SnsModuleCfg.ModuleHash)")
		{Write-Warning 'There Is New Version Of SnsPsModule Module Released. Please Restart The PowerShell Session.'};
		
		Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName)`r`n";
		
		##### Initialize The Variables
		[System.Management.Automation.ScriptBlock]$scrBlock = $null;
		[System.Management.Automation.PSCredential]$objCredential = $null;
		[System.Collections.Specialized.OrderedDictionary]$hshSplat = [Ordered]@{};
		[System.Int32]$intCheckSum = 0;
		[System.Management.Automation.Runspaces.PSSession]$objPsSession = $null;
		[System.Management.Automation.PSModuleInfo]$objSesModule = $null;
		[System.Object[]]$arrAcceptedDomains = @();
		
		##### Generate The Verification Script Block
		[System.Management.Automation.ScriptBlock]$scrBlock = `
			[System.Management.Automation.ScriptBlock]::Create("Get-$($Prefix)AcceptedDomain");
		#####
		
		#==================================================================================
		#region Create The Credentials Object
		#==================================================================================
		
		###### Generate The Credential Object In FolderPath Parameter Set
		Write-Debug 'Verify The Parameter Set Name';
		Switch ("$($PSCmdlet.ParameterSetName)")
		{
			'FolderPath'
			{
				##### Generate The Credential Object In FolderPath Parameter Set
				Write-Verbose 'Generate The Credential Object In FolderPath Parameter Set';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = Import-SnsCredentialFile `
					-UserName "$($UserName)" -FolderPath "$($FolderPath)" -EventSource "$($EventSource)" `
					-Verbose:$false -Debug:$false;
				#####
			}
			
			'FilePath'
			{
				##### Generate The Credential Object In FilePath Parameter Set
				Write-Verbose 'Generate The Credential Object In FilePath Parameter Set';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = Import-SnsCredentialFile `
					-FilePath "$($FilePath)" -EventSource "$($EventSource)" `
					-Verbose:$false -Debug:$false;
				#####
			}
			
			'Credential'
			{
				##### Assign The Provided Credential Object In Credential Parameter Set
				Write-Verbose 'Assign The Provided Credential Object In Credential Parameter Set';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = $Credential;
				#####
			}
		}
		
		##### This ExchangeOnline Session Uses Basic Authentication Only
		##### Therefore The Credential Object Is Mandatory
		##### Ask The User Interactively If No Any Credential
		While ((-not "$($objCredential.UserName)") -and ([Environment]::UserInteractive))
		{
			##### Ask The User About Credentials
			Write-Verbose 'Ask The User About Credentials';
			[System.Management.Automation.PSCredential]$objCredential = $null;
			[System.Management.Automation.PSCredential]$objCredential = Get-Credential -Verbose:$false -Debug:$false;
		}
		
		##### Verify The Credential Object
		Write-Debug 'Verify The Credential Object';
		If (-not "$($objCredential.UserName)")
		{
			[System.String]$strEventMessage = 'Failed To Generate The Credential For ExchangeOnline';
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			[System.Management.Automation.PSCredential]$objCredential = $null;
			Return
		}
		
		#==================================================================================
		#endregion Create The Credentials Object
		#==================================================================================
		
		#==================================================================================
		#region Create ExchangeOnline Session
		#==================================================================================
		
		##### Verify Any Previous Sessions Existence
		Write-Debug "Verify Any Previous Sessions Existence";
		If (-not -not ( `
			Get-PSSession -Verbose:$false -Debug:$false | `
			Where-Object {"$($_.Name)" -like 'ExchangeOnline'} -Verbose:$false -Debug:$false `
		))
		{
			##### Disconnect The Previous Sessions
			Write-Verbose 'Removing Previous Sessions'; 
			Get-PSSession -Verbose:$false -Debug:$false | `
				Where-Object {"$($_.Name)" -like 'ExchangeOnline'} -Verbose:$false -Debug:$false | `
				Remove-PSSession -Confirm:$false -Verbose:$false -Debug:$false;
			#####
		}
		
		##### Prepare The Host Machine For Remote PSSession
		Write-Debug "Prepare The Host Machine For Remote PSSession";
		If (-not ( `
			Prepare-SnsHostForRemoteSessions "$($EventSource)" `
			-WhatIf:$false -Confirm:$false `
			-Verbose:$false -Debug:$false `
		))
		{
			Return
		}
		
		##### Verify The Prerequisites For Remote PSSession
		Write-Debug 'Verify The Prerequisites For Remote PSSession';
		If (-not -not "$($objCredential.UserName)")
		{
			##### Generate The New-PSSession Splatting HashTable
			Write-Debug "Generate The New-PSSession Splatting HashTable";
			[System.Collections.Specialized.OrderedDictionary]$hshSplat = [Ordered]@{};
			$hshSplat.Add('Name', 'ExchangeOnline');
			$hshSplat.Add('ConfigurationName', 'Microsoft.Exchange');
			$hshSplat.Add('ConnectionUri', 'https://ps.outlook.com/powershell');
			$hshSplat.Add('Authentication', 'Basic');
			$hshSplat.Add('Credential', $objCredential);
			$hshSplat.Add('AllowRedirection', $true);
			$hshSplat.Add('SessionOption', $( `
				New-PSSessionOption `
					-SkipRevocationCheck:$true `
					-SkipCACheck:$true `
					-SkipCNCheck:$true `
					-ProxyAccessType "$($ProxyAccessType)" `
					-Verbose:$false -Debug:$false `
			));
			$hshSplat.Add('Verbose', $false);
			$hshSplat.Add('Debug', $false);
			$hshSplat.Add('ErrorAction', 'SilentlyContinue');
			$hshSplat.Add('WarningAction', 'SilentlyContinue');
			
			##### Loop The Session Creation
			Write-Debug 'Loop The Session Creation';
			[System.Int32]$intCheckSum = 0;
			Do
			{
				##### Establish The ExchangeOnline Session
				Write-Verbose 'Establish The ExchangeOnline Session';
				[System.Management.Automation.Runspaces.PSSession]$objPsSession = $null;
				[System.Management.Automation.Runspaces.PSSession]$objPsSession = New-PSSession @hshSplat;
				#####
				
				##### Process The Loop Variable And TimeOut
				Start-Sleep -Seconds 2 -Verbose:$false -Debug:$false;
				[System.Int32]$intCheckSum = $intCheckSum + 1;
			}
			While (("$($objPsSession.Name)" -notlike 'ExchangeOnline') -and ($intCheckSum -lt $Attempts))
		}
		
		##### Verify Session Creation
		Write-Debug 'Verify Session Creation';
		If (-not "$($objPsSession.Name)")
		{
			[System.String]$strEventMessage = 'Failed To Establish PowerShell Session To ExchangeOnline';
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			[System.Management.Automation.Runspaces.PSSession]$objPsSession = $null;
			Return
		}
		
		#==================================================================================
		#endregion Create ExchangeOnline Session
		#==================================================================================
		
		#==================================================================================
		#region Import The ExchangeOnline Session
		#==================================================================================
		
		##### Verify Whether The Session Is Established
		Write-Debug "Verify Whether The Session Is Established";
		If (-not -not "$($objPsSession.Name)")
		{
			##### Generate The Import-PSSession Splatting HashTable
			Write-Debug "Generate The Import-PSSession Splatting HashTable";
			[System.Collections.Specialized.OrderedDictionary]$hshSplat = [Ordered]@{};
			$hshSplat.Add('Session', $objPsSession);
			$hshSplat.Add('AllowClobber', $true);
			$hshSplat.Add('DisableNameChecking', $true);
			$hshSplat.Add('Verbose', $false);
			$hshSplat.Add('Debug', $false);
			$hshSplat.Add('ErrorAction', 'SilentlyContinue');
			$hshSplat.Add('WarningAction', 'SilentlyContinue');
			
			##### Verify Whether Prefix Is Specified
			Write-Debug "Verify Whether Prefix Is Specified";
			If (-Not -Not "$($Prefix)") { $hshSplat.Add('Prefix', "$($Prefix)"); }
			
			##### Import The ExchangeOnline Session
			Write-Verbose "Importing The ExchangeOnline Session With Prefix ""$($Prefix)""";
			[System.Management.Automation.PSModuleInfo]$objSesModule = $null;
			[System.Management.Automation.PSModuleInfo]$objSesModule = Import-Module `
				-ModuleInfo ( Import-PSSession @hshSplat ) `
				-Prefix "$($Prefix)" `
				-Global:$true `
				-DisableNameChecking:$true `
				-Force:$true `
				-PassThru:$true `
				-Verbose:$false -Debug:$false;
			#####
		}
		
		##### Verify The PSSession Import
		Write-Debug "Verify The PSSession Import";
		If (-not "$($objSesModule.Name)")
		{
			[System.String]$strEventMessage = 'Failed To Import The ExchangeOnline PowerShell Session';
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			[System.Management.Automation.PSModuleInfo]$objSesModule = $null;
			Return
		}
		
		#==================================================================================
		#endregion Import The ExchangeOnline Session
		#==================================================================================
		
		#==================================================================================
		#region Retrieve The Accepted Domains Via The Remote Session
		#==================================================================================
		
		##### Verify The PSSession Import
		Write-Debug "Verify The PSSession Import";
		If (-not -not "$($objSesModule.Name)")
		{
			##### Verify Whether Get-AcceptedDomain Command Is Among The Exported Commands
			Write-Debug 'Verify Whether Get-AcceptedDomain Command Is Among The Exported Commands';
			If ($objSesModule.ExportedCommands.Keys -icontains "Get-$($Prefix)AcceptedDomain")
			{
				##### Generate The ExchangeOnline Accepted Domain Array
				Write-Debug 'Generate The ExchangeOnline Accepted Domain Array';
				[System.Object[]]$arrAcceptedDomains = @();
				[System.Object[]]$arrAcceptedDomains = Invoke-Command -ScriptBlock $scrBlock -Verbose:$false -Debug:$false;
				
				##### Verify The ExchangeOnline Accepted Domain Array
				Write-Debug 'Verify The ExchangeOnline Accepted Domain Array';
				If (($arrAcceptedDomains.Count) -eq 0)
				{
					[System.String]$strEventMessage = 'Failed To Retrieve The ExchangeOnline AcceptedDomain';
					Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
					
					##### Write Into The Event Log If The Source Is Provided And Exists
					If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
					{
						Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
							-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
						#####
						
						##### Wait A Minute And Kill The Script Process
						Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
						Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
					}
					
					##### Reset the Variable
					Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
					Return
				}
				Else
				{
					##### Continue If Output Is Requested
					Write-Debug "Continue If Output Is Requested";
					If ($PassThru.IsPresent)
					{
						##### Pass The Output Object To The Pipeline
						Write-Debug "Pass Output Object To The Pipeline";
						$PSCmdlet.WriteObject($arrAcceptedDomains);
					}
				}
			}
			Else
			{
				Return
			}
		}
		
		#==================================================================================
		#endregion Retrieve The Accepted Domains Via The Remote Session
		#==================================================================================
		
		##### Reset The Variables
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'arrAcceptedDomains';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objSesModule';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objPsSession';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'intCheckSum';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'hshSplat';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objCredential';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'scrBlock';
		
		$PSCmdlet.MyInvocation.BoundParameters | Select-Object -ExpandProperty 'Keys' -Verbose:$false -Debug:$false | ForEach `
		{Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name "$($_)"};
	}
	
	##### Override The End Method
	End
	{
		##Stop The StopWatch
		$objCmdStopWatch.Stop();
		Write-Verbose "Command Elapsed: ""$($objCmdStopWatch.ElapsedMilliseconds)"" Milliseconds." ;
		Write-Verbose "End!";
	}
}

##### Connect-SnsSharePointOnline =================================================
Function Connect-SnsSharePointOnline ()
{
<#
.SYNOPSIS
This CmdLet Establish Remote PowerShell Session To SharePoint Online In Office 365.
.DESCRIPTION
This CmdLet Establish Remote PowerShell Session To SharePoint Online In Office 365.
In Case The Session Creation Fail The CmdLet Can Log An Event In The Windows Event Viewer Application Log And Kill
The Script Process. This Functionality Is Enabled Automatically When EventSource Parameter Is Provided. Simple
Throwing Terminating Error Will Keep The PowerShell Process Which Will Prevent The Next Script Instances From
Execution And Any Possible Script Monitoring Will Be Cheated That The Script Is Still Running.
Because Of A Bug In Microsoft Import-PSSession Command, The CmdLet Have No Any Parameter Validations.
The Risk Of Providing Wrong Parameter Arguments Or Missing Arguments Remains Entirely With The User.
The CmdLet Have Four Parameter Sets:
-- FolderPath Here Have To Be Specified The UserName And The Full Absolute UNC Folder Path Where The Encrypted
Password File Resides.
-- FilePath Here Have To Be Provided The Full Absolute UNC Path To The Credential File. The CmdLet Will Try To
Generate The UserName From The FileName.
-- Credential Here Have To Be Provided System.Management.Automation.PSCredential Object.
-- Interactive This Is The Only Parameter Set Which Is Capable To Establish Remote PowerShell Session To Skype For
Business Online With Multifactor Authentication. However It Cannot Be Used Whenever The Script Or The Function Is
Executed In As Service Mode. In This Parameter Set The CmdLet Opens A Window Where The User Can Specify His
Credentials And Multi Factor Authentication Code Received On A SMS Or Inside A Phone App Or Phone Call And Etc.
Obviously When The CmdLet Is Executed As Service There Is No Real Person To Specify The Credentials And The MFA
Code. Depending Of The Configuration There Might Not Be PowerShell Host Console Window Either.
NOTE: The CmdLet Requires Microsoft.Online.SharePoint.PowerShell Module To Be Installed In Advance
https://bit.ly/315AQoE
NOTE: The CmdLet Requires The Host To Be Prepared For Remote PowerShell With Enable-PSRemoting And Then
Disable-PSRemoting. Actually The Host Does Not Require To Accept Remote Sessions. However Without Preparing And
Then Removing The Remote Sessions Accepting The Generation Of Remote Sessions To Other Hosts Does Not Work As Well.
.PARAMETER UserName
Specifies The UserName
Parameter Set: FolderPath And Interactive
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER FolderPath
Specifies The Full Absolute UNC Folder Path Where The Credential File Resides
Parameter Set: FolderPath
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER FilePath
Specifies The Full Absolute UNC Path To The Credential File
Parameter Set: FilePath
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Credential
Specifies [System.Management.Automation.PSCredential] Object
Parameter Set: Credential
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Interactive
Specifies That The User Have To Be Asked Interactively For Credentials
Parameter Set: Interactive
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER AuthenticationUrl
Location For AAD Cross-Tenant Authentication Service. Can Be Optionally Used If Non-Default Cross-Tenant Authentication Service Is Used.
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER ClientTag
Permits Appending A Client Tag To Existing Client Tag. Used Optionally In The CSOM http Traffic To Identify Used Script Or Solution.
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Region
Specifies The Office 365 Regional Instances.
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: Yes, Using Enumeration Validation.
.PARAMETER TenantName
Specifies The Office 365 Tenant Name To Which have To Be Established A Connection.
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Attempts
Specifies The Number Of Attempts That Have To Be Made To Establish The Remote Session
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER EventSource
Specifies The Application Log Event Source To Be Used For The Error Event Logging
Parameter Set: All
Parameter Alias: ScriptName
Parameter Validation: N/A
.PARAMETER PassThru
Specifies That The CmdLet Have To Revert A Verification Collection.
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.INPUTS
Pipeline Input None
.OUTPUTS
[System.Object[]] Which Contains A List With The Skype For Business Online SIP Domain Objects
.NOTES
AUTHOR:    Svetoslav Nedyalkov Savov (svesavov@hotmail.com)
COPYRIGHT: (c) 2020 Svetoslav Nedyalkov Savov, all rights reserved.
THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
.EXAMPLE
[System.Object]$objSpTenant = Connect-SnsSharePointOnline -UserName 'john.smith@contoso.com' `
-FolderPath 'C:\';
.EXAMPLE
[System.Object]$objSpTenant = Connect-SnsSharePointOnline -FilePath 'C:\john.smith@contoso.com.ini';
.EXAMPLE
[System.Object]$objSpTenant = Connect-SnsSharePointOnline -Credential $objCredential;
.EXAMPLE
[System.Object]$objSpTenant = Connect-SnsSharePointOnline -UserName 'john.smith@contoso.com' -Interactive;
#>
[Alias('New-SfbOnlineSession')]
[CmdletBinding(PositionalBinding = $false, DefaultParameterSetName = 'Interactive')]
Param (
	[Parameter(Mandatory = $true, ParameterSetName = 'FolderPath', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.String]$UserName,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'FolderPath', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.String]$FolderPath,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'FilePath', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.String]$FilePath,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'Credential', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.Management.Automation.PSCredential]$Credential,
	
	[Parameter(Mandatory = $false, ParameterSetName = 'Interactive', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Switch]$Interactive = $false,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.String]$AuthenticationUrl,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.String]$ClientTag,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateSet("Default", "ITAR", "Germany", "China")]
	[System.String]$Region = "Default",
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.String]$TenantName,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[System.Int32]$Attempts = 3,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Alias('ScriptName')]
	[AllowNull()][AllowEmptyString()][System.String]$EventSource,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Switch]$PassThru
)
	##### Override The Begin Method
	Begin
	{
		Write-Verbose '';
		Write-Verbose "Connect-SnsSharePointOnline";
		Write-Debug 'Override Begin Method';
		
		##### Initialize New Measure Watch
		[System.Diagnostics.Stopwatch]$objCmdStopWatch = [System.Diagnostics.Stopwatch]::StartNew();
		
		If ("$((Get-FileHash -Path $PSCommandPath -Algorithm 'SHA256' -Verbose:$false -Debug:$false).Hash)" -ne "$($global:SnsModuleCfg.ModuleHash)")
		{Write-Warning 'There Is New Version Of SnsPsModule Module Released. Please Restart The PowerShell Session.'};
		
		Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName)`r`n";
		
		##### Initialize The Variables
		[System.Management.Automation.ScriptBlock]$scrBlock = $null;
		[System.Management.Automation.PSCredential]$objCredential = $null;
		[System.Collections.Specialized.OrderedDictionary]$hshSplat = [Ordered]@{};
		[System.Int32]$intCheckSum = 0;
		[System.Object]$objSpTenant = $null;
		
		##### Generate The Verification Script Block
		[System.Management.Automation.ScriptBlock]$scrBlock = `
			[System.Management.Automation.ScriptBlock]::Create("Get-SPOTenant");
		#####
		
		#==================================================================================
		#region Load Microsoft.Online.SharePoint.PowerShell Module
		#==================================================================================
		
		##### Verify Microsoft.Online.SharePoint.PowerShell Module Existence
		Write-Debug 'Verify Microsoft.Online.SharePoint.PowerShell Module Existence';
		If (-not (Get-Module -Name 'Microsoft.Online.SharePoint.PowerShell' -ListAvailable -Verbose:$false -Debug:$false))
		{
			[System.String]$strEventMessage = 'Module Microsoft.Online.SharePoint.PowerShell Is Not Installed';
			[System.String]$strEventMessage += "`r`nPlease Refer To https://bit.ly/315AQoE";
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			Return
		}
		
		##### Load Microsoft.Online.SharePoint.PowerShell Module
		Write-Debug 'Load Microsoft.Online.SharePoint.PowerShell Module';
		If ((-not (Get-Module -Name 'Microsoft.Online.SharePoint.PowerShell' -Verbose:$false -Debug:$false)) -and `
			(-not -not (Get-Module -Name 'Microsoft.Online.SharePoint.PowerShell' -ListAvailable -Verbose:$false -Debug:$false)))
		{
			Write-Host 'Import Microsoft.Online.SharePoint.PowerShell Module' -ForegroundColor 'Green';
			Import-Module -Name 'Microsoft.Online.SharePoint.PowerShell' -Global:$true -Force:$true -Verbose:$false -Debug:$false;
		}
		
		##### Verify Microsoft.Online.SharePoint.PowerShell Module Load
		Write-Debug 'Verify Microsoft.Online.SharePoint.PowerShell Module Load';
		If (-not (Get-Module -Name 'Microsoft.Online.SharePoint.PowerShell' -Verbose:$false -Debug:$false))
		{
			[System.String]$strEventMessage = 'Failed To Load Module Microsoft.Online.SharePoint.PowerShell';
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			Return
		}
		
		#==================================================================================
		#endregion Load Microsoft.Online.SharePoint.PowerShell Module
		#==================================================================================
		
		#==================================================================================
		#region Validate TenantName Input
		#==================================================================================
		
		##### Verify Whether Tenant Name Is Provided
		Write-Debug "Verify Whether Tenant Name Is Provided";
		If (-not "$($TenantName)")
		{
			##### Tenant Is Not Provided
			##### Check If The Host Belongs To Known AD Domain
			If ( `
				"$((Get-CimInstance -Namespace 'root\CIMV2' `
					-ClassName 'Win32_ComputerSystem' `
					-Verbose:$false -Debug:$false).Domain)" `
				-eq `
				'Betgenius.local' `
			)
			{
				##### This Is Known Domain
				##### Assign Known Value Of "geniussportsgroup"
				Write-Verbose "Assign Known Value Of geniussportsgroup";
				[System.String]$TenantName = "geniussportsgroup";
			}
			Else
			{
				[System.String]$strEventMessage = 'Cannot Validate The Input Of Parameter TenantName.';
				Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
				
				##### Write Into The Event Log If The Source Is Provided And Exists
				If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
				{
					Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
						-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
					#####
					
					##### Wait A Minute And Kill The Script Process
					Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
					Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
				}
				
				##### Reset the Variable
				Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
				Return
			}
		}
		
		#==================================================================================
		#endregion Validate TenantName Input
		#==================================================================================
		
		#==================================================================================
		#region Create The Credentials Object
		#==================================================================================
		
		###### Generate The Credential Object In FolderPath Parameter Set
		Write-Debug 'Verify The Parameter Set Name';
		Switch ("$($PSCmdlet.ParameterSetName)")
		{
			'FolderPath'
			{
				##### Generate The Credential Object In FolderPath Parameter Set
				Write-Verbose 'Generate The Credential Object In FolderPath Parameter Set';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = Import-SnsCredentialFile `
					-UserName "$($UserName)" -FolderPath "$($FolderPath)" -EventSource "$($EventSource)" `
					-Verbose:$false -Debug:$false;
				#####
			}
			
			'FilePath'
			{
				##### Generate The Credential Object In FilePath Parameter Set
				Write-Verbose 'Generate The Credential Object In FilePath Parameter Set';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = Import-SnsCredentialFile `
					-FilePath "$($FilePath)" -EventSource "$($EventSource)" `
					-Verbose:$false -Debug:$false;
				#####
			}
			
			'Credential'
			{
				##### Assign The Provided Credential Object In Credential Parameter Set
				Write-Verbose 'Assign The Provided Credential Object In Credential Parameter Set';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = $Credential;
				#####
			}
		}
		
		##### Verify The Credential Object
		Write-Debug 'Verify The Credential Object';
		If ((-not [Environment]::UserInteractive) -and (-not "$($objCredential.UserName)"))
		{
			[System.String]$strEventMessage = 'Failed To Generate The Credential For SfB Online';
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			[System.Management.Automation.PSCredential]$objCredential = $null;
			Return
		}
		
		#==================================================================================
		#endregion Create The Credentials Object
		#==================================================================================
		
		#==================================================================================
		#region Create SharePoint Online Session
		#==================================================================================
		
		##### Verify Any Previous Sessions Existence
		Write-Debug "Verify Any Previous Sessions Existence";
		If (-Not -Not ( `
			Get-Variable -Verbose:$false -Debug:$false | `
			Where-Object {"$($_.Name)" -like 'ObjSpoTenant'} -Verbose:$false -Debug:$false `
		))
		{
			##### Disconnect The Previous Sessions
			Write-Verbose 'Removing Previous Sessions'; 
			Disconnect-SPOService -Verbose:$false -Debug:$false | Out-Null;
			#####
		}
		
		##### Prepare The Host Machine For Remote PSSession
		Write-Debug "Prepare The Host Machine For Remote PSSession";
		If (-not ( `
			Prepare-SnsHostForRemoteSessions "$($EventSource)" `
			-WhatIf:$false -Confirm:$false `
			-Verbose:$false -Debug:$false `
		))
		{
			Return
		}
		
		##### Generate The Splatting HashTable
		Write-Debug "Generate The Splatting HashTable For New-CsOnlineSession";
		[System.Collections.Specialized.OrderedDictionary]$hshSplat = [Ordered]@{};
		If (-not -not "$($AuthenticationUrl)") { $hshSplat.Add('AuthenticationUrl', $AuthenticationUrl); }
		If (-not -not "$($ClientTag)") { $hshSplat.Add('ClientTag', $ClientTag); }
		If (-not -not "$($Region)") { $hshSplat.Add('Region', $Region); }
		$hshSplat.Add('Url', "https://$($TenantName)-admin.sharepoint.com");
		$hshSplat.Add('Verbose', $false);
		$hshSplat.Add('Debug', $false);
		
		##### Check Credential Object Existence
		Write-Debug 'Check Credential Object Existence';
		If (-not -not "$($objCredential.UserName)") {$hshSplat.Add('Credential', $objCredential);}
		
		##### Loop The Session Creation
		Write-Debug 'Loop The Session Creation';
		[System.Int32]$intCheckSum = 0;
		[System.Object]$objSpTenant = $null;
		Do
		{
			##### Establish The SharePoint Online Session
			Write-Verbose 'Establish The SharePoint Online Session';
			Connect-SPOService @hshSplat | Out-Null;
			
			##### Process The Loop Variable And TimeOut
			Start-Sleep -Seconds 2; [System.Int32]$intCheckSum = $intCheckSum + 1;
			
			[System.Object]$objSpTenant = $null;
			[System.Object]$objSpTenant = Invoke-Command -ScriptBlock $scrBlock -Verbose:$false -Debug:$false;
		}
		While ((-not "$($objSpTenant.SharingCapability)") -and ($intCheckSum -lt $Attempts))
		
		##### Verify Session Creation
		Write-Debug 'Verify Session Creation';
		If (-not "$($objSpTenant.SharingCapability)")
		{
			[System.String]$strEventMessage = 'Failed To Establish PowerShell Session To SharePoint Online';
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			Return
		}
		
		#==================================================================================
		#endregion Create SharePoint Online Session
		#==================================================================================
		
		#==================================================================================
		#region Generate The Output Objects
		#==================================================================================
		
		##### Verify The PSSession Import
		Write-Debug "Verify The PSSession Import";
		If (-not -not "$($objSpTenant.SharingCapability)")
		{
			##### Verify Whether The Global SharePoint Online Tenant Variable Exists
			Write-Debug "Verify Whether The Global SharePoint Online Tenant Variable Exists";
			If (-not ( `
				Get-Variable -Verbose:$false -Debug:$false | `
				Where-Object {"$($_.Name)" -like 'ObjSpoTenant'} -Verbose:$false -Debug:$false `
			))
			{
				##### Create The Global SharePoint Online Tenant Variable
				Write-Debug "Create The Global SharePoint Online Tenant Variable";
				New-Variable -Scope 'Global' -Option 'Constant' -Name 'ObjSpoTenant' -Value ($objSpTenant);
			}
			
			##### Continue If Output Is Requested
			Write-Debug "Continue If Output Is Requested";
			If ($PassThru.IsPresent)
			{
				##### Pass The Output Object To The Pipeline
				Write-Debug "Pass Output Object To The Pipeline";
				$PSCmdlet.WriteObject($objSpTenant);
			}
		}
		
		#==================================================================================
		#endregion Retrieve The SIP Domains Via The Remote Session
		#==================================================================================
		
		##### Reset The Variables
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objSpTenant';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'intCheckSum';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'hshSplat';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objCredential';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'scrBlock';
		
		$PSCmdlet.MyInvocation.BoundParameters | Select-Object -ExpandProperty 'Keys' -Verbose:$false -Debug:$false | ForEach `
		{Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name "$($_)"};
	}
	
	##### Override The End Method
	End
	{
		##Stop The StopWatch
		$objCmdStopWatch.Stop();
		Write-Verbose "Command Elapsed: ""$($objCmdStopWatch.ElapsedMilliseconds)"" Milliseconds." ;
		Write-Verbose "End!";
	}
}

##### Connect-SnsAzureAd ==========================================================
Function Connect-SnsAzureAd ()
{
<#
.SYNOPSIS
This CmdLet Establish A Remote PowerShell Session To Office 365 AzureAD V2 Service.
.DESCRIPTION
This CmdLet Establish A Remote PowerShell Session To Office 365 AzureAD V2 Service.
The CmdLet Have Four Parameter Sets:
-- FolderPath Here Have To Be Specified The UserName And The Full Absolute UNC Folder Path Where The Encrypted
Password File Resides.
-- FilePath Here Have To Be Provided The Full Absolute UNC Path To The Credential File. The CmdLet Will Try To
Generate The UserName From The FileName.
-- Credential Here Have To Be Provided System.Management.Automation.PSCredential Object.
-- Interactive This Is The Only Parameter Set Which Is Capable To Establish Remote PowerShell Session To AzureAD
V2 Service With Multifactor Authentication. However It Cannot Be Used Whenever The Script Or The Function Is
Executed In As Service Mode.
In This Parameter Set The CmdLet Opens A Window Where The User Can Specify His Credentials And Multi Factor
Authentication Code Received On A SMS Or Inside A Phone App Or Phone Call And Etc.
Obviously When The CmdLet Is Executed As Service There Is No Real Person To Specify The Credentials And The MFA
Code. Depending Of The Configuration There Might Not Be PowerShell Host Console Window Either.
NOTE: The CmdLet Requires AzureAD V2 Module To Be Installed In Advance. Please Refer To https://bit.ly/30VWxaV
NOTE: There Must Be A Direct Connection / Firewall Openings To Office 365. Proxy Usage Is Not Allowed.
.PARAMETER UserName
Specifies The UserName In UPN Format.
Parameter Set: FolderPath
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER FolderPath
Specifies The Full Absolute UNC Folder Path Where The Credential File Resides.
Parameter Set: FolderPath
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER FilePath
Specifies The Full Absolute UNC Path To The Credential File.
Parameter Set: FilePath
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Credential
Specifies [System.Management.Automation.PSCredential] Object.
Parameter Set: Credential
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Interactive
Specifies That The User Have To Be Asked Interactively For Credentials.
Parameter Set: Interactive
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Attempts
Specifies The Number Of Attempts That Have To Be Made To Establish The Remote Session.
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER EventSource
Specifies The Application Log Event Source To Be Used For The Error Event Logging.
Parameter Set: All
Parameter Alias: ScriptName
Parameter Validation: N/A
.PARAMETER PassThru
Specifies That The CmdLet Have To Revert A Verification Collection.
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.INPUTS
Pipeline Input None
.OUTPUTS
[System.Object[]] Which Contains A List With The Available AzureAD License Objects.
.NOTES
AUTHOR:    Svetoslav Nedyalkov Savov (svesavov@hotmail.com)
COPYRIGHT: (c) 2020 Svetoslav Nedyalkov Savov, all rights reserved.
THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
.EXAMPLE
[System.Object[]]$arrAzureLicenses = Connect-SnsAzureAd -UserName 'john.smith@contoso.com' `
-FolderPath 'C:\';
.EXAMPLE
[System.Object[]]$arrAzureLicenses = Connect-SnsAzureAd -FilePath 'C:\john.smith@contoso.com.ini';
.EXAMPLE
[System.Object[]]$arrAzureLicenses = Connect-SnsAzureAd -Credential $objCredential;
.EXAMPLE
[System.Object[]]$arrAzureLicenses = Connect-SnsAzureAd -Interactive;
#>
[CmdletBinding(PositionalBinding = $false, DefaultParameterSetName = 'Interactive')]
Param (
	[Parameter(Mandatory = $true, ParameterSetName = 'FolderPath', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateNotNullOrEmpty()][System.String]$UserName,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'FolderPath', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateScript({("$($_)" -eq "$($_.Trim())")})]
	[ValidateScript({("$($_)" -like "*\*")})]
	[ValidateScript({(Test-Path -Path "$($_)" -PathType 'Container')})]
	[ValidateNotNullOrEmpty()][System.String]$FolderPath,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'FilePath', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateScript({("$($_)" -eq "$($_.Trim())")})]
	[ValidateScript({("$($_)" -like "*\*.ini")})]
	[ValidateScript({(Test-Path -Path "$($_)" -PathType 'Leaf')})]
	[ValidateNotNullOrEmpty()][System.String]$FilePath,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'Credential', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateNotNullOrEmpty()][System.Management.Automation.PSCredential]$Credential,
	
	[Parameter(Mandatory = $false, ParameterSetName = 'Interactive', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Switch]$Interactive = $false,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateNotNullOrEmpty()][System.Int32]$Attempts = 3,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Alias('ScriptName')]
	[AllowNull()][AllowEmptyString()][System.String]$EventSource,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Switch]$PassThru
)
	##### Override The Begin Method
	Begin
	{
		Write-Verbose '';
		Write-Verbose "Connect-SnsAzureAd";
		Write-Debug 'Override Begin Method';
		
		##### Initialize New Measure Watch
		[System.Diagnostics.Stopwatch]$objCmdStopWatch = [System.Diagnostics.Stopwatch]::StartNew();
		
		If ("$((Get-FileHash -Path $PSCommandPath -Algorithm 'SHA256' -Verbose:$false -Debug:$false).Hash)" -ne "$($global:SnsModuleCfg.ModuleHash)")
		{Write-Warning 'There Is New Version Of SnsPsModule Module Released. Please Restart The PowerShell Session.'};
		
		Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName)`r`n";
		
		##### Initialize The Variables
		[System.String]$strModule = "AzureADPreview";
		[System.Management.Automation.PSCredential]$objCredential = $null;
		[System.Collections.Specialized.OrderedDictionary]$hshSplat = [Ordered]@{};
		[System.Int32]$intI = 0;
		[System.Array]$arrClLics = @();
		
		#==================================================================================
		#region Load AzureADPreview PowerShell Module
		#==================================================================================
		
		##### Verify AzureADPreview PowerShell Module Existence
		Write-Debug "Verify $($strModule) PowerShell Module Existence";
		If (-not (Get-Module -Name "$($strModule)" -ListAvailable -Verbose:$false -Debug:$false))
		{
			[System.String]$strEventMessage = "PowerShell Module $($strModule) Is Not Installed";
			[System.String]$strEventMessage += "`r`nPlease Refer To https://bit.ly/30VWxaV";
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			Return
		}
		
		##### Load AzureADPreview PowerShell Module
		Write-Debug "Load $($strModule) PowerShell Module";
		If ((-not (Get-Module -Name "$($strModule)" -Verbose:$false -Debug:$false)) -and `
			(-not -not (Get-Module -Name "$($strModule)" -ListAvailable -Verbose:$false -Debug:$false)))
		{
			Write-Host "Import $($strModule) Module" -ForegroundColor 'Green';
			Import-Module -Name "$($strModule)" -Global:$true -Force:$true -Verbose:$false -Debug:$false;
		}
		
		##### Verify AzureADPreview PowerShell Module Load
		Write-Debug "Verify $($strModule) PowerShell Module Load";
		If (-not (Get-Module -Name "$($strModule)" -Verbose:$false -Debug:$false))
		{
			[System.String]$strEventMessage = "Failed To Load PowerShell Module $($strModule)";
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			Return
		}
		
		#==================================================================================
		#endregion Load AzureADPreview PowerShell Module
		#==================================================================================
		
		#==================================================================================
		#region Create The Credentials Object
		#==================================================================================
		
		###### Generate The Credential Object In FolderPath Parameter Set
		Write-Debug 'Verify The Parameter Set Name';
		Switch ("$($PSCmdlet.ParameterSetName)")
		{
			'FolderPath'
			{
				##### Generate The Credential Object In FolderPath Parameter Set
				Write-Verbose 'Generate The Credential Object In FolderPath Parameter Set';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = Import-SnsCredentialFile `
					-UserName "$($UserName)" -FolderPath "$($FolderPath)" -EventSource "$($EventSource)" `
					-Verbose:$false -Debug:$false;
				#####
			}
			
			'FilePath'
			{
				##### Generate The Credential Object In FilePath Parameter Set
				Write-Verbose 'Generate The Credential Object In FilePath Parameter Set';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = Import-SnsCredentialFile `
					-FilePath "$($FilePath)" -EventSource "$($EventSource)" `
					-Verbose:$false -Debug:$false;
				#####
			}
			
			'Credential'
			{
				##### Assign The Provided Credential Object In Credential Parameter Set
				Write-Verbose 'Assign The Provided Credential Object In Credential Parameter Set';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = $Credential;
				#####
			}
		}
		
		##### Verify The Credential Object
		Write-Debug 'Verify The Credential Object';
		If ((-not [Environment]::UserInteractive) -and (-not "$($objCredential.UserName)"))
		{
			[System.String]$strEventMessage = 'Failed To Generate The Credential For SfB Online';
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			[System.Management.Automation.PSCredential]$objCredential = $null;
			Return
		}
		
		#==================================================================================
		#endregion Create The Credentials Object
		#==================================================================================
		
		#==================================================================================
		#region Create AzureAD V2 Service Connection
		#==================================================================================
		
		##### Verify Any Previous Sessions Existence
		Write-Debug "Verify Any Previous Sessions Existence";
		If (-Not -Not ( `
			Get-Variable -Verbose:$false -Debug:$false | `
			Where-Object {"$($_.Name)" -like 'ArrAzureAdLicenses'} -Verbose:$false -Debug:$false `
		))
		{
			##### Disconnect The Previous Sessions
			Write-Verbose 'Removing Previous Sessions'; 
			Disconnect-AzureAD -Verbose:$false -Debug:$false;
			#####
		}
		
		##### Generate The Connect-AzureAD Splatting HashTable
		Write-Debug "Generate The Connect-AzureAD Splatting HashTable";
		[System.Collections.Specialized.OrderedDictionary]$hshSplat = [Ordered]@{};
		$hshSplat.Add('Verbose', $false);
		$hshSplat.Add('Debug', $false);
		
		##### Check Whether The Parameter Set Is Interactive
		Write-Debug "Check Whether The Parameter Set Is Interactive";
		If ("$($PSCmdlet.ParameterSetName)" -eq "Interactive")
		{
			#==================================================================================
			#region Interactively Authenticate Against AzureAD
			#==================================================================================
			
			##### Verify Whether It Is The First Interactive Logon
			Write-Debug "Verify Whether It Is The First Interactive Logon";
			If (-not ( `
				( `
					Get-Variable -Verbose:$false -Debug:$false | `
					Where-Object {"$($_.Name)" -like 'AzureAdAccount'} -Verbose:$false -Debug:$false `
				) `
				-and `
				( `
					Get-Variable -Verbose:$false -Debug:$false | `
					Where-Object {"$($_.Name)" -like 'AzureAdTenantId'} -Verbose:$false -Debug:$false `
				) `
			))
			{
				##### Loop the Interactive Login Process
				Write-Debug "Loop the Interactive Login Process";
				[System.Int32]$intI = 0;
				[System.Object]$objRmAccount = $null;
				[System.String]$strAccountId = "";
				[System.String]$strTenantId = "";
				Do
				{
					##### LogOn To RmAccount
					Write-Verbose "LogOn To RmAccount";
					[System.Object]$objRmAccount = $null;
					[System.Object]$objRmAccount = Login-AzureRmAccount -Verbose:$false -Debug:$false;
					
					##### Generate The Account ID
					Write-Debug "Generate The Account ID";
					[System.String]$strAccountId = "";
					[System.String]$strAccountId = "$($objRmAccount.Context.Account.Id)";
					
					##### Generate The Tenant ID
					Write-Debug "Generate The Tenant ID";
					[System.String]$strTenantId = "";
					[System.String]$strTenantId = "$(($objRmAccount.Context.Tenant | `
						Where-Object {""$($strAccountId)"" -like ""*$($_.Directory)""} `
						-Verbose:$false -Debug:$false)[0].Id)";
					#####
					
					##### Increment The Counter
					[System.Int32]$intI = $intI + 1;
				}
				While (((-Not "$($strAccountId)") -or (-Not "$($strTenantId)")) -and ($intI -lt $Attempts))
				
				##### Verify The Token Generation
				Write-Debug "Verify The Token Generation";
				If ((-Not -Not "$($strAccountId)") -and (-Not -Not "$($strTenantId)"))
				{
					##### Generate The Token Global Variables
					New-Variable -Scope 'Global' -Option 'Constant' -Name 'AzureAdAccount' -Value "$($strAccountId)";
					New-Variable -Scope 'Global' -Option 'Constant' -Name 'AzureAdTenantId' -Value "$($strTenantId)";
				}
				
				##### Reset The Variables
				Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strTenantId';
				Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strAccountId';
				Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objRmAccount';
			}
			
			##### Verify The Token Generation
			Write-Debug "Verify The Token Generation";
			If ((-Not -Not "$($global:AzureAdAccount)") -and (-Not -Not "$($global:AzureAdTenantId)"))
			{
				##### Add The Token Parameters To The Splatting HashTable
				$hshSplat.Add('TenantId', "$($global:AzureAdTenantId)");
				$hshSplat.Add('AccountId', "$($global:AzureAdAccount)");
			}
			Else
			{
				[System.String]$strEventMessage = 'Failed To Interactively Authenticate Against AzureAD';
				Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
				
				##### Write Into The Event Log If The Source Is Provided And Exists
				If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
				{
					Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
						-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
					#####
					
					##### Wait A Minute And Kill The Script Process
					Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
					Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
				}
				
				##### Reset the Variable
				Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
				Return
			}
			
			#==================================================================================
			#endregion Interactively Authenticate Against AzureAD
			#==================================================================================
		}
		Else
		{
			##### Add The Generated Credential To The Splatting HashTable
			$hshSplat.Add('Credential', $objCredential);
		}
		
		##### Loop The Session Creation
		Write-Debug 'Loop The Session Creation';
		[System.Int32]$intI = 0;
		[System.Array]$arrClLics = @();
		Do
		{
			##### Display The Action On The Console
			Write-Verbose 'Connecting To AzureAD V2 Service.';
			Connect-AzureAD @hshSplat | Out-Null;
			
			##### Process the Loop Variable and TimeOut
			Start-Sleep -Seconds 2; [System.Int32]$intI = $intI + 1;
			
			##### Verify The PowerShell Session To The AzureAD
			[System.Array]$arrClLics = @();
			[System.Array]$arrClLics = Get-AzureADSubscribedSku `
				-Verbose:$true -Debug:$true | Select-Object `
				-Property @('SkuPartNumber','SkuId','ServicePlans','ConsumedUnits') `
				-ExpandProperty 'PrepaidUnits' -Verbose:$true -Debug:$true;
			#####
		}
		While (($arrClLics.Count -lt 1) -and ($intI -lt $Attempts))
		
		##### Verify The AzureAD Session Creation
		Write-Debug 'Verify The AzureAD Session Creation';
		If ($arrClLics.Count -lt 1)
		{
			[System.String]$strEventMessage = 'Failed To Establish A Connection To AzureAD V2 Service';
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			[System.Management.Automation.Runspaces.PSSession]$objPsSession = $null;
			Return
		}
		Else
		{
			##### Verify Whether The Global AzureAd Licenses Variable Exists
			Write-Debug "Verify Whether The Global AzureAd Licenses Variable Exists";
			If (-not ( `
				Get-Variable -Verbose:$false -Debug:$false | `
				Where-Object {"$($_.Name)" -like 'ArrAzureAdLicenses'} -Verbose:$false -Debug:$false `
			))
			{
				##### Create The Global AzureAd Licenses Variable
				Write-Debug "Create The Global AzureAd Licenses Variable";
				New-Variable -Scope 'Global' -Option 'Constant' -Name 'ArrAzureAdLicenses' -Value ($arrClLics);
			}
			
			##### Continue If Output Is Requested
			Write-Debug "Continue If Output Is Requested";
			If ($PassThru.IsPresent)
			{
				##### Pass The Output Object To The Pipeline
				Write-Debug "Pass Output Object To The Pipeline";
				$PSCmdlet.WriteObject($arrClLics);
			}
		}
		
		#==================================================================================
		#endregion Create AzureAD V2 Service Connection
		#==================================================================================
		
		##### Reset The Variables
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'arrClLics';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'intI';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'hshSplat';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objCredential';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strModule';
		
		$PSCmdlet.MyInvocation.BoundParameters | Select-Object -ExpandProperty 'Keys' -Verbose:$false -Debug:$false | ForEach `
		{Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name "$($_)"};
	}
	
	##### Override The End Method
	End
	{
		##Stop The StopWatch
		$objCmdStopWatch.Stop();
		Write-Verbose "Command Elapsed: ""$($objCmdStopWatch.ElapsedMilliseconds)"" Milliseconds." ;
		Write-Verbose "End!";
	}
}

##### Connect-SnsMsolService ======================================================
Function Connect-SnsMsolService ()
{
<#
.SYNOPSIS
This CmdLet Establish A Remote PowerShell Session To Office 365 MSOnline V1 Service.
.DESCRIPTION
This CmdLet Establish A Remote PowerShell Session To Office 365 MSOnline V1 Service.
The CmdLet Have Four Parameter Sets:
-- FolderPath Here Have To Be Specified The UserName And The Full Absolute UNC Folder Path Where The Encrypted
Password File Resides.
-- FilePath Here Have To Be Provided The Full Absolute UNC Path To The Credential File. The CmdLet Will Try To
Generate The UserName From The FileName.
-- Credential Here Have To Be Provided System.Management.Automation.PSCredential Object.
-- Interactive This Is The Only Parameter Set Which Is Capable To Establish Remote PowerShell Session To MSOnline
V1 Service With Multifactor Authentication. However It Cannot Be Used Whenever The Script Or The Function Is
Executed In As Service Mode.
In This Parameter Set The CmdLet Opens A Window Where The User Can Specify His Credentials And Multi Factor
Authentication Code Received On A SMS Or Inside A Phone App Or Phone Call And Etc.
Obviously When The CmdLet Is Executed As Service There Is No Real Person To Specify The Credentials And The MFA
Code. Depending Of The Configuration There Might Not Be PowerShell Host Console Window Either.
NOTE: The CmdLet Requires MSOnline Module To Be Installed In Advance. Please Refer To https://bit.ly/2O0VxwO
NOTE: There Must Be A Direct Connection / Firewall Openings To Office 365. Proxy Usage Is Not Allowed.
.PARAMETER UserName
Specifies The UserName In UPN Format.
Parameter Set: FolderPath
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER FolderPath
Specifies The Full Absolute UNC Folder Path Where The Credential File Resides.
Parameter Set: FolderPath
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER FilePath
Specifies The Full Absolute UNC Path To The Credential File.
Parameter Set: FilePath
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Credential
Specifies [System.Management.Automation.PSCredential] Object.
Parameter Set: Credential
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Interactive
Specifies That The User Have To Be Asked Interactively For Credentials.
Parameter Set: Interactive
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Attempts
Specifies The Number Of Attempts That Have To Be Made To Establish The Remote Session.
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER EventSource
Specifies The Application Log Event Source To Be Used For The Error Event Logging.
Parameter Set: All
Parameter Alias: ScriptName
Parameter Validation: N/A
.PARAMETER PassThru
Specifies That The CmdLet Have To Revert A Verification Collection.
Parameter Set: All
Parameter Alias: N/A
Parameter Validation: N/A
.INPUTS
Pipeline Input None
.OUTPUTS
[System.Object[]] Which Contains A List With The Available Msol License Objects.
.NOTES
AUTHOR:    Svetoslav Nedyalkov Savov (svesavov@hotmail.com)
COPYRIGHT: (c) 2020 Svetoslav Nedyalkov Savov, all rights reserved.
THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
.EXAMPLE
[System.Object[]]$arrAzureLicenses = Connect-SnsMsolService -UserName 'john.smith@contoso.com' `
-FolderPath 'C:\';
.EXAMPLE
[System.Object[]]$arrAzureLicenses = Connect-SnsMsolService -FilePath 'C:\john.smith@contoso.com.ini';
.EXAMPLE
[System.Object[]]$arrAzureLicenses = Connect-SnsMsolService -Credential $objCredential;
.EXAMPLE
[System.Object[]]$arrAzureLicenses = Connect-SnsMsolService -Interactive;
#>
[CmdletBinding(PositionalBinding = $false, DefaultParameterSetName = 'Interactive')]
Param (
	[Parameter(Mandatory = $true, ParameterSetName = 'FolderPath', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateNotNullOrEmpty()][System.String]$UserName,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'FolderPath', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateScript({("$($_)" -eq "$($_.Trim())")})]
	[ValidateScript({("$($_)" -like "*\*")})]
	[ValidateScript({(Test-Path -Path "$($_)" -PathType 'Container')})]
	[ValidateNotNullOrEmpty()][System.String]$FolderPath,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'FilePath', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateScript({("$($_)" -eq "$($_.Trim())")})]
	[ValidateScript({("$($_)" -like "*\*.ini")})]
	[ValidateScript({(Test-Path -Path "$($_)" -PathType 'Leaf')})]
	[ValidateNotNullOrEmpty()][System.String]$FilePath,
	
	[Parameter(Mandatory = $true, ParameterSetName = 'Credential', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateNotNullOrEmpty()][System.Management.Automation.PSCredential]$Credential,
	
	[Parameter(Mandatory = $false, ParameterSetName = 'Interactive', `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Switch]$Interactive = $false,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateNotNullOrEmpty()][System.Int32]$Attempts = 3,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Alias('ScriptName')]
	[AllowNull()][AllowEmptyString()][System.String]$EventSource,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Switch]$PassThru
)
	##### Override The Begin Method
	Begin
	{
		Write-Verbose '';
		Write-Verbose "Connect-SnsMsolService";
		Write-Debug 'Override Begin Method';
		
		##### Initialize New Measure Watch
		[System.Diagnostics.Stopwatch]$objCmdStopWatch = [System.Diagnostics.Stopwatch]::StartNew();
		
		If ("$((Get-FileHash -Path $PSCommandPath -Algorithm 'SHA256' -Verbose:$false -Debug:$false).Hash)" -ne "$($global:SnsModuleCfg.ModuleHash)")
		{Write-Warning 'There Is New Version Of SnsPsModule Module Released. Please Restart The PowerShell Session.'};
		
		Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName)`r`n";
		
		##### Initialize The Variables
		[System.String]$strModule = "MSOnline";
		[System.Management.Automation.PSCredential]$objCredential = $null;
		[System.Int32]$intI = 0;
		[System.Array]$arrClLics = @();
		
		#==================================================================================
		#region Load MSOnline PowerShell Module
		#==================================================================================
		
		##### Verify MSOnline PowerShell Module Existence
		Write-Debug "Verify $($strModule) PowerShell Module Existence";
		If (-not (Get-Module -Name "$($strModule)" -ListAvailable -Verbose:$false -Debug:$false))
		{
			[System.String]$strEventMessage = "PowerShell Module $($strModule) Is Not Installed";
			[System.String]$strEventMessage += "`r`nPlease Refer To https://bit.ly/2O0VxwO";
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			Return
		}
		
		##### Load MSOnline PowerShell Module
		Write-Debug "Load $($strModule) PowerShell Module";
		If ((-not (Get-Module -Name "$($strModule)" -Verbose:$false -Debug:$false)) -and `
			(-not -not (Get-Module -Name "$($strModule)" -ListAvailable -Verbose:$false -Debug:$false)))
		{
			Write-Host "Import $($strModule) Module" -ForegroundColor 'Green';
			Import-Module -Name "$($strModule)" -Global:$true -Force:$true -Verbose:$false -Debug:$false;
		}
		
		##### Verify MSOnline PowerShell Module Load
		Write-Debug "Verify $($strModule) PowerShell Module Load";
		If (-not (Get-Module -Name "$($strModule)" -Verbose:$false -Debug:$false))
		{
			[System.String]$strEventMessage = "Failed To Load PowerShell Module $($strModule)";
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			Return
		}
		
		#==================================================================================
		#endregion Load MSOnline PowerShell Module
		#==================================================================================
		
		#==================================================================================
		#region Create The Credentials Object
		#==================================================================================
		
		###### Generate The Credential Object In FolderPath Parameter Set
		Write-Debug 'Verify The Parameter Set Name';
		Switch ("$($PSCmdlet.ParameterSetName)")
		{
			'FolderPath'
			{
				##### Generate The Credential Object In FolderPath Parameter Set
				Write-Verbose 'Generate The Credential Object In FolderPath Parameter Set';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = Import-SnsCredentialFile `
					-UserName "$($UserName)" -FolderPath "$($FolderPath)" -EventSource "$($EventSource)" `
					-Verbose:$false -Debug:$false;
				#####
			}
			
			'FilePath'
			{
				##### Generate The Credential Object In FilePath Parameter Set
				Write-Verbose 'Generate The Credential Object In FilePath Parameter Set';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = Import-SnsCredentialFile `
					-FilePath "$($FilePath)" -EventSource "$($EventSource)" `
					-Verbose:$false -Debug:$false;
				#####
			}
			
			'Credential'
			{
				##### Assign The Provided Credential Object In Credential Parameter Set
				Write-Verbose 'Assign The Provided Credential Object In Credential Parameter Set';
				[System.Management.Automation.PSCredential]$objCredential = $null;
				[System.Management.Automation.PSCredential]$objCredential = $Credential;
				#####
			}
		}
		
		##### Verify The Credential Object
		Write-Debug 'Verify The Credential Object';
		If ((-not [Environment]::UserInteractive) -and (-not "$($objCredential.UserName)"))
		{
			[System.String]$strEventMessage = 'Failed To Generate The Credential For Msol V1 Service';
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			[System.Management.Automation.PSCredential]$objCredential = $null;
			Return
		}
		
		#==================================================================================
		#endregion Create The Credentials Object
		#==================================================================================
		
		#==================================================================================
		#region Create Msol Service Connection
		#==================================================================================
		
		##### Loop The Session Creation
		Write-Debug 'Loop The Session Creation';
		[System.Int32]$intI = 0;
		[System.Array]$arrClLics = @();
		Do
		{
			##### Verify The ParameterSetName
			Write-Debug 'Verify The ParameterSetName';
			If ("$($PSCmdlet.ParameterSetName)" -eq "Interactive")
			{
				##### Display The Action On The Console
				Write-Verbose 'Interactively Connecting To Msol Service.';
				Connect-MsolService | Out-Null;
			}
			Else
			{
				If (-not -not "$($objCredential.UserName)")
				{
					##### Display The Action On The Console
					Write-Verbose 'Connecting To Msol Service.';
					Connect-MsolService -Credential $objCredential | Out-Null;
				}
				Else
				{
					[System.String]$strEventMessage = 'Failed To Generate The Credential For Msol V1 Service';
					Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
					
					##### Write Into The Event Log If The Source Is Provided And Exists
					If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
					{
						Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
							-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
						#####
						
						##### Wait A Minute And Kill The Script Process
						Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
						Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
					}
					
					##### Reset the Variable
					Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
					[System.Management.Automation.PSCredential]$objCredential = $null;
					Return
				}
			}
			
			##### Process the Loop Variable and TimeOut
			Start-Sleep -Seconds 2; [System.Int32]$intI = $intI + 1;
			
			##### Verify The PowerShell Session To The Msol Service
			[System.Array]$arrClLics = @();
			[System.Array]$arrClLics = Get-MsolAccountSku -Verbose:$false -Debug:$false | `
				Select-Object -Verbose:$false -Debug:$false `
				@("AccountSkuId", "SkuId", "ServiceStatus", "ActiveUnits", "ConsumedUnits");
			#####
		}
		While (($arrClLics.Count -lt 1) -and ($intI -lt $Attempts))
		
		##### Verify The Msol Service Session Creation
		Write-Debug 'Verify The Msol Service Session Creation';
		If ($arrClLics.Count -lt 1)
		{
			[System.String]$strEventMessage = 'Failed To Establish A Connection To Msol Service';
			Write-Error "$($strEventMessage)" -ErrorAction 'Continue';
			
			##### Write Into The Event Log If The Source Is Provided And Exists
			If ([System.Diagnostics.EventLog]::SourceExists("$($EventSource)"))
			{
				Write-EventLog -LogName 'Application' -Source "$($EventSource)" -EventId 9998 `
					-EntryType 'Error' -Message "$($strEventMessage)" -Verbose:$false -Debug:$false | Out-Null;
				#####
				
				##### Wait A Minute And Kill The Script Process
				Start-Sleep -Seconds 60 -Verbose:$false -Debug:$false;
				Stop-Process $pid -Force -Confirm:$false -Verbose:$false -Debug:$false;
			}
			
			##### Reset the Variable
			Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strEventMessage';
			[System.Management.Automation.Runspaces.PSSession]$objPsSession = $null;
			Return
		}
		Else
		{
			##### Verify Whether The Global Msol Licenses Variable Exists
			Write-Debug "Verify Whether The Global Msol Licenses Variable Exists";
			If (-not ( `
				Get-Variable -Verbose:$false -Debug:$false | `
				Where-Object {"$($_.Name)" -like 'ArrMsolLicenses'} -Verbose:$false -Debug:$false `
			))
			{
				##### Create The Global Msol Licenses Variable
				Write-Debug "Create The Global Msol Licenses Variable";
				New-Variable -Scope 'Global' -Option 'Constant' -Name 'ArrMsolLicenses' -Value ($arrClLics);
			}
			
			##### Continue If Output Is Requested
			Write-Debug "Continue If Output Is Requested";
			If ($PassThru.IsPresent)
			{
				##### Pass The Output Object To The Pipeline
				Write-Debug "Pass Output Object To The Pipeline";
				$PSCmdlet.WriteObject($arrClLics);
			}
		}
		
		#==================================================================================
		#endregion Create Msol Service Connection
		#==================================================================================
		
		##### Reset The Variables
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'arrClLics';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'intI';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objCredential';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'strModule';
		
		$PSCmdlet.MyInvocation.BoundParameters | Select-Object -ExpandProperty 'Keys' -Verbose:$false -Debug:$false | ForEach `
		{Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name "$($_)"};
	}
	
	##### Override The End Method
	End
	{
		##Stop The StopWatch
		$objCmdStopWatch.Stop();
		Write-Verbose "Command Elapsed: ""$($objCmdStopWatch.ElapsedMilliseconds)"" Milliseconds." ;
		Write-Verbose "End!";
	}
}

##### Enable-SnsMfa ===============================================================
Function Enable-SnsMfa ()
{
<#
.SYNOPSIS
CmdLet Designed To Enable Per User MultiFactor Authentication For An Azure Account.
.DESCRIPTION
CmdLet Designed To Enable Per User MultiFactor Authentication For An Azure Account.
The CmdLet Accept As Input The AzureAD Account UserPrincipalName String, AzureAD Account ObjectId String Or
AzureAD MSOL User Object. On Input Are Evaluated The TypeName Of The Provided Objects. Therefore The CmdLet Will
Accept Input From Pipeline Or Collection Variable Of All The Specified TypeName Simultaneously.
Using WhatIf Switch Parameter Allows The CmdLet To Be Used For MFA Report Generation Without Actually Modification
Of Users MFA Status.
.PARAMETER InputObject
Specifies Either MsolUser Object, Or UserPrincipalName, Or AzureAD ObjectId Of The User Or Users Which Have To
Be MFA Enabled
Parameter Alias: "UserPrincipalName", "ObjectId"
Parameter Validation: Yes Using Object TypeName And RegEx Matching Validation
.PARAMETER AuthRequirement
Specifies A Microsoft.Online.Administration.StrongAuthenticationRequirement Object With The Required MFA
Parameters.
If Omitted The CmdLet Will Generate One Internally With Default Parameters:
-- MFA Status "Enabled"
-- Keep Any Existing Authentication Methods And Devices.
Parameter Alias: N/A
Parameter Validation: Yes, Using Object TypeName Validation
.PARAMETER Attempts
Specifies The Number Of Attempts That Have To Be Made To Enable The MFA.
Parameter Alias: N/A
Parameter Validation: N/A
.PARAMETER Force
Specifies To The CmdLet That Exact Matching Of Enforce And Enabled Have To Be Used.
If Omitted The CmdLet Will Consider Users With Enabled MFA To Be Compliant When AuthRequirement Object Require Enforced MFA And Vice Versa.
Parameter Alias: N/A
Parameter Validation: N/A
.INPUTS
Pipeline Input -InputObject Which Accept Values Of Type [System.Object[]] And [System.String[]]
.OUTPUTS
Pipeline Output [SnsPsModule.SnsMfaStatus[]] Which Contains A Report About Users MFA Status
.NOTES
AUTHOR:    Svetoslav Nedyalkov Savov (svesavov@hotmail.com)
COPYRIGHT: (c) 2020 Svetoslav Nedyalkov Savov, all rights reserved.
THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
.EXAMPLE
[SnsPsModule.SnsMfaStatus[]]$arrMfa = Enable-SnsMfa -InputObject $arrCollection `
-AuthRequirement $objAuthRequirement -Force;
#>
[CmdletBinding(PositionalBinding = $false, `
	SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
Param (
	[Parameter(Mandatory = $true, `
		ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
	[Alias('UserPrincipalName', 'ObjectId')]
	[ValidateNotNullOrEmpty()]
	[ValidateScript({( `
		(
			"$(($_ | Get-Member -Verbose:$false -Debug:$false )[0].TypeName)" `
			-like `
			"*Microsoft.Online.Administration.User" `
		) `
		-or `
		("$($_)" -match "^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$") `
		-or `
		("$($_)" -match "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$") `
	)})]
	[System.Object[]]$InputObject,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateNotNullOrEmpty()]
	[ValidateScript({ `
		"$(($_ | Get-Member -Verbose:$false -Debug:$false )[0].TypeName)" `
		-eq `
		"Microsoft.Online.Administration.StrongAuthenticationRequirement" `
	})]
	[System.Object]$AuthRequirement,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateNotNullOrEmpty()][System.Int32]$Attempts = 3,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Switch]$Force = $false
)
	##### Override The Begin Method
	Begin
	{
		Write-Verbose '';
		Write-Verbose "Enable-SnsMfa";
		Write-Debug 'Override Begin Method';
		
		##### Initialize New Measure Watch
		[System.Diagnostics.Stopwatch]$objCmdStopWatch = [System.Diagnostics.Stopwatch]::StartNew();
		
		If ("$((Get-FileHash -Path $PSCommandPath -Algorithm 'SHA256' -Verbose:$false -Debug:$false).Hash)" -ne "$($global:SnsModuleCfg.ModuleHash)")
		{Write-Warning 'There Is New Version Of SnsPsModule Module Released. Please Restart The PowerShell Session.'};
		
		#Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName)`r`n";
		
		#==================================================================================
		#region Define The Output Object TypeName
		#==================================================================================
		
		##### Define The [SnsPsModule.SnsMfaStatus] Object
		Write-Debug 'Define The [SnsPsModule.SnsMfaStatus] Object';
		Add-Type `
@"
	using System;
	namespace SnsPsModule
	{
		public class SnsMfaStatus
		{
			public SnsMfaStatus()
			{
				UserPrincipalName = "";
				DisplayName = "";
				ObjectId = "";
				MfaState = "";
				ValueModified = false;
				ValueCorrect = false;
				MsolUser = null;
			}
			public string UserPrincipalName { get; set; }
			public string DisplayName { get; set; }
			public string ObjectId { get; set; }
			public string MfaState { get; set; }
			public bool ValueModified { get; set; }
			public bool ValueCorrect { get; set; }
			public object MsolUser { get; set; }
		}
	}
"@
		#####
		
		#==================================================================================
		#endregion Define The Output Object TypeName
		#==================================================================================
		
		#==================================================================================
		#region Verify The Msol V1 Service Connection
		#==================================================================================
		
		##### Verify The Msol V1 Service Connection
		Write-Verbose "Verify The Msol V1 Service Connection";
		If (-not ( `
			Get-Variable -Verbose:$false -Debug:$false | `
			Where-Object {"$($_.Name)" -like 'ArrMsolLicenses'} -Verbose:$false -Debug:$false `
		))
		{
			Write-Error "Please Establish A Connection To Msol Service" -ErrorAction 'Stop';
		}
		
		#==================================================================================
		#endregion Verify The Msol V1 Service Connection
		#==================================================================================
		
		##### Initialize The Variables
		[Microsoft.Online.Administration.StrongAuthenticationRequirement]$objAuthRequirement = $null;
		[System.UInt32]$intI = 0;
		[SnsPsModule.SnsMfaStatus]$objMfa = $null;
		[Microsoft.Online.Administration.User[]]$arrMsolUsr = @();
		[System.UInt32]$intIn = 0;
		
		#==================================================================================
		#region Generate The StrongAuthenticationRequirement Object
		#==================================================================================
		
		##### Verify Whether StrongAuthenticationRequirement Object Is Provided
		Write-Debug "Verify Whether StrongAuthenticationRequirement Object Is Provided";
		If (-Not "$($AuthRequirement.State)")
		{
			##### Generate The StrongAuthenticationRequirement Object
			Write-Verbose "Generate The StrongAuthenticationRequirement Object";
			[Microsoft.Online.Administration.StrongAuthenticationRequirement]$objAuthRequirement = $null;
			[Microsoft.Online.Administration.StrongAuthenticationRequirement]$objAuthRequirement = `
				New-Object -TypeName 'Microsoft.Online.Administration.StrongAuthenticationRequirement';
			$objAuthRequirement.RelyingParty = "*"
			#$objAuthRequirement.State = 'Enforced';
			$objAuthRequirement.State = 'Enabled';
			$objAuthRequirement.RememberDevicesNotIssuedBefore = [System.DateTime]::Now;
		}
		Else
		{
			[Microsoft.Online.Administration.StrongAuthenticationRequirement]$objAuthRequirement = $null;
			[Microsoft.Online.Administration.StrongAuthenticationRequirement]$objAuthRequirement = $AuthRequirement
		}
		
		#==================================================================================
		#endregion Generate The StrongAuthenticationRequirement Object
		#==================================================================================
	}
	
	##### Override The Process Method
	Process
	{
		Write-Verbose '';
		Write-Debug 'Override Process Method';
		
		##### Process Each Input Object
		Write-Debug "Process Each Input Object";
		[System.UInt32]$intI = 0;
		For ([System.UInt32]$intI = 0; $intI -lt $InputObject.Count; $intI++)
		{
			##### Evaluate The Number Of Input Objects
			If ($InputObject.Count -gt 5)
			{
				Write-Progress -Activity 'Enable-SnsMfa' -Id 1 `
					-PercentComplete (($intI / $InputObject.Count) * 100) `
					-Verbose:$false -Debug:$false;
				#####
			}
			
			#==================================================================================
			#region Retrieve MsolUser Object From AzureAD
			#==================================================================================
			
			##### Generate A Mfa Object
			Write-Debug "Generate A Mfa Object";
			[SnsPsModule.SnsMfaStatus]$objMfa = [SnsPsModule.SnsMfaStatus]::new();
			
			##### Verify What Kind Of Input Was Provided
			Write-Debug "Verify What Kind Of Input Was Provided";
			If  ( `
				"$(($InputObject[$intI] | Get-Member -Verbose:$false -Debug:$false )[0].TypeName)" `
				-like `
				"*Microsoft.Online.Administration.User" `
			)
			{
				##### Assign The Msol User Object To The Corresponding Object Property
				$objMfa.MsolUser = $InputObject[$intI] | Select-Object -Property * -Verbose:$false -Debug:$false;
				$objMfa.MsolUser | Add-Member -TypeName 'Selected.Microsoft.Online.Administration.User';
				
				##### Verify The Provided Object
				Write-Debug "Verify The Provided Object";
				If ( `
					( `
						"$($InputObject[$intI].ObjectId.Guid)" `
						-notmatch `
						"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$" `
					) `
					-or `
					( `
						"$($InputObject[$intI].UserPrincipalName)" `
						-notmatch `
						"^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" `
					) `
				)
				{
					Write-Error "Unable To Recognize The Provided Input Object";
					$PSCmdlet.WriteObject($objMfa);
					Continue;
				}
			}
			ElseIf ("$($InputObject[$intI])" -match "^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
			{
				##### Assign the UPN Property To The Corresponding Object Property
				$objMfa.UserPrincipalName = "$($InputObject[$intI])";
				
				##### Query The Msol V1 About User With UPN
				Write-Debug "Query The Msol V1 About User With UPN: $($objMfa.UserPrincipalName)";
				[Microsoft.Online.Administration.User[]]$arrMsolUsr = @();
				[Microsoft.Online.Administration.User[]]$arrMsolUsr = Get-MsolUser `
					-UserPrincipalName "$($objMfa.UserPrincipalName)" `
					-Verbose:$false -Debug:$false;
				#####
				
				If ($arrMsolUsr.Count -eq 1)
				{
					##### Process The User
					$objMfa.MsolUser = $arrMsolUsr[0] | Select-Object -Property * -Verbose:$false -Debug:$false;
				}
				ElseIf ($arrMsolUsr.Count -lt 1)
				{
					Write-Error "Unable To Find MsolUser With UPN:$($objMfa.UserPrincipalName)";
					$PSCmdlet.WriteObject($objMfa);
					Continue;
				}
				ElseIf ($arrMsolUsr.Count -gt 1)
				{
					Write-Error "UPN Conflict in Msol V1 Service About $($objMfa.UserPrincipalName)";
					$PSCmdlet.WriteObject($objMfa);
					Continue;
				}
			}
			ElseIf ("$($InputObject[$intI])" -match "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
			{
				##### Assign the UPN Property To The Corresponding Object Property
				$objMfa.ObjectId = "$($InputObject[$intI])";
				
				##### Query The Msol V1 About User With UPN
				Write-Debug "Query The Msol V1 About User With ObjectId: $($objMfa.ObjectId)";
				[Microsoft.Online.Administration.User[]]$arrMsolUsr = @();
				[Microsoft.Online.Administration.User[]]$arrMsolUsr = Get-MsolUser `
					-ObjectId "$($objMfa.ObjectId)" `
					-Verbose:$false -Debug:$false;
				#####
				
				If ($arrMsolUsr.Count -eq 1)
				{
					##### Process The User
					$objMfa.MsolUser = $arrMsolUsr[0] | Select-Object -Property * -Verbose:$false -Debug:$false;
				}
				ElseIf ($arrMsolUsr.Count -lt 1)
				{
					Write-Error "Unable To Find MsolUser With ObjectId:$($objMfa.ObjectId)";
					$PSCmdlet.WriteObject($objMfa);
					Continue;
				}
				ElseIf ($arrMsolUsr.Count -gt 1)
				{
					Write-Error "ObjectId Conflict in Msol V1 Service About $($objMfa.ObjectId)";
					$PSCmdlet.WriteObject($objMfa);
					Continue;
				}
			}
			
			#==================================================================================
			#endregion Retrieve MsolUser Object From AzureAD
			#==================================================================================
			
			#==================================================================================
			#region Calculate The Initial State
			#==================================================================================
			
			##### Continue If The MsolUser Is Generated
			Write-Debug "Continue If The MsolUser Is Generated";
			If ( `
				"$(($objMfa.MsolUser | Get-Member -Verbose:$false -Debug:$false)[0].TypeName)" `
				-eq `
				"Selected.Microsoft.Online.Administration.User" `
			)
			{
				##### Evaluate The Current Object State
				Write-Debug "Evaluate The Current Object State";
				$objMfa.UserPrincipalName = "$($objMfa.MsolUser.UserPrincipalName)";
				$objMfa.DisplayName = "$($objMfa.MsolUser.DisplayName)";
				$objMfa.ObjectId = "$($objMfa.MsolUser.ObjectId.Guid)";
				$objMfa.MfaState = "$($objMfa.MsolUser.StrongAuthenticationRequirements[0].State)";
				$objMfa.ValueCorrect = ( `
					((-not $Force.IsPresent) -and (-not -not "$($objMfa.MfaState)")) `
					-or `
					(($Force.IsPresent) -and ("$($objMfa.MfaState)" -eq "$($objAuthRequirement.State)")) `
				);
				Write-Verbose "Found UPN:$($objMfa.UserPrincipalName) ObjectId:$($objMfa.ObjectId) MfaState:$($objMfa.MfaState)";
			}
			
			#==================================================================================
			#endregion Calculate The Initial State
			#==================================================================================
			
			#==================================================================================
			#region Enable-SnsMfa
			#==================================================================================
			
			##### Continue If The MsolUser Is Retrieved Successfully
			Write-Debug "Continue If The MsolUser Is Retrieved Successfully"
			If ( `
				"$(($objMfa.MsolUser | Get-Member -Verbose:$false -Debug:$false)[0].TypeName)" `
				-eq `
				"Selected.Microsoft.Online.Administration.User" `
			)
			{
				##### Verify Whether The MFA Is Not Enabled
				Write-Debug "Verify Whether The MFA Is Not Enabled";
				If (-not $objMfa.ValueCorrect)
				{
					##### Invoke ShouldProcess Method
					Write-Debug "Invoke ShouldProcess Method";
					If ($PSCmdlet.ShouldProcess("$($objMfa.UserPrincipalName)"))
					{
						##### Loop The MFA Enforcement
						Write-Debug "Loop The MFA Enforcement";
						[System.UInt32]$intIn = 0;
						While ((-not $objMfa.ValueCorrect) -and ($intIn -lt $Attempts))
						{
							##### Enforce MFA To The User
							Write-Verbose "$($objAuthRequirement.State) MFA To: $($objMfa.UserPrincipalName)";
							Set-MsolUser `
								-ObjectId "$($objMfa.ObjectId)" `
								-StrongAuthenticationRequirements $objAuthRequirement `
								-Verbose:$false -Debug:$false | Out-Null;
							#####
							
							##### Process The Loop Variables
							Write-Debug "Process The Loop Variables";
							[System.UInt32]$intIn = $intIn + 1;
							$objMfa.ValueModified = $true;
							$objMfa.MsolUser = $null;
							$objMfa.MfaState = "";
							$objMfa.ValueCorrect = $false;
							Start-Sleep -Seconds 1 -Verbose:$false -Debug:$false;
							
							##### Query The Msol V1 About User With UPN
							Write-Debug "Query The Msol V1 About User With UPN: $($objMfa.UserPrincipalName)";
							[Microsoft.Online.Administration.User[]]$arrMsolUsr = @();
							[Microsoft.Online.Administration.User[]]$arrMsolUsr = Get-MsolUser `
								-ObjectId "$($objMfa.ObjectId)" `
								-Verbose:$false -Debug:$false;
							#####
							
							##### Verify The Msol V1 Query Output
							Write-Debug "Verify The Msol V1 Query Output";
							If ($arrMsolUsr.Count -eq 1)
							{
								##### Update The Object Properties
								Write-Debug "Update The Object Properties";
								$objMfa.MsolUser = $arrMsolUsr[0] | Select-Object -Property * -Verbose:$false -Debug:$false;
								$objMfa.MfaState = "$($objMfa.MsolUser.StrongAuthenticationRequirements[0].State)";
								$objMfa.ValueCorrect = ( `
									((-not $Force.IsPresent) -and (-not -not "$($objMfa.MfaState)")) `
									-or `
									(($Force.IsPresent) -and ("$($objMfa.MfaState)" -eq "$($objAuthRequirement.State)")) `
								);
							}
						}
					}
				}
				Else
				{
					Write-Verbose "The MFA Of User:$($objMfa.UserPrincipalName) Is Already:$($objMfa.MfaState)";
				}
			}
			
			#==================================================================================
			#endregion Enable-SnsMfa
			#==================================================================================
			
			##### Pass The Output Object To The Pipeline
			Write-Debug "Pass Output Object To The Pipeline";
			$PSCmdlet.WriteObject($objMfa);
		}
		
		##### Close The Progress Bar
		Write-Debug 'Close The Progress Bar';
		If ($InputObject.Count -gt 5)
		{
			Write-Progress -Activity 'Enable-SnsMfa' -Id 1 -PercentComplete 100 -Verbose:$false -Debug:$false;
			Write-Progress -Activity 'Enable-SnsMfa' -Id 1 -Completed -Verbose:$false -Debug:$false;
		}
	}
	
	##### Override The End Method
	End
	{
		Write-Verbose '';
		Write-Debug 'Override End Method';
		
		##### Reset The Variables
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'intIn';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'arrMsolUsr';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objMfa';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'intI';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objAuthRequirement';
		
		$PSCmdlet.MyInvocation.BoundParameters | Select-Object -ExpandProperty 'Keys' -Verbose:$false -Debug:$false | ForEach `
		{Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name "$($_)"};
		
		##Stop The StopWatch
		$objCmdStopWatch.Stop();
		Write-Verbose "Command Elapsed: ""$($objCmdStopWatch.ElapsedMilliseconds)"" Milliseconds." ;
		Write-Verbose "End!";
	}
}

##### Disable-SnsMfa ==============================================================
Function Disable-SnsMfa ()
{
<#
.SYNOPSIS
CmdLet Designed To Disable Per User MultiFactor Authentication For An Azure Account.
.DESCRIPTION
CmdLet Designed To Disable Per User MultiFactor Authentication For An Azure Account.
The CmdLet Disables The Per User MFA Gracefully, In Terms That Any Set By The User StrongAuthenticationMethods Are
Preserved. Which Means That If The MFA Is Disabled Temporary After Re-Enablement The User Wont Be Required To Set
Up The MFA From Scratch. Which Means That The Authentication App And The Remaining Configuration Is Preserved.
Unfortunately The AppPasswords Cannot Be Preserved. The Can Be Used Only Whenever MFA Is Enabled And Are Lost
Immediately With The Disablement.
The CmdLet Accept As Input The AzureAD Account UserPrincipalName String, AzureAD Account ObjectId String Or
AzureAD MSOL User Object. On Input Are Evaluated The TypeName Of The Provided Objects. Therefore The CmdLet Will
Accept Input From Pipeline Or Collection Variable Of All The Specified TypeName Simultaneously.
Using WhatIf Switch Parameter Allows The CmdLet To Be Used For MFA Report Generation Without Actually Modification
Of Users MFA Status.
.PARAMETER InputObject
Specifies Either MsolUser Object, Or UserPrincipalName, Or AzureAD ObjectId Of The User Or Users Which Have To
Be MFA Enabled
Parameter Alias: "UserPrincipalName", "ObjectId"
Parameter Validation: Yes Using Object TypeName And RegEx Matching Validation
.PARAMETER Attempts
Specifies The Number Of Attempts That Have To Be Made To Enable The MFA.
Parameter Alias: N/A
Parameter Validation: N/A
.INPUTS
Pipeline Input -InputObject Which Accept Values Of Type [System.Object[]] And [System.String[]]
.OUTPUTS
Pipeline Output [SnsPsModule.SnsMfaStatus[]] Which Contains A Report About Users MFA Status
.NOTES
AUTHOR:    Svetoslav Nedyalkov Savov (svesavov@hotmail.com)
COPYRIGHT: (c) 2020 Svetoslav Nedyalkov Savov, all rights reserved.
THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
.EXAMPLE
[SnsPsModule.SnsMfaStatus[]]$arrMfa = Disable-SnsMfa -InputObject $arrCollection;
#>
[CmdletBinding(PositionalBinding = $false, `
	SupportsShouldProcess = $true, ConfirmImpact = 'High')]
Param (
	[Parameter(Mandatory = $true, `
		ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
	[Alias('UserPrincipalName', 'ObjectId')]
	[ValidateNotNullOrEmpty()]
	[ValidateScript({( `
		(
			"$(($_ | Get-Member -Verbose:$false -Debug:$false )[0].TypeName)" `
			-like `
			"*Microsoft.Online.Administration.User" `
		) `
		-or `
		("$($_)" -match "^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$") `
		-or `
		("$($_)" -match "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$") `
	)})]
	[System.Object[]]$InputObject,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateNotNullOrEmpty()][System.Int32]$Attempts = 3
)
	##### Override The Begin Method
	Begin
	{
		Write-Verbose '';
		Write-Verbose "Disable-SnsMfa";
		Write-Debug 'Override Begin Method';
		
		##### Initialize New Measure Watch
		[System.Diagnostics.Stopwatch]$objCmdStopWatch = [System.Diagnostics.Stopwatch]::StartNew();
		
		If ("$((Get-FileHash -Path $PSCommandPath -Algorithm 'SHA256' -Verbose:$false -Debug:$false).Hash)" -ne "$($global:SnsModuleCfg.ModuleHash)")
		{Write-Warning 'There Is New Version Of SnsPsModule Module Released. Please Restart The PowerShell Session.'};
		
		#Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName)`r`n";
		
		#==================================================================================
		#region Define The Output Object TypeName
		#==================================================================================
		
		##### Define The [SnsPsModule.SnsMfaStatus] Object
		Write-Debug 'Define The [SnsPsModule.SnsMfaStatus] Object';
		Add-Type `
@"
	using System;
	namespace SnsPsModule
	{
		public class SnsMfaStatus
		{
			public SnsMfaStatus()
			{
				UserPrincipalName = "";
				DisplayName = "";
				ObjectId = "";
				MfaState = "";
				ValueModified = false;
				ValueCorrect = false;
				MsolUser = null;
			}
			public string UserPrincipalName { get; set; }
			public string DisplayName { get; set; }
			public string ObjectId { get; set; }
			public string MfaState { get; set; }
			public bool ValueModified { get; set; }
			public bool ValueCorrect { get; set; }
			public object MsolUser { get; set; }
		}
	}
"@
		#####
		
		#==================================================================================
		#endregion Define The Output Object TypeName
		#==================================================================================
		
		#==================================================================================
		#region Verify The Msol V1 Service Connection
		#==================================================================================
		
		##### Verify The Msol V1 Service Connection
		Write-Verbose "Verify The Msol V1 Service Connection";
		If (-not ( `
			Get-Variable -Verbose:$false -Debug:$false | `
			Where-Object {"$($_.Name)" -like 'ArrMsolLicenses'} -Verbose:$false -Debug:$false `
		))
		{
			Write-Error "Please Establish A Connection To Msol Service" -ErrorAction 'Stop';
		}
		
		#==================================================================================
		#endregion Verify The Msol V1 Service Connection
		#==================================================================================
		
		##### Initialize The Variables
		[System.UInt32]$intI = 0;
		[SnsPsModule.SnsMfaStatus]$objMfa = $null;
		[Microsoft.Online.Administration.User[]]$arrMsolUsr = @();
		[Microsoft.Online.Administration.StrongAuthenticationMethod[]]$arrAuthMethods = $null;
		[System.Boolean]$bolMethOk = $false;
		[System.UInt32]$intIn = 0;
	}
	
	##### Override The Process Method
	Process
	{
		Write-Verbose '';
		Write-Debug 'Override Process Method';
		
		##### Process Each Input Object
		Write-Debug "Process Each Input Object";
		[System.UInt32]$intI = 0;
		For ([System.UInt32]$intI = 0; $intI -lt $InputObject.Count; $intI++)
		{
			##### Evaluate The Number Of Input Objects
			If ($InputObject.Count -gt 5)
			{
				Write-Progress -Activity 'Enable-SnsMfa' -Id 1 `
					-PercentComplete (($intI / $InputObject.Count) * 100) `
					-Verbose:$false -Debug:$false;
				#####
			}
			
			#==================================================================================
			#region Retrieve MsolUser Object From AzureAD
			#==================================================================================
			
			##### Generate A Mfa Object
			Write-Debug "Generate A Mfa Object";
			[SnsPsModule.SnsMfaStatus]$objMfa = [SnsPsModule.SnsMfaStatus]::new();
			
			##### Verify What Kind Of Input Was Provided
			Write-Debug "Verify What Kind Of Input Was Provided";
			If  ( `
				"$(($InputObject[$intI] | Get-Member -Verbose:$false -Debug:$false )[0].TypeName)" `
				-like `
				"*Microsoft.Online.Administration.User" `
			)
			{
				##### Assign The Msol User Object To The Corresponding Object Property
				$objMfa.MsolUser = $InputObject[$intI] | Select-Object -Property * -Verbose:$false -Debug:$false;
				$objMfa.MsolUser | Add-Member -TypeName 'Selected.Microsoft.Online.Administration.User';
				
				##### Verify The Provided Object
				Write-Debug "Verify The Provided Object";
				If ( `
					( `
						"$($InputObject[$intI].ObjectId.Guid)" `
						-notmatch `
						"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$" `
					) `
					-or `
					( `
						"$($InputObject[$intI].UserPrincipalName)" `
						-notmatch `
						"^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" `
					) `
				)
				{
					Write-Error "Unable To Recognize The Provided Input Object";
					$PSCmdlet.WriteObject($objMfa);
					Continue;
				}
			}
			ElseIf ("$($InputObject[$intI])" -match "^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
			{
				##### Assign the UPN Property To The Corresponding Object Property
				$objMfa.UserPrincipalName = "$($InputObject[$intI])";
				
				##### Query The Msol V1 About User With UPN
				Write-Debug "Query The Msol V1 About User With UPN: $($objMfa.UserPrincipalName)";
				[Microsoft.Online.Administration.User[]]$arrMsolUsr = @();
				[Microsoft.Online.Administration.User[]]$arrMsolUsr = Get-MsolUser `
					-UserPrincipalName "$($objMfa.UserPrincipalName)" `
					-Verbose:$false -Debug:$false;
				#####
				
				If ($arrMsolUsr.Count -eq 1)
				{
					##### Process The User
					$objMfa.MsolUser = $arrMsolUsr[0] | Select-Object -Property * -Verbose:$false -Debug:$false;
				}
				ElseIf ($arrMsolUsr.Count -lt 1)
				{
					Write-Error "Unable To Find MsolUser With UPN:$($objMfa.UserPrincipalName)";
					$PSCmdlet.WriteObject($objMfa);
					Continue;
				}
				ElseIf ($arrMsolUsr.Count -gt 1)
				{
					Write-Error "UPN Conflict in Msol V1 Service About $($objMfa.UserPrincipalName)";
					$PSCmdlet.WriteObject($objMfa);
					Continue;
				}
			}
			ElseIf ("$($InputObject[$intI])" -match "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
			{
				##### Assign the UPN Property To The Corresponding Object Property
				$objMfa.ObjectId = "$($InputObject[$intI])";
				
				##### Query The Msol V1 About User With UPN
				Write-Debug "Query The Msol V1 About User With ObjectId: $($objMfa.ObjectId)";
				[Microsoft.Online.Administration.User[]]$arrMsolUsr = @();
				[Microsoft.Online.Administration.User[]]$arrMsolUsr = Get-MsolUser `
					-ObjectId "$($objMfa.ObjectId)" `
					-Verbose:$false -Debug:$false;
				#####
				
				If ($arrMsolUsr.Count -eq 1)
				{
					##### Process The User
					$objMfa.MsolUser = $arrMsolUsr[0] | Select-Object -Property * -Verbose:$false -Debug:$false;
				}
				ElseIf ($arrMsolUsr.Count -lt 1)
				{
					Write-Error "Unable To Find MsolUser With ObjectId:$($objMfa.ObjectId)";
					$PSCmdlet.WriteObject($objMfa);
					Continue;
				}
				ElseIf ($arrMsolUsr.Count -gt 1)
				{
					Write-Error "ObjectId Conflict in Msol V1 Service About $($objMfa.ObjectId)";
					$PSCmdlet.WriteObject($objMfa);
					Continue;
				}
			}
			
			#==================================================================================
			#endregion Retrieve MsolUser Object From AzureAD
			#==================================================================================
			
			#==================================================================================
			#region Calculate The Initial State
			#==================================================================================
			
			##### Continue If The MsolUser Is Generated
			Write-Debug "Continue If The MsolUser Is Generated";
			If ( `
				"$(($objMfa.MsolUser | Get-Member -Verbose:$false -Debug:$false)[0].TypeName)" `
				-eq `
				"Selected.Microsoft.Online.Administration.User" `
			)
			{
				##### Evaluate The Current Object State
				Write-Debug "Evaluate The Current Object State";
				$objMfa.UserPrincipalName = "$($objMfa.MsolUser.UserPrincipalName)";
				$objMfa.DisplayName = "$($objMfa.MsolUser.DisplayName)";
				$objMfa.ObjectId = "$($objMfa.MsolUser.ObjectId.Guid)";
				$objMfa.MfaState = "$($objMfa.MsolUser.StrongAuthenticationRequirements[0].State)";
				$objMfa.ValueCorrect = (-not "$($objMfa.MfaState)");
				Write-Verbose "Found UPN:$($objMfa.UserPrincipalName) ObjectId:$($objMfa.ObjectId) MfaState:$($objMfa.MfaState)";
				
				##### Get Users StrongAuthenticationMethods
				[Microsoft.Online.Administration.StrongAuthenticationMethod[]]$arrAuthMethods = `
				$objMfa.MsolUser.StrongAuthenticationMethods;
			}
			
			#==================================================================================
			#endregion Calculate The Initial State
			#==================================================================================
			
			#==================================================================================
			#region Disable-SnsMfa
			#==================================================================================
			
			##### Continue If The MsolUser Is Retrieved Successfully
			Write-Debug "Continue If The MsolUser Is Retrieved Successfully"
			If ( `
				"$(($objMfa.MsolUser | Get-Member -Verbose:$false -Debug:$false)[0].TypeName)" `
				-eq `
				"Selected.Microsoft.Online.Administration.User" `
			)
			{
				##### Verify Whether The MFA Is Not Enabled
				Write-Debug "Verify Whether The MFA Is Not Enabled";
				If (-not $objMfa.ValueCorrect)
				{
					##### Invoke ShouldProcess Method
					Write-Debug "Invoke ShouldProcess Method";
					If ($PSCmdlet.ShouldProcess("$($objMfa.UserPrincipalName)"))
					{
						#==================================================================================
						#region Disable-MFA
						#==================================================================================
						
						##### Loop The MFA Disablement
						Write-Debug "Loop The MFA Disablement";
						[System.UInt32]$intIn = 0;
						While ((-not $objMfa.ValueCorrect) -and ($intIn -lt $Attempts))
						{
							##### Disable MFA Of The User
							Write-Verbose "Disable MFA Of: $($objMfa.UserPrincipalName)";
							Set-MsolUser `
								-ObjectId "$($objMfa.ObjectId)" `
								-StrongAuthenticationRequirements @() `
								-Verbose:$false -Debug:$false | Out-Null;
							#####
							
							##### Process The Loop Variables
							Write-Debug "Process The Loop Variables";
							[System.UInt32]$intIn = $intIn + 1;
							$objMfa.ValueModified = $true;
							$objMfa.MsolUser = $null;
							$objMfa.MfaState = "Enabled";
							$objMfa.ValueCorrect = $false;
							Start-Sleep -Seconds 1 -Verbose:$false -Debug:$false;
							
							##### Query The Msol V1 About User With UPN
							Write-Debug "Query The Msol V1 About User With UPN: $($objMfa.UserPrincipalName)";
							[Microsoft.Online.Administration.User[]]$arrMsolUsr = @();
							[Microsoft.Online.Administration.User[]]$arrMsolUsr = Get-MsolUser `
								-ObjectId "$($objMfa.ObjectId)" `
								-Verbose:$false -Debug:$false;
							#####
							
							##### Verify The Msol V1 Query Output
							Write-Debug "Verify The Msol V1 Query Output";
							If ($arrMsolUsr.Count -eq 1)
							{
								##### Update The Object Properties
								Write-Debug "Update The Object Properties";
								$objMfa.MsolUser = $arrMsolUsr[0] | Select-Object -Property * -Verbose:$false -Debug:$false;
								$objMfa.MfaState = "$($objMfa.MsolUser.StrongAuthenticationRequirements[0].State)";
								$objMfa.ValueCorrect = (-not "$($objMfa.MfaState)");
							}
						}
						
						#==================================================================================
						#endregion Disable-MFA
						#==================================================================================
						
						#==================================================================================
						#region Put The StrongAuthenticationMethods Back
						#==================================================================================
						
						##### Check Whether There Are Methods To Be Reverted
						Write-Debug "Check Whether There Are Methods To Be Reverted";
						If ($arrAuthMethods.Count -gt 0)
						{
							##### Verify the Current Authentication Methods
							[System.Boolean]$bolMethOk = $false;
							[System.Boolean]$bolMethOk = ($arrAuthMethods.Count -eq $objMfa.MsolUser.StrongAuthenticationMethods.Count);
							
							##### Loop The MFA Methods Insert
							Write-Debug "Loop The MFA Methods Insert";
							[System.UInt32]$intIn = 0;
							While ((-not $bolMethOk) -and ($intIn -lt $Attempts))
							{
								##### Set StrongAuthenticationMethods Back To The User
								Write-Verbose "Set StrongAuthenticationMethods Back To: $($objMfa.UserPrincipalName)";
								Set-MsolUser `
									-ObjectId "$($objMfa.ObjectId)" `
									-StrongAuthenticationMethods $arrAuthMethods `
									-Verbose:$false -Debug:$false | Out-Null;
								#####
								
								##### Process The Loop Variables
								Write-Debug "Process The Loop Variables";
								[System.UInt32]$intIn = $intIn + 1;
								$objMfa.MsolUser = $null;
								[System.Boolean]$bolMethOk = $false;
								Start-Sleep -Seconds 1 -Verbose:$false -Debug:$false;
								
								##### Query The Msol V1 About User With UPN
								Write-Debug "Query The Msol V1 About User With UPN: $($objMfa.UserPrincipalName)";
								[Microsoft.Online.Administration.User[]]$arrMsolUsr = @();
								[Microsoft.Online.Administration.User[]]$arrMsolUsr = Get-MsolUser `
									-ObjectId "$($objMfa.ObjectId)" `
									-Verbose:$false -Debug:$false;
								#####
								
								##### Verify The Msol V1 Query Output
								Write-Debug "Verify The Msol V1 Query Output";
								If ($arrMsolUsr.Count -eq 1)
								{
									##### Update The Object Properties
									Write-Debug "Update The Object Properties";
									$objMfa.MsolUser = $arrMsolUsr[0] | Select-Object -Property * -Verbose:$false -Debug:$false;
									[System.Boolean]$bolMethOk = ($arrAuthMethods.Count -eq $objMfa.MsolUser.StrongAuthenticationMethods.Count);
								}
							}
							
							##### Verify Whether the Methods Are Set Back or The Number Of Attempts Exceeded
							If (-not $bolMethOk) { $objMfa.ValueCorrect = $false; };
						}
						
						#==================================================================================
						#endregion Put The StrongAuthenticationMethods Back
						#==================================================================================
					}
				}
				Else
				{
					Write-Verbose "The MFA Of User:$($objMfa.UserPrincipalName) Is Already Disabled";
				}
			}
			
			#==================================================================================
			#endregion Disable-SnsMfa
			#==================================================================================
			
			##### Pass The Output Object To The Pipeline
			Write-Debug "Pass Output Object To The Pipeline";
			$PSCmdlet.WriteObject($objMfa);
		}
		
		##### Close The Progress Bar
		Write-Debug 'Close The Progress Bar';
		If ($InputObject.Count -gt 5)
		{
			Write-Progress -Activity 'Enable-SnsMfa' -Id 1 -PercentComplete 100 -Verbose:$false -Debug:$false;
			Write-Progress -Activity 'Enable-SnsMfa' -Id 1 -Completed -Verbose:$false -Debug:$false;
		}
	}
	
	##### Override The End Method
	End
	{
		Write-Verbose '';
		Write-Debug 'Override End Method';
		
		##### Reset The Variables
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'intIn';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'bolMethOk';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'arrAuthMethods';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'arrMsolUsr';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'objMfa';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'intI';
		
		$PSCmdlet.MyInvocation.BoundParameters | Select-Object -ExpandProperty 'Keys' -Verbose:$false -Debug:$false | ForEach `
		{Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name "$($_)"};
		
		##Stop The StopWatch
		$objCmdStopWatch.Stop();
		Write-Verbose "Command Elapsed: ""$($objCmdStopWatch.ElapsedMilliseconds)"" Milliseconds." ;
		Write-Verbose "End!";
	}
}

##### Assert-SnsGroupBasedLicense =================================================
Function Assert-SnsGroupBasedLicense ()
{
<#
.SYNOPSIS
CmdLet Intended To Verify And Confirm Whether Specified Licenses Is Assigned To The Specified User Using Group
Based Licensing AzureAD Feature.
.DESCRIPTION
CmdLet Intended To Verify And Confirm Whether Specified Licenses Is Assigned To The Specified User Using Group
Based Licensing AzureAD Feature.
This CmdLet Search Among The Licenses Assigned To The User About The Specified License. Then Reads The
GroupsAssigningLicense Property Of The Specified License. This License Property Normally Contains A Collection Of
Object ID's Of The Objects That Have Assigned That License.
In Case The License Is Assigned Directly Via PowerShell Or The Admin Portal, There Will Be The Users ObjectID (Not
Administrators One) Or The Collection Will Be Empty. The Value Of The Property Can Neither Be Used For
Identification Who Did Assigned The License, Nor For Troubleshooting, Because The Value There Is The Users Own
ObjectID. The Collection Will Be Empty Whenever The Group Based License Feature Were Never Used In The Tenant.
In Case The User Inherits Specified License From A Group Or Groups, The Collection Will Contain The ObjectID Of
The Groups Which Assign The Specified License To The User. In That Way The ObjectID's From The Collection Can Be
Used For Troubleshooting. For That Purpose The CmdLet Have Switch Parameter PassThru, Which Is Used To Revert The
ObjectID Of The Groups Assigning The Specified License To The Specified User.
Note: A License Might Be Assigned Directly In Addition To Being Inherited. In Case A License Is Inherited Will Be
Wrong Assumption That It Is Not Directly Assigned.
Note: The CmdLet Does Not Perform Any Queries To Msol V1 Service As Long As All The Required Information Is
Already Present In The Required Input. It Just Extracts The Information From There.
.PARAMETER MsolUser
Specifies Either MsolUser Object Which Have To Be Evaluated.
Parameter Alias: N/A
Parameter Validation: Yes Using Object TypeName Validation
.PARAMETER SkuId
Specifies The ID Of The License Which Have To Be Verified.
Parameter Alias: N/A
Parameter Validation: Yes, Using RegEx Validation
.PARAMETER PassThru
Specifies That The CmdLet Have To Revert The ObjectID's Of The Groups That The Specified User Inherits The
Specified License From.
Parameter Alias: N/A
Parameter Validation: N/A
.INPUTS
The CmdLet Does Not Accept Pipeline Input.
.OUTPUTS
Pipeline Output [System.Boolean] Which Indicates Whether The Specified User Inherits The Specified License From
Groups.
.NOTES
AUTHOR:    Svetoslav Nedyalkov Savov (svesavov@hotmail.com)
COPYRIGHT: (c) 2020 Svetoslav Nedyalkov Savov, all rights reserved.
THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
.EXAMPLE
[System.Boolean]$bolGroupAssigned = Assert-SnsGroupBasedLicense -MsolUser $objUser `
-SkuId "contoso:ENTERPRISEPACK";
#>
[CmdletBinding(PositionalBinding = $false)]
Param (
	[Parameter(Mandatory = $true, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Alias('User')]
	[ValidateNotNullOrEmpty()]
	[ValidateScript({( `
		"$(($_ | Get-Member -Verbose:$false -Debug:$false )[0].TypeName)" `
		-like `
		"*Microsoft.Online.Administration.User" `
	)})]
	[System.Object]$MsolUser,
	
	[Parameter(Mandatory = $true, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateNotNullOrEmpty()]
	[ValidateScript({("$($_)" -match "^[a-z]+:[a-zA-Z0-9_]+$")})]
	[System.String]$SkuId,
	
	[Parameter(Mandatory = $false, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Switch]$PassThru = $false
)
	##### Override The Begin Method
	Begin
	{
		Write-Verbose '';
		Write-Verbose "Assert-SnsGroupBasedLicense";
		Write-Debug 'Override Begin Method';
		
		##### Initialize New Measure Watch
		[System.Diagnostics.Stopwatch]$objCmdStopWatch = [System.Diagnostics.Stopwatch]::StartNew();
		
		If ("$((Get-FileHash -Path $PSCommandPath -Algorithm 'SHA256' -Verbose:$false -Debug:$false).Hash)" -ne "$($global:SnsModuleCfg.ModuleHash)")
		{Write-Warning 'There Is New Version Of SnsPsModule Module Released. Please Restart The PowerShell Session.'};
		
		##### Initialize The Variables
		[System.UInt32]$intI = 0;
		[System.UInt32]$intIn = 0;
		[System.Boolean]$bolGbl = $false;
		
		##### Continue If The User Have Licenses Assigned
		Write-Debug "Continue If The User Have Licenses Assigned";
		If ($MsolUser.Licenses.Count -gt 0)
		{
			##### Process All Assigned To The User Licenses
			Write-Debug "Process All Assigned To The User Licenses";
			[System.UInt32]$intI = 0;
			For  ([System.UInt32]$intI = 0; $intI -lt $MsolUser.Licenses.Count; $intI++)
			{
				##### We Look For The Specified License SKU In All Licenses Assigned To The User
				If ("$($MsolUser.Licenses[$intI].AccountSkuId)" -like "$($SkuId)")
				{
					##### GroupsAssigningLicense Property Contains A Collection Of IDs Of Objects Assigning The License
					##### This Could Be A Group Object Or A User Object (Contrary To What The Name Suggests)
					##### If The Collection Contains At Least One ID Not Matching The User ID This Means That The License Is Inherited From A Group.
					##### Note: The License May Also Be Assigned Directly In Addition To Being Inherited
					##### In Case In The Tenant Were Never Used Group Based Licensing The GroupsAssigningLicense Will Be Empty
					##### Verify The Count Of The License Assigning Sources
					Write-Debug "Verify The Count Of The License Assigning Sources";
					If ($MsolUser.Licenses[$intI].GroupsAssigningLicense.Count -gt 0)
					{
						##### Process Each License Assigning Source As It Can Be A Collection
						Write-Debug "Process Each License Assigning Source";
						[System.UInt32]$intIn = 0;
						For ( `
							[System.UInt32]$intIn = 0; `
							$intIn -lt $MsolUser.Licenses[$intI].GroupsAssigningLicense.Count; `
							$intIn++ `
						)
						{
							##### Check If The Current Assignment Source Belongs To Object Different Than The User Himself
							If ( `
								"$($MsolUser.Licenses[$intI].GroupsAssigningLicense[$intIn].Guid)" `
								-notlike `
								"$($MsolUser.ObjectId)" `
							)
							{
								##### This License Is Group Inherited
								Write-Verbose "The License $($SkuId) Is Assigned To The User Via Group $( `
									$MsolUser.Licenses[$intI].GroupsAssigningLicense[$intIn].Guid)";
								$bolGbl = $true;
								
								##### Verify Whether Return Object Has Been Requested
								If ($PassThru.IsPresent)
								{
									##### Pass The Output Object To The Pipeline
									Write-Debug "Pass Output Object To The Pipeline";
									$PSCmdlet.WriteObject("$($MsolUser.Licenses[$intI].GroupsAssigningLicense[$intIn].Guid)");
								}
							}
						}
					}
				}
			}
		}
		
		##### Verify Whether Return Object Has Been Requested
		If (-not $PassThru.IsPresent)
		{
			##### Pass The Output Object To The Pipeline
			Write-Debug "Pass Output Object To The Pipeline";
			$PSCmdlet.WriteObject($bolGbl);
		}
		
		##### Reset The Variables
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'bolGbl';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'intIn';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'intI';
		
		$PSCmdlet.MyInvocation.BoundParameters | Select-Object -ExpandProperty 'Keys' -Verbose:$false -Debug:$false | ForEach `
		{Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name "$($_)"};
	}
	
	##### Override The End Method
	End
	{
		##Stop The StopWatch
		$objCmdStopWatch.Stop();
		Write-Verbose "Command Elapsed: ""$($objCmdStopWatch.ElapsedMilliseconds)"" Milliseconds." ;
		Write-Verbose "End!";
	}
}

##### Assert-SnsDirectAssignedLicense =============================================
Function Assert-SnsDirectAssignedLicense ()
{
<#
.SYNOPSIS
CmdLet Intended To Verify And Confirm Whether Specified Licenses Is Assigned To The Specified User Directly Using
PowerShell Or Admin Portal.
.DESCRIPTION
CmdLet Intended To Verify And Confirm Whether Specified Licenses Is Assigned To The Specified User Directly Using
PowerShell Or Admin Portal.
This CmdLet Search Among The Licenses Assigned To The User About The Specified License. Then Reads The
GroupsAssigningLicense Property Of The Specified License. This License Property Normally Contains A Collection Of
Object ID's Of The Objects That Have Assigned That License.
In Case The License Is Assigned Directly Via PowerShell Or The Admin Portal, There Will Be The Users ObjectID (Not
Administrators One) Or The Collection Will Be Empty. The Value Of The Property Can Neither Be Used For
Identification Who Did Assigned The License, Nor For Troubleshooting, Because The Value There Is The Users Own
ObjectID. The Collection Will Be Empty Whenever The Group Based License Feature Were Never Used In The Tenant.
In Case The User Inherits Specified License From A Group Or Groups, The Collection Will Contain The ObjectID Of
The Groups Which Assign The Specified License To The User. In That Way The ObjectID's From The Collection Can Be
Used For Troubleshooting.
Note: A License Might Be Assigned Directly In Addition To Being Inherited. In Case A License Is Directly Assigned
Will Be Wrong Assumption That It Is Not Inherited From A Group.
Note: The CmdLet Does Not Perform Any Queries To Msol V1 Service As Long As All The Required Information Is
Already Present In The Required Input. It Just Extracts The Information From There.
.PARAMETER MsolUser
Specifies Either MsolUser Object Which Have To Be Evaluated.
Parameter Alias: N/A
Parameter Validation: Yes Using Object TypeName Validation
.PARAMETER SkuId
Specifies The ID Of The License Which Have To Be Verified.
Parameter Alias: N/A
Parameter Validation: Yes, Using RegEx Validation
.INPUTS
The CmdLet Does Not Accept Pipeline Input.
.OUTPUTS
Pipeline Output [System.Boolean] Which Indicates Whether The Specified User Have The Specified License Directly
Assigned.
.NOTES
AUTHOR:    Svetoslav Nedyalkov Savov (svesavov@hotmail.com)
COPYRIGHT: (c) 2020 Svetoslav Nedyalkov Savov, all rights reserved.
THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
.EXAMPLE
[System.Boolean]$bolGroupAssigned = Assert-SnsDirectAssignedLicense -MsolUser $objUser `
-SkuId "contoso:ENTERPRISEPACK";
#>
[CmdletBinding(PositionalBinding = $false)]
Param (
	[Parameter(Mandatory = $true, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[Alias('User')]
	[ValidateNotNullOrEmpty()]
	[ValidateScript({( `
		"$(($_ | Get-Member -Verbose:$false -Debug:$false )[0].TypeName)" `
		-like `
		"*Microsoft.Online.Administration.User" `
	)})]
	[System.Object]$MsolUser,
	
	[Parameter(Mandatory = $true, `
		ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false)]
	[ValidateNotNullOrEmpty()]
	[ValidateScript({("$($_)" -match "^[a-z]+:[a-zA-Z0-9_]+$")})]
	[System.String]$SkuId
)
	##### Override The Begin Method
	Begin
	{
		Write-Verbose '';
		Write-Verbose "Assert-SnsDirectAssignedLicense";
		Write-Debug 'Override Begin Method';
		
		##### Initialize New Measure Watch
		[System.Diagnostics.Stopwatch]$objCmdStopWatch = [System.Diagnostics.Stopwatch]::StartNew();
		
		If ("$((Get-FileHash -Path $PSCommandPath -Algorithm 'SHA256' -Verbose:$false -Debug:$false).Hash)" -ne "$($global:SnsModuleCfg.ModuleHash)")
		{Write-Warning 'There Is New Version Of SnsPsModule Module Released. Please Restart The PowerShell Session.'};
		
		##### Initialize The Variables
		[System.UInt32]$intI = 0;
		[System.UInt32]$intIn = 0;
		[System.Boolean]$bolDirect = $false;
		
		##### Continue If The User Have Licenses Assigned
		Write-Debug "Continue If The User Have Licenses Assigned";
		If ($MsolUser.Licenses.Count -gt 0)
		{
			##### Process All Assigned To The User Licenses
			Write-Debug "Process All Assigned To The User Licenses";
			[System.UInt32]$intI = 0;
			For  ([System.UInt32]$intI = 0; $intI -lt $MsolUser.Licenses.Count; $intI++)
			{
				##### We Look For The Specified License SKU In All Licenses Assigned To The User
				If ("$($MsolUser.Licenses[$intI].AccountSkuId)" -like "$($SkuId)")
				{
					##### GroupsAssigningLicense Property Contains A Collection Of IDs Of Objects Assigning The License
					##### This Could Be A Group Object Or A User Object (Contrary To What The Name Suggests)
					##### If The Collection Contains At Least One ID Not Matching The User ID This Means That The License Is Inherited From A Group.
					##### Note: The License May Also Be Assigned Directly In Addition To Being Inherited
					##### In Case In The Tenant Were Never Used Group Based Licensing The GroupsAssigningLicense Will Be Empty
					##### Verify The Count Of The License Assigning Sources
					Write-Debug "Verify The Count Of The License Assigning Sources";
					If ($MsolUser.Licenses[$intI].GroupsAssigningLicense.Count -gt 0)
					{
						##### Process Each License Assigning Source As It Can Be A Collection
						Write-Debug "Process Each License Assigning Source";
						[System.UInt32]$intIn = 0;
						For ( `
							[System.UInt32]$intIn = 0; `
							$intIn -lt $MsolUser.Licenses[$intI].GroupsAssigningLicense.Count; `
							$intIn++ `
						)
						{
							##### Check If The Current Assignment Source Is The User Himself
							If ( `
								"$($MsolUser.Licenses[$intI].GroupsAssigningLicense[$intIn].Guid)" `
								-like `
								"$($MsolUser.ObjectId)" `
							)
							{
								##### This License Is Directly Assigned
								Write-Verbose "The License $($SkuId) Is Directly Assigned To The User";
								$bolDirect = $true;
							}
						}
					}
					Else
					{
						##### There Are No ObjectID In The Object Property
						##### Which Means The Tenant Has Never GBL
						##### Which MEans That The License Can Be Assigned Only Directly
						Write-Verbose "The License $($SkuId) Is Directly Assigned To The User";
						[System.Boolean]$bolDirect = $true;
					}
				}
			}
		}
		
		##### Pass The Output Object To The Pipeline
		Write-Debug "Pass Output Object To The Pipeline";
		$PSCmdlet.WriteObject($bolDirect);
		
		##### Reset The Variables
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'bolDirect';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'intIn';
		Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name 'intI';
		
		$PSCmdlet.MyInvocation.BoundParameters | Select-Object -ExpandProperty 'Keys' -Verbose:$false -Debug:$false | ForEach `
		{Remove-Variable -Force -WhatIf:$false -Confirm:$false -ErrorAction 'SilentlyContinue' -Name "$($_)"};
	}
	
	##### Override The End Method
	End
	{
		##Stop The StopWatch
		$objCmdStopWatch.Stop();
		Write-Verbose "Command Elapsed: ""$($objCmdStopWatch.ElapsedMilliseconds)"" Milliseconds." ;
		Write-Verbose "End!";
	}
}

#==================================================================================
#endregion Commands
#==================================================================================

