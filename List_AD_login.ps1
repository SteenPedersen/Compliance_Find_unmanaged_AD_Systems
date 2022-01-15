# Gets time stamps for all computers in the domain that have logged in since specified number of days
# Steen Pedersen, 2022 - Version 003
#
# Prepare 
# Windows 10 -
#    Download https://www.microsoft.com/en-us/download/details.aspx?id=45520 
# Install-Module -Name WindowsCompatibility
# Add-WindowsCapability –online –Name “Rsat.ActiveDirectory.DS-LDS.Tools”
# Info from: https://theitbros.com/install-and-import-powershell-active-directory-module/


# List modules Get-Module -ListAvailable

#$g_Destination_folder 	= "E:\McAfee\Scripts\AD_Login_list\data\"
$g_ISO_Date = Get-Date -format "yyyyMMdd"
$g_ISO_Date_with_time = Get-Date -format "yyyyMMdd_HHmm"


import-module ActiveDirectory
#$domain="domain name.net"
$domain=""
$Daysactive=14
$time=(Get-Date).Adddays(-($Daysactive))
$g_working_dir = $PSScriptRoot
$g_Destination_folder 	= $g_working_dir
#$g_ADComputer_file = "$g_Destination_folder"+"ALL_ADComputers_7_"+$g_ISO_Date+".csv" 
$g_ADComputer_file = "$g_Destination_folder"+"\ALL_ADComputers_2.csv" 
$g_ePO_result_csv_filename ='\ePO_result_2.csv'
$g_ePO_dupplicated_csv_filename = "$g_Destination_folder"+"\ePO_temp_3.csv" 
$g_ISO_Date_with_time = Get-Date -format "yyyyMMdd_HHmmss"
#
$Result =''
$cred=''
$URL_ePO = 'https://<epo>:port'
$username = 'user'  
$password = 'password'  

$URL_ePO = 'https://<ip>:<port>'
$username = '<script_ePO_user>'  
$password = '<password>'  

$password_base64 = ConvertTo-SecureString $password -AsPlainText -Force  
$cred = New-Object System.Management.Automation.PSCredential ($username, $password_base64)    
# Ask for cred if there is not coded credentials
if (($username -eq "user") -or ($username.Length -lt 1))
{
    $cred = Get-Credential #Ask for ePO credentials
}


# Bypass the certificate check
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Ssl3
[Net.ServicePointManager]::SecurityProtocol = "Tls, Tls11, Tls12, Ssl3"


function g_Prepare_modules_needed {
    if (Get-Module -ListAvailable -Name servermanager) {
        Write-Host "Module servermanager exists"
    } 
    else {
        Write-Host "Module servermanager does not exist"
        Get-WindowsCapability -Name RSAT.active* -Online | Add-WindowsCapability -Online
        Import-module ServerManager -Verbose
        Add-windowsFeature RSAT-Ad-PowerShell
    }
}

function g_Get_AD_Systems_from_AD {
	# Get all AD computers with lastLogonTimestamp less than our time 
	# ---- Get All AD Computers -----
	Echo "Read domain $domain for All AD Computers with active login within $Daysactive days - starting from $time"

	$l_ADComputers = Get-ADComputer -Filter {LastLogonTimeStamp -gt $time -and OperatingSystem -like '*Windows*' -and enabled -eq $true} -Properties LastLogonTimeStamp, OperatingSystem 

	# Less than 2 days $l_ADComputers = Get-ADComputer -Filter {LastLogonTimeStamp -lt $time -and OperatingSystem -like '*Windows*' -and enabled -eq $true} -Properties LastLogonTimeStamp, OperatingSystem 

	# WORKING $l_ADComputers = Get-ADComputer -Filter {LastLogonTimeStamp -ge $time -and OperatingSystem -like '*Windows*' -and enabled -eq $true} -Properties LastLogonTimeStamp, OperatingSystem 
	# WORKING $l_ADComputers = Get-ADComputer -Filter {OperatingSystem -like '*Windows*' -and enabled -eq $true} -Properties LastLogonTimeStamp, OperatingSystem 
	# WORKING $l_ADComputers = Get-ADComputer -Filter {OperatingSystem -like '*Windows*'} -Properties LastLogonTimeStamp, OperatingSystem | Where {$_.Enabled -eq $true}

	#$l_ADComputers = Get-ADComputer -Filter {LastLogonTimeStamp -lt $time} -Properties LastLogonTimeStamp | Where {$_.Enabled -eq $true}
	#$l_ADComputers = Get-ADComputer -Filter {LastLogonTimeStamp -lt $time} -Properties LastLogonTimeStamp

	# Output hostname and lastLogonTimestamp into CSV 
	#select-object Name,@{Name="Stamp"; Expression={[DateTime]::FromFileTime($_.lastLogonTimestamp)}} | export-csv OLD_Computer.csv -notypeinformation
		
	#[datetime]::FromFileTime(129948127853609000).ToString('d MMMM')	

	$g_Clean_Computer_list= @()
	ForEach ($l_system in $l_ADComputers ) {
		#echo $scope.name.length
		#If ($scope.name.length -gt 0) 
		#{
		#echo $scope.name
		#}
		
		
		$l_human_date=[datetime]::FromFileTime($l_system.lastLogonTimestamp).ToString('yyyyMMddhhmm')
		echo $l_system.name $l_human_date
		#$l_system.Login_Data=$l_human_date
		$l_system.lastLogonTimestamp=$l_human_date
		#$l_system.Login_Data='abc'
		#echo $l_human_date
		#echo $l_system
		$g_Clean_Computer_list += $l_system

	}
	echo "Write result to: $g_ADComputer_file"

	#	$l_ADComputers | Export-Csv -Path $g_ADComputer_file -NoTypeInformation -Delimiter ";"
		$g_Clean_Computer_list | Export-Csv -Path $g_ADComputer_file -NoTypeInformation -Delimiter ";"
        #($Short | ConvertFrom-Json) | export-csv -Path ($g_working_dir+$g_ePO_result_csv_filename) -NoTypeInformation


}


function g_Get_System_Tree_info_from_ePO {
    $ePO_command = '/remote/core.executeQuery?' 
    
    # Pull all systems
    $options = 'target=EPOLeafNode&select=(select EPOLeafNode.AutoID EPOLeafNode.NodeName EPOLeafNode.LastUpdate EPOComputerProperties.OSType EPOComputerProperties.IPAddress EPOComputerProperties.UserName EPOLeafNode.Tags EPOBranchNode.NodeTextPath2 EPOLeafNode.AgentGUID EPOComputerProperties.UserProperty2 EPOComputerProperties.UserProperty3 )&:output=json'
    
    # Pull only systems with DLP installed and Workstations
    #$options = 'target=EPOLeafNode&select=(select%20EPOLeafNode.AutoID%20EPOLeafNode.NodeName%20EPOLeafNode.LastUpdate%20EPOLeafNode.AgentGUID%20EPOComputerProperties.UserName%20EPOLeafNode.Tags%20EPOBranchNode.NodeTextPath2%20EPOComputerProperties.UserProperty2%20EPOComputerProperties.UserProperty3%20EPOProdPropsView_UDLP.productversion%20)&where=(+and+(+version_ge+EPOProdPropsView_UDLP.productversion+%2211%22+)+(+eq+EPOComputerProperties.OSPlatform+%22Workstation%22+)+)+)&:output=json'
    
    # Solidcore status from All workstations
    #$options = 'target=EPOLeafNode&select=(select EPOLeafNode.AutoID EPOComputerProperties.ComputerName EPOComputerProperties.IPAddress EPOComputerProperties.OSType SCOR_VW_STATUS.SolidifierStatus SCOR_VW_STATUS.SolidifierStatusOnReboot SCOR_VW_STATUS.CLIStatus SCOR_VW_STATUS.SoStatus SCOR_VW_STATUS.activationStatus SCOR_VW_STATUS.memoryProtection)&where=(eq+EPOComputerProperties.OSPlatform+%22Workstation%22+)&:output=json'
    
    # Solidcore status from All systems with Solidcore status
    #$options = 'target=EPOLeafNode&select=(select EPOLeafNode.AutoID EPOComputerProperties.ComputerName EPOComputerProperties.IPAddress EPOComputerProperties.OSType SCOR_VW_STATUS.SolidifierStatus SCOR_VW_STATUS.SolidifierStatusOnReboot SCOR_VW_STATUS.CLIStatus SCOR_VW_STATUS.SoStatus SCOR_VW_STATUS.activationStatus SCOR_VW_STATUS.memoryProtection)&where=(not_isBlank+SCOR_VW_STATUS.SolidifierStatus)&:output=json'

    $URL = $URL_ePO + $ePO_command + $options
    "   URL used: "+$URL
    #Working 
    #$Result = Invoke-RestMethod -Uri $URL -Credential $cred 
    $Result = Invoke-RestMethod  -Uri $URL -Credential $cred -Method GET -Headers $headers -Body $body -ContentType 'application/json'
    
    # Write the Result to a file - this is needed as the result size can be >100 MBytes
    $Short = $Result.Replace('OK:','')
    
    #Output in JSON format
    $Short | out-file -filepath ($g_working_dir+'\ePO_result.json')
    #$Short

    #EPOLeafNode.LastUpdate

    #Output in CSV format
    ($Short | ConvertFrom-Json) | export-csv -Path ($g_working_dir+$g_ePO_result_csv_filename) -NoTypeInformation
    }


function Handle_files_and_compare_dates {
        "Ready for handling the files"     
        # remove first line in the ePO_Result file
        ##$l_file = $g_working_dir+'\ePO_result.json'
        #Remove_top_line_in_file ($l_file)
        #$l_file_tmp = $g_working_dir+'\ePO_result.txt.tmp'
        ##$ePO_System_Obj = Get-Content -Raw -Path $l_file | ConvertFrom-Json
        ##"Number of Systems in the ePO List : "+$ePO_System_Obj.Count

        $l_file_epo_csv = $g_working_dir+$g_ePO_result_csv_filename
        $ePO_System_Obj_csv = Get-Content -Raw -Path $l_file_epo_csv | ConvertFrom-Csv
        $l_file_epo_csv
        "Number of Systems in the ePO List : "+$ePO_System_Obj_csv.Count

        #$l_file_ad_csv = $g_working_dir+'\ALL_ADComputers.csv'
        $AD_System_Obj_csv = Get-Content -Raw -Path $g_ADComputer_file| ConvertFrom-Csv -Delimiter ";"
        "Number of Systems in the AD List :  "+$AD_System_Obj_csv.Count
        if ($AD_System_Obj_csv.Count -lt 1) {
            'Missing AD information and exit'
             exit}

        $l_unmanged_state_count = 0 
        $l_manged_state_count = 0

        "--- Start handling the data ---"
        # Prepare list of hosts to Tag
        $l_array_host = New-Object System.Collections.ArrayList($null)
        ForEach ($l_system_in_EPO in $ePO_System_Obj_csv) {
            # For each system in the ePO System list        
            
            # Unifiy the user names all to Upcase
            ##$l_username = $l_system | Select-Object -ExpandProperty "EPOComputerProperties.UserName"
            ##$l_username = $l_username.ToUpper()
            # Make array of with each Username for a each single system
            ##$l_username_array = $l_username.split(",")
            
            $l_LastUpdate = $l_system_in_EPO | Select-Object -ExpandProperty "EPOLeafNode.LastUpdate"
            $l_System_AutoID = $l_system_in_EPO | Select-Object -ExpandProperty "EPOLeafNode.AutoID"
            
            $l_hostename = $l_system_in_EPO | Select-Object -ExpandProperty "EPOLeafNode.NodeName"

            # Skip is the l_LastUpdate (Last communication) is blank
            
            if ($l_LastUpdate -gt 0 ) {
                # Is the ePO system located in the AD Name List
                if ($AD_System_Obj_csv.Name.Contains($l_hostename))
                {
                # Identiy which Last Communication time is the most current. There can be duplicated entries in ePO System Tree
                    ForEach ($l_system_in_AD in $AD_System_Obj_csv) {
                        
                        if ($l_system_in_AD.Name -eq ($l_hostename))
                        {
                            
                            # Convert $l_LastUpdate to Date format YYYYMMDDHHMM
                            $l_LastUpdate_date_AD = [int64]$l_system_in_AD.LastLogonTimeStamp
                            $l_Last_AD_date = [datetime]::ParseExact($l_system_in_AD.LastLogonTimeStamp, "yyyyMMddHHmm", $null)
                            $l_LastUpdate_date_ePO = [datetime]$l_LastUpdate
                            
                            $l_timespan = NEW-TIMESPAN -Start $l_Last_AD_date -End $l_LastUpdate_date_ePO 


                            #$Time_temp
                            #$time_convert
                            #$time_convert = $time_convert.ToUniversalTime
                            #'UTC'
                            #$Time_temp.ToUniversalTime().ToString("yyyyMMddHHmm")
                            $l_LastUpdate_date_ePO_UTC = [int64]$l_LastUpdate_date_ePO.ToUniversalTime().ToString("yyyyMMddHHmm")
                            $l_date_diff = (($l_LastUpdate_date_AD - $l_LastUpdate_date_ePO_UTC ))
                            if ($l_date_diff -gt 400) {
                                $l_unmanged_state = "True"
                                $l_unmanged_state_count++

                                'Found ' +$l_hostename   + '   '+  $l_LastUpdate_date_AD + '   '+ $l_LastUpdate_date_ePO_UTC + '   '+ $l_unmanged_state+ '    '+$l_date_diff
                                '       '+$l_Last_AD_date +' - '+ $l_LastUpdate_date_ePO 
                                $l_timespan

                            }
                            else {
                                $l_unmanged_state = "False"
                                $l_manged_state_count++
                            }
                            #$l_date_AD=$l_date_AD+12
                            #$l_date_AD
                            #$l_LastUpdate_date_ePO 
                            # The $l_LastUpdate_date_AD should not be larger than $l_LastUpdate_date_ePO_UTC by more than x hours
                            # Every hour is 100 so if the AD date is 400 or more larger than ePO date then the system has been AD uthenticated but not communcaited to ePO
                            #'Found ' +$l_hostename + '   '+  $l_LastUpdate_date_AD + '   '+ $l_LastUpdate_date_ePO_UTC + '   '+ $l_unmanged_state+ '    '+$l_date_diff
                        }
                        
                    }

                }
            }
            #$l_hostename + '   '+ $l_LastUpdate
        }
        #Write-Output $ePO_System_Obj_csv | Format-Table 
        #Write-Output $AD_System_Obj_csv | Format-Table 

        'Managed:   '+$l_manged_state_count
        'Unmaanged: '+$l_unmanged_state_count

    }

function Handle_files_and_compare_dates2 {
    "Ready for handling the files"     
    # remove first line in the ePO_Result file
    ##$l_file = $g_working_dir+'\ePO_result.json'
    #Remove_top_line_in_file ($l_file)
    #$l_file_tmp = $g_working_dir+'\ePO_result.txt.tmp'
    ##$ePO_System_Obj = Get-Content -Raw -Path $l_file | ConvertFrom-Json
    ##"Number of Systems in the ePO List : "+$ePO_System_Obj.Count

    $l_file_epo_csv = $g_working_dir+$g_ePO_result_csv_filename
    $ePO_System_Obj_csv = Get-Content -Raw -Path $l_file_epo_csv | ConvertFrom-Csv
    $l_file_epo_csv
    "Number of Systems in the ePO List : "+$ePO_System_Obj_csv.Count

    #Remove duplicates from ePO list
    $ePO_System_Obj_csv = $ePO_System_Obj_csv|Sort-Object -Property "EPOLeafNode.NodeName"
    #$ePO_System_Obj_csv
    $l_hostename_previous = ''
    ForEach ($l_system_in_EPO in $ePO_System_Obj_csv) {
        # For each system in the ePO System list        
        $l_LastUpdate = $l_system_in_EPO | Select-Object -ExpandProperty "EPOLeafNode.LastUpdate"
        $l_System_AutoID = $l_system_in_EPO | Select-Object -ExpandProperty "EPOLeafNode.AutoID"
        $l_hostename = $l_system_in_EPO | Select-Object -ExpandProperty "EPOLeafNode.NodeName"
        $l_OS_type = $l_system_in_EPO | Select-Object -ExpandProperty "EPOComputerProperties.OSType"
        If ($l_hostename -eq $l_hostename_previous) {
            
            'Dupple name: '+$l_hostename

        }
        else {
            $l_hostename_previous = $l_hostename    
        }
        
    }
    $ePO_System_Obj_csv | export-csv -Path ($g_ePO_dupplicated_csv_filename) -NoTypeInformation

    exit

    #$l_file_ad_csv = $g_working_dir+'\ALL_ADComputers.csv'
    $AD_System_Obj_csv = Get-Content -Raw -Path $g_ADComputer_file| ConvertFrom-Csv -Delimiter ";"
    "Number of Systems in the AD List :  "+$AD_System_Obj_csv.Count
    if ($AD_System_Obj_csv.Count -lt 1) {
        'Missing AD information and exit'
            exit}

    $l_unmanged_state_count = 0 
    $l_manged_state_count = 0

    "--- Start handling the data ---"
    # Prepare list of hosts to Tag
    $l_array_host = New-Object System.Collections.ArrayList($null)
    ForEach ($l_system_in_EPO in $ePO_System_Obj_csv) {
        # For each system in the ePO System list        
        
        # Unifiy the user names all to Upcase
        ##$l_username = $l_system | Select-Object -ExpandProperty "EPOComputerProperties.UserName"
        ##$l_username = $l_username.ToUpper()
        # Make array of with each Username for a each single system
        ##$l_username_array = $l_username.split(",")
        
        $l_LastUpdate = $l_system_in_EPO | Select-Object -ExpandProperty "EPOLeafNode.LastUpdate"
        $l_System_AutoID = $l_system_in_EPO | Select-Object -ExpandProperty "EPOLeafNode.AutoID"
        
        $l_hostename = $l_system_in_EPO | Select-Object -ExpandProperty "EPOLeafNode.NodeName"

        # Skip is the l_LastUpdate (Last communication) is blank
        
        if ($l_LastUpdate -gt 0 ) {
            # Is the ePO system located in the AD Name List
            if ($AD_System_Obj_csv.Name.Contains($l_hostename))
            {
            # Identiy which Last Communication time is the most current. There can be duplicated entries in ePO System Tree
                ForEach ($l_system_in_AD in $AD_System_Obj_csv) {
                    
                    if ($l_system_in_AD.Name -eq ($l_hostename))
                    {
                        
                        # Convert $l_LastUpdate to Date format YYYYMMDDHHMM
                        $l_LastUpdate_date_AD = [int64]$l_system_in_AD.LastLogonTimeStamp
                        $l_Last_AD_date = [datetime]::ParseExact($l_system_in_AD.LastLogonTimeStamp, "yyyyMMddHHmm", $null)
                        $l_LastUpdate_date_ePO = [datetime]$l_LastUpdate
                        
                        $l_timespan = NEW-TIMESPAN -Start $l_Last_AD_date -End $l_LastUpdate_date_ePO 


                        #$Time_temp
                        #$time_convert
                        #$time_convert = $time_convert.ToUniversalTime
                        #'UTC'
                        #$Time_temp.ToUniversalTime().ToString("yyyyMMddHHmm")
                        $l_LastUpdate_date_ePO_UTC = [int64]$l_LastUpdate_date_ePO.ToUniversalTime().ToString("yyyyMMddHHmm")
                        $l_date_diff = (($l_LastUpdate_date_AD - $l_LastUpdate_date_ePO_UTC ))
                        if ($l_date_diff -gt 400) {
                            $l_unmanged_state = "True"
                            $l_unmanged_state_count++

                            'Found ' +$l_hostename   + '   '+  $l_LastUpdate_date_AD + '   '+ $l_LastUpdate_date_ePO_UTC + '   '+ $l_unmanged_state+ '    '+$l_date_diff
                            '       '+$l_Last_AD_date +' - '+ $l_LastUpdate_date_ePO 
                            $l_timespan

                        }
                        else {
                            $l_unmanged_state = "False"
                            $l_manged_state_count++
                        }
                        #$l_date_AD=$l_date_AD+12
                        #$l_date_AD
                        #$l_LastUpdate_date_ePO 
                        # The $l_LastUpdate_date_AD should not be larger than $l_LastUpdate_date_ePO_UTC by more than x hours
                        # Every hour is 100 so if the AD date is 400 or more larger than ePO date then the system has been AD uthenticated but not communcaited to ePO
                        #'Found ' +$l_hostename + '   '+  $l_LastUpdate_date_AD + '   '+ $l_LastUpdate_date_ePO_UTC + '   '+ $l_unmanged_state+ '    '+$l_date_diff
                    }
                    
                }

            }
        }
        #$l_hostename + '   '+ $l_LastUpdate
    }
    #Write-Output $ePO_System_Obj_csv | Format-Table 
    #Write-Output $AD_System_Obj_csv | Format-Table 

    'Managed:   '+$l_manged_state_count
    'Unmaanged: '+$l_unmanged_state_count

}

function Handle_files_and_compare_dates3 {
    "Ready for handling the files"     
    # remove first line in the ePO_Result file
    ##$l_file = $g_working_dir+'\ePO_result.json'
    #Remove_top_line_in_file ($l_file)
    #$l_file_tmp = $g_working_dir+'\ePO_result.txt.tmp'
    ##$ePO_System_Obj = Get-Content -Raw -Path $l_file | ConvertFrom-Json
    ##"Number of Systems in the ePO List : "+$ePO_System_Obj.Count

    $l_file_epo_csv = $g_working_dir+$g_ePO_result_csv_filename
    $ePO_System_Obj_csv = Get-Content -Raw -Path $l_file_epo_csv | ConvertFrom-Csv
    $l_file_epo_csv
    "Number of Systems in the ePO List : "+$ePO_System_Obj_csv.Count

    #$l_file_ad_csv = $g_working_dir+'\ALL_ADComputers.csv'
    $AD_System_Obj_csv = Get-Content -Raw -Path $g_ADComputer_file| ConvertFrom-Csv -Delimiter ";"
    "Number of Systems in the AD List :  "+$AD_System_Obj_csv.Count
    if ($AD_System_Obj_csv.Count -lt 1) {
        'Missing AD information and exit'
         exit}

    $l_unmanged_state_count = 0 
    $l_manged_state_count = 0

    #Create dictionary for EPO systems
    $EPOSystemsData = New-Object System.Collections.Generic.Dictionary"[String,String]"
    ForEach ($l_system in $ePO_System_Obj_csv) {
        #$EPOSystemsData.Add($l_system.'EPOLeafNode.NodeName', $l_system.'EPOLeafNode.NodeName' )
        $computerSystemFoundInEPO = $EPOSystemsData[$l_system.'EPOLeafNode.NodeName']
        if ($computerSystemFoundInEPO -eq $null) 
        {
            #$EPOSystemsData.Add($l_system.'- ode.NodeName', 'Fundet '+$l_system.'EPOLeafNode.NodeName' ) 
            $l_temp_string = convertto-json -InputObject $l_system
            $EPOSystemsData.Add($l_system.'EPOLeafNode.NodeName', $l_temp_string ) 

        }
        else 
        {
            echo "Double entry found"
            $($l_system.'EPOLeafNode.LastUpdate')
            #echo "Double entry found $($computerSystemFoundInEPO)"
            $currentRecordInDict = convertfrom-json -InputObject $computerSystemFoundInEPO 
            # Hvis ny skal indsættes
            #
            #
            echo $currentRecordInDict.'EPOLeafNode.LastUpdate'
            # If the data in the current date is newer than the saved date
            $dummy = $EPOSystemsData.remove($l_system.'EPOLeafNode.NodeName')
            $l_temp_string = convertto-json -InputObject $l_system
            $EPOSystemsData.Add($l_system.'EPOLeafNode.NodeName', $l_temp_string ) 

        }
        
    }



    "--- Start handling the data ---"
    # Prepare list of hosts to Tag
    $l_array_host = New-Object System.Collections.ArrayList($null)

    ForEach ($l_system in $AD_System_Obj_csv) {
        #$l_system.Name
        $computerSystemFoundInEPO = $EPOSystemsData[$l_system.Name]
        if ($computerSystemFoundInEPO -eq $null) {
            echo "Did not find: $($l_system.Name)"
        }
        #$computerSystemFoundInEPO

        #$computerSystem = $ePO_System_Obj_csv | where {$_.'EPOLeafNode.NodeName' -eq $l_system.Name}
        #echo $computerSystem
        
    }
<# 
    ForEach ($l_system_in_AD in $AD_System_Obj_csv) {

        $l_system_in_AD.Name
        $l_hostename = $l_system_in_AD.Name
        $l_found_in_ePO=$False    
       
        #$ePO_System_Obj_csv

        if ($ePO_System_Obj_csv.'EPOLeafNode.NodeName'.Equal($l_hostename))
        {"Fundet"}
        
       
        ForEach ($l_system_in_EPO in $ePO_System_Obj_csv) {
            # For each system in the ePO System list        
         
            $l_hostename = $l_system_in_EPO | Select-Object -ExpandProperty "EPOLeafNode.NodeName"
            
            # Skip is the l_LastUpdate (Last communication) is blank
            if ($l_system_in_AD.Name -eq ($l_hostename))
            {
                $l_found_in_ePO = $true
                $l_LastUpdate = $l_system_in_EPO | Select-Object -ExpandProperty "EPOLeafNode.LastUpdate"
                $l_System_AutoID = $l_system_in_EPO | Select-Object -ExpandProperty "EPOLeafNode.AutoID"
 
                if (-not ($l_LastUpdate -gt 0 )) {
                    "empty last update date" +$l_hostename 
                    $l_LastUpdate= 0}
                
                # Is the ePO system located in the AD Name List
                # Identiy which Last Communication time is the most current. There can be duplicated entries in ePO System Tree
                        
                # Convert $l_LastUpdate to Date format YYYYMMDDHHMM
                $l_LastUpdate_date_AD = [int64]$l_system_in_AD.LastLogonTimeStamp
                $l_Last_AD_date = [datetime]::ParseExact($l_system_in_AD.LastLogonTimeStamp, "yyyyMMddHHmm", $null)
                $l_LastUpdate_date_ePO = [datetime]$l_LastUpdate
                
                $l_timespan = NEW-TIMESPAN -Start $l_Last_AD_date -End $l_LastUpdate_date_ePO 
                
                #$l_Last_AD_date
                #$Time_temp
                #$time_convert
                #$time_convert = $time_convert.ToUniversalTime
                #'UTC'
                #$Time_temp.ToUniversalTime().ToString("yyyyMMddHHmm")
                $l_LastUpdate_date_ePO_UTC = [int64]$l_LastUpdate_date_ePO.ToUniversalTime().ToString("yyyyMMddHHmm")
                $l_date_diff = (($l_LastUpdate_date_AD - $l_LastUpdate_date_ePO_UTC ))
                if ($l_date_diff -gt 400) {
                    $l_unmanged_state = "True"
                    $l_unmanged_state_count++

                    'Found ' +$l_hostename   + '   '+  $l_LastUpdate_date_AD + '   '+ $l_LastUpdate_date_ePO_UTC + '   '+ $l_unmanged_state+ '    '+$l_date_diff
                    '       '+$l_Last_AD_date +' - '+ $l_LastUpdate_date_ePO 
                    $l_timespan

                    $l_array_host = $l_array_host + $l_system_in_AD
                }
                else {
                    $l_unmanged_state = "False"
                    $l_manged_state_count++
                }
                    
                #$l_date_AD=$l_date_AD+12
                #$l_date_AD
                #$l_LastUpdate_date_ePO 
                # The $l_LastUpdate_date_AD should not be larger than $l_LastUpdate_date_ePO_UTC by more than x hours
                # Every hour is 100 so if the AD date is 400 or more larger than ePO date then the system has been AD uthenticated but not communcaited to ePO
                #'Found ' +$l_hostename + '   '+  $l_LastUpdate_date_AD + '   '+ $l_LastUpdate_date_ePO_UTC + '   '+ $l_unmanged_state+ '    '+$l_date_diff
                
                        
            }
        
            #$l_hostename + '   '+ $l_LastUpdate
        }
        #>
        if (-not $l_found_in_ePO)
        {
            $l_array_host = $l_array_host + $l_system_in_AD

        }
    
    
    #Write-Output $ePO_System_Obj_csv | Format-Table 
    #Write-Output $AD_System_Obj_csv | Format-Table 

    #$l_array_host | export-csv -Path ($g_ePO_dupplicated_csv_filename) -NoTypeInformation -Delimiter ";"
    'Managed:   '+$l_manged_state_count
    'Unmaanged: '+$l_unmanged_state_count

}


################
# Main section #
################

$g_ISO_Date_with_time
#$time_string_to_convert = Get-Date -Format "o"
#g_Prepare_modules_needed 
#$time_string_to_convert = '2021-08-20T12:24:31+02:00'
#$time_string_to_convert ='2015-10-14T14:43:55-04:00'
#$time_convert = Get-Date -Date $time_string_to_convert -Format "yyyy-MM-dd HH:mm:ss"
#$time_string_to_convert 

# Convert working without timezone information
#$time_convert = Get-Date -Date $time_string_to_convert -Format "yyyyMMddHHmm"

# Convert string to datetime and include timezone information
#$Time_temp = [datetime]$time_string_to_convert 
#'UTC'
#$Time_temp.ToUniversalTime().ToString("yyyyMMddHHmm")



# Collect ePO systems information 
# Collect the AD information
# Remark if just working on the files allready collected

"Step 1 - Get System information from ePO " + $URL_ePO 
#g_Get_System_Tree_info_from_ePO
"   System information from ePO resuls are stored in :"+$g_working_dir


"Step 2 - Get System information from AD"
#g_Get_AD_Systems_from_AD


"Step 3 - Compare system communication dates form ePO and AD" 
Handle_files_and_compare_dates3


# Write time when finished
Get-Date -format "yyyyMMdd_HHmmss"




