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

#$g_ISO_Date = Get-Date -format "yyyyMMdd"
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
$g_ignore_list_file = "$g_Destination_folder"+"\Ignore_systems.csv" 

$g_List_A_csv_filename = "$g_Destination_folder"+"\List_A.csv" 
$g_List_B_csv_filename = "$g_Destination_folder"+"\List_B.csv" 
$g_List_C_csv_filename = "$g_Destination_folder"+"\List_C.csv" 
$g_List_D_csv_filename = "$g_Destination_folder"+"\List_D.csv" 
$g_List_G_csv_filename = "$g_Destination_folder"+"\List_G.csv" 

$g_ISO_Date_with_time = Get-Date -format "yyyyMMdd_HHmmss"
#
$Result =''
$cred=''
$URL_ePO = 'https://<epo>:port'
$username = 'user'  
$password = 'password'    

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
	Write-Output "Read domain $domain for All AD Computers with active login within $Daysactive days - starting from $time"

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
		Write-Output $l_system.name $l_human_date
		#$l_system.Login_Data=$l_human_date
		$l_system.lastLogonTimestamp=$l_human_date
		#$l_system.Login_Data='abc'
		#echo $l_human_date
		#echo $l_system
		$g_Clean_Computer_list += $l_system

	}
	Write-Output "Write result to: $g_ADComputer_file"

	#	$l_ADComputers | Export-Csv -Path $g_ADComputer_file -NoTypeInformation -Delimiter ";"
		$g_Clean_Computer_list | Export-Csv -Path $g_ADComputer_file -NoTypeInformation -Delimiter ";"
        #($Short | ConvertFrom-Json) | export-csv -Path ($g_working_dir+$g_ePO_result_csv_filename) -NoTypeInformation


}


function g_Get_System_Tree_info_from_ePO {
    $ePO_command = '/remote/core.executeQuery?' 
    
    # Pull all systems
    $options = 'target=EPOLeafNode&select=(select EPOLeafNode.AutoID EPOLeafNode.NodeName EPOLeafNode.LastUpdate EPOComputerProperties.DomainName EPOComputerProperties.OSType EPOComputerProperties.IPAddress EPOComputerProperties.UserName EPOLeafNode.Tags EPOBranchNode.NodeTextPath2 EPOLeafNode.AgentGUID EPOComputerProperties.UserProperty2 EPOComputerProperties.UserProperty3 )&:output=json'
    
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


function Handle_files_and_compare_dates3 {
    "Ready for handling the files - remove duplicated systems and keeping the one with the latest communication"     
    $l_file_epo_csv = $g_working_dir+$g_ePO_result_csv_filename
    $ePO_System_Obj_csv = Get-Content -Raw -Path $l_file_epo_csv | ConvertFrom-Csv
    "Reading : "+$l_file_epo_csv
    "Number of Systems in the ePO List : "+$ePO_System_Obj_csv.Count

    $AD_System_Obj_csv = Get-Content -Raw -Path $g_ADComputer_file| ConvertFrom-Csv -Delimiter ";"
    "Number of Systems in the AD List  : "+$AD_System_Obj_csv.Count
    if ($AD_System_Obj_csv.Count -lt 1) {
        'Missing AD information and exit'
         exit}
    
    
    $Ignore_list = New-Object System.Collections.Generic.Dictionary"[String,String]"
    if(Test-path $g_ignore_list_file){
        #$Ignore_list_csv = Get-Content -Raw -Path $g_ignore_list_file| ConvertFrom-Csv -Delimiter ";"
        $Ignore_list_csv = Import-Csv -Path $g_ignore_list_file -Header name
        ForEach ($l_ignore_system in $Ignore_list_csv) {
            $Ignore_list.Add($l_ignore_system.name, $l_ignore_system.name) 
            
        }
        "Ignore count : "+$Ignore_list.Count
    }
    
    $counter = 0

    #Create dictionary for EPO systems
    $EPOSystemsData = New-Object System.Collections.Generic.Dictionary"[String,String]"
    ForEach ($l_system in $ePO_System_Obj_csv) {
        #$EPOSystemsData.Add($l_system.'EPOLeafNode.NodeName', $l_system.'EPOLeafNode.NodeName' )
        $counter++
        if ($counter%200 -eq 0) 
        {
            Write-Progress -Activity "Build ePO Dictionary :" -PercentComplete (($counter / $ePO_System_Obj_csv.count) * 100)
            #"Processed : " + $counter
        }
        # System name from ePO list
        
        $l_ePO_System_name = $l_system.'EPOLeafNode.NodeName'

        $computerSystemFoundInIgnorelist = $Ignore_list[$l_ePO_System_name]
        # Skip to next if system is listed on ignore list
        if ($null -ne $computerSystemFoundInIgnorelist) 
        {
            continue
        }
        
        $computerSystemFoundInEPO = $EPOSystemsData[$l_ePO_System_name]
        if ($null -eq $computerSystemFoundInEPO) 
        {
            # Insert the System name as key and all the systems information is added as a JSON object 
            # in the dictonary
            $l_temp_string = convertto-json -InputObject $l_system
            $EPOSystemsData.Add($l_ePO_System_name, $l_temp_string ) 
        }
        else 
        {
            
            #echo "Double entry found $($computerSystemFoundInEPO)"
            $currentRecordInDict = convertfrom-json -InputObject $computerSystemFoundInEPO 
            
            # Show information if testing/verification is needed
            #echo "Double entry found"
            #echo $l_system.'EPOLeafNode.LastUpdate'
            #echo $currentRecordInDict.'EPOLeafNode.LastUpdate'
            
            # Convert to datetime format
            $l_DateInFile = [datetime]$l_system.'EPOLeafNode.LastUpdate'
            $l_DateInDict = [datetime]$currentRecordInDict.'EPOLeafNode.LastUpdate'
            
            # If the data in the current date is newer than the saved date
            if ($l_DateInFile -gt $l_DateInDict)
            {
                $EPOSystemsData.remove($l_ePO_System_name) | Out-Null
                $l_temp_string = convertto-json -InputObject $l_system
                $EPOSystemsData.Add($l_ePO_System_name, $l_temp_string ) 
            }

        }
    }
   
    "ePO List without duplicated       : "+$EPOSystemsData.Count

    Write-Output "--- Start comparing the AD and ePO data ---"
    # Step through each systems listed in the AD list
    $List_A_array = New-Object System.Collections.ArrayList($null)
    $List_B_array = New-Object System.Collections.ArrayList($null)
    $List_C_array = New-Object System.Collections.ArrayList($null)
    $List_D_array = New-Object System.Collections.ArrayList($null)
    $List_E = New-Object System.Collections.Generic.Dictionary"[String,String]"
    $List_F = New-Object System.Collections.Generic.Dictionary"[String,String]"
    $List_G_array = New-Object System.Collections.ArrayList($null)
    $List_H_array = New-Object System.Collections.ArrayList($null)
    # Add all ePO systems to List E - which will be reduced
    $List_E = $EPOSystemsData
    $counter = 0
    #"Processed : " + $counter
    ForEach ($l_system in $AD_System_Obj_csv) {
        $computerSystemFoundInIgnorelist = $Ignore_list[$l_system.Name]
        $counter++
        if ($counter%200 -eq 0) 
        {
            Write-Progress -Activity "AD Systems :" -PercentComplete (($counter / $AD_System_Obj_csv.count) * 100)
            
            #"Processed : " + $counter
        }
        # Skip to next if system is listed on ignore list
        if ($null -ne $computerSystemFoundInIgnorelist) 
        {
            continue
        }
        
        $computerSystemFoundInEPO = $EPOSystemsData[$l_system.Name]
        if ($null -eq $computerSystemFoundInEPO) {
            #echo "Did not find: $($l_system.Name)"
            # Add AD system to "List B" - System does not exist in ePO list 
            # Insert AD information into Dictonary
            $List_B_array += $l_system
        }
        else {
            # System found in ePO compare communication date
            #echo "Found: $($l_system.Name) in ePO list"
            #$EPOSystemsData[$l_system.Name]
            
            #Remove from ePO only list - known in both systems
            $List_E.remove($l_system.Name) | Out-Null

            #Get the dates;
            $currentRecordInEPO = convertfrom-json -InputObject $computerSystemFoundInEPO 
            #$currentRecordInEPO
            $l_DateInAD  = [DateTime]::ParseExact($l_system.LastLogonTimeStamp, "yyyyMMddHHmm", $null)
            $l_DateInEPO = $currentRecordInEPO.'EPOLeafNode.LastUpdate'
            if ($l_DateInEPO -ne "")
            {
                $l_DateInEPO = [DateTime]$l_DateInEPO
                #$l_DateInAD.DateTime
                #$l_DateInEPO.DateTime            

                # Calculate the timespan between the two dates
                #$l_timespan = NEW-TIMESPAN -Start $l_DateInAD  -End $l_DateInEPO  
                $l_timespan = NEW-TIMESPAN -Start $l_DateInEPO -End $l_DateInAD
                                
                if ($l_timespan.TotalSeconds -lt 24*60*60)
                {
                    #"Add to a list A - compliant"
                    $List_A_array += $currentRecordInEPO 
                }
                else 
                {
                    #"Add to a list D - Non compliant"
                    $List_D_array += $currentRecordInEPO 
                    
                }
            }
            else 
            {
                # Move system to the List C - system listed in ePO by never communicated
                $List_C_array += $l_system

            }
                       
        }
        #$computerSystemFoundInEPO

        #$computerSystem = $ePO_System_Obj_csv | where {$_.'EPOLeafNode.NodeName' -eq $l_system.Name}
        #echo $computerSystem
        
    }

    $l_DateNow = Get-Date
    $counter = 0

    ForEach ($l_system_key in $List_E.Keys)
    {
        #$l_system=$List_E[$l_system_key]
        $currentRecordInListE = convertfrom-json -InputObject $List_E[$l_system_key]
        #$currentRecordInListE
        $counter++
        if ($counter%200 -eq 0) 
        {
            Write-Progress -Activity "Sorting ePO Systems :" -PercentComplete (($counter / $List_E.count) * 100)
            #"Processed : " + $counter
        }
    
        $l_DateInEPO = $currentRecordInListE.'EPOLeafNode.LastUpdate'
        #$l_DateInEPO
        if ($l_DateInEPO -ne "")
            {
                $l_DateInEPO = [DateTime]$l_DateInEPO          

                # Calculate the timespan between the two dates
                #$l_timespan = NEW-TIMESPAN -Start $l_DateInAD  -End $l_DateInEPO  
                $l_timespan = NEW-TIMESPAN -Start $l_DateInEPO -End $l_DateNow
                                
                if ($l_timespan.TotalSeconds -gt 24*60*60)
                {
                    #"Add to a list G"
                    $List_G_array += $currentRecordInListE 
                    
                    #"Remove from list E"
                    #$dummy = $List_E_temp.remove($currentRecordInListE.'EPOLeafNode.NodeName')
                    #$dummy = $List_E_temp.remove($l_system_key)
                }
                else 
                {
                    #"On to F or stay on E - depending on Domain information"
                    
                    
                }
            }
        else 
        {
            # No ePO date
            #"Add to a list H"
            $List_H_array += $currentRecordInListE 
        }
    }

    # Clean Up list E
    ForEach ($l_system in $List_G_array) 
    {
        $List_E.remove($l_system.'EPOLeafNode.NodeName') | Out-Null
    }
    ForEach ($l_system in $List_H_array) 
    {
        $List_E.remove($l_system.'EPOLeafNode.NodeName') | Out-Null
    }


    # Write List A to CSV file
    "List A : "+$List_A_array.Count+" located in file : "+$g_List_A_csv_filename
    $List_A_array | export-csv -Path ($g_List_A_csv_filename) -NoTypeInformation -Delimiter ";"
    # Write List B to CSV file
    "List B : "+$List_B_array.Count+" located in file : "+$g_List_B_csv_filename
    $List_B_array | export-csv -Path ($g_List_B_csv_filename) -NoTypeInformation -Delimiter ";"
    # Write List C to CSV file
    "List C : "+$List_C_array.Count+" located in file : "+$g_List_C_csv_filename
    $List_C_array | export-csv -Path ($g_List_C_csv_filename) -NoTypeInformation -Delimiter ";"
    # Write List D to CSV file
    "List D : "+$List_D_array.Count+" located in file : "+$g_List_D_csv_filename
    $List_D_array | export-csv -Path ($g_List_D_csv_filename) -NoTypeInformation -Delimiter ";"
    "List E : "+$List_E.Count 
    $List_G_array | export-csv -Path ($g_List_G_csv_filename) -NoTypeInformation -Delimiter ";"
    "List G : "+$List_G_array.Count 
    "Unmanaged systems on ePO : "+$List_H_array.Count 

}


################
# Main section #
################

$g_ISO_Date_with_time

# Collect ePO systems information 
# Collect the AD information
# The ePO and AD functions has been remarked whne data has been exracted it is not need to pull the information 
# again and again when you are testing the processing and results of the data extracted

"Step 1 - Get System information from ePO " + $URL_ePO 
#g_Get_System_Tree_info_from_ePO
"   System information from ePO resuls are stored in :"+$g_working_dir


"Step 2 - Get System information from AD"
#g_Get_AD_Systems_from_AD


"Step 3 - Compare system communication dates form ePO and AD" 
Handle_files_and_compare_dates3


# Write time when finished
Get-Date -format "yyyyMMdd_HHmmss"




