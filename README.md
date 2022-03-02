# Compliance_Find_unmanaged_AD_Systems
Compare onlines systems in AD with managed systems in ePO and report which AD systems are not managed in ePO.
This is a method to identify unmanaged endpoints.

List A	Systems are located in both ePO and AD - Compliant systems	Systems where AD login time and ePO communication time are within acceptable criteria
		
List B	Systems are only listed in AD	Systems not managed by ePO 
		        - missing Agent 
		        - managed by different ePO
		        - excepted to be managed by this ePO
		        - using different Endpoint Protection solution
		
		Get agent installed or Systems can be added to Ignore list if they should be ignored from the compliance check
		        
List C	Systems are listed in AD and ePO but never communicated to ePO	Systems not managed by ePO 
		        - Can be created by a synchronization with AD or Hypervisor done by ePO Server Task
		        
		        - missing Agent 
		        - managed by different ePO
		        - excepted to be managed by this ePO
		        - using different Endpoint Protection solution
		
		Get agent installed or Systems can be added to Ignore list if they should be ignored from the compliance check
		        
List D	Systems are located in both ePO and AD but not compliant on communication to ePO	Systems connected to AD recently but has not communicated to ePO not within within defined timespan - 1 day.
		
		This can be a broken Agent
		
		Inspect the Agent on the endpoint
		
List E	Systems are only listed in ePO and connected in the last 24 hours - with Domain name	Systems included in the Domain but:
		        - The systems has not logged in to AD in the last 24 hours (vacation, leave etc)
		        - Possible issue if the system has communicated to ePO in the last 24 hours but not authenticated to AD in the last 24 hours 
		        
List F	Systems are only listed in ePO and connected in the last 24 hours - without the Domain name	Systems not included in domain
		        - Standalone workstation
		        - Connected to different domain
		
		
		        
List G	Systems are only listed in ePO and not connected in the last 24 hours	Systems not communicating:
		        - Retired systems which has been decommissioned and do not exist anymore
		
		Critical - if system still exist on network but not communicating to ePO:
		        - Standalone systems where agent are not communicating anymore
		These systems can be hard to catch.
		
		To be added - Options to identify unmanaged non-AD systems
		        


Example of output - Processing more than 26.000 systems
```
20220302_005030
--- Start comparing the AD and ePO data ---
List A : 26016 located in file : C:\scripts\AD_ePO_find_unmanaged_systems\List_A.csv
List B : 386 located in file : C:\scripts\AD_ePO_find_unmanaged_systems\List_B.csv
List C : 2522 located in file : C:\scripts\AD_ePO_find_unmanaged_systems\List_C.csv
List D : 367 located in file : C:\scripts\AD_ePO_find_unmanaged_systems\List_D.csv
List E : 0
List G : 4268
Unmanaged systems on ePO : 16641
20220302_005210
```