#You can run this script in powershell one of a few ways:
#. .\meraki-api.ps1; get-merakiOrganizations
#Or import-module meraki-api.ps1 then run the functions as normal: get-merakiOrganizations


$api_key = '' #Key your current API key or the script will FAIL in all instances

#You don't have to set the below values, but site to site VPN will fail, copy-merakiAdmin will fail. Possibly another.  

$masterendpoint = 'https://api.meraki.com/api/v1' #most calls point to this except in certain cases where it requires org URL
$masterOrg = "" #Set this value to the NAME of the MASTER organization. IE: You are the MSP, the MSP org name as indicated by get-merakiOrganizations
$masterId = "" #This is master org ID as indicated by get-MerakiOrganizations
$masterIp = "" #This is the master ORG IP (IE the one that you'd site to site VPN to) and your external address
$masterSubnet = '' #This is the master ORG SUBNET to direct Site to Site VPN's to - IE: your lab and not your private secure internal network (192.168.1.0/24)
$masterBanCopy = 'example@example.com', 'example2@example2.com' #Items in this list won't be copied in Copy-merakiadmins
#These values are set specifically to prevent client to client VPN connections which could result in legal action as a result of an inadvertent connection between them,


#This header is required. If you don't have it, nothing else will work. 
$header = @{
        
        "X-Cisco-Meraki-API-Key" = $api_key
        "Content-Type" = 'application/json'
        
    }




#If this function is changed, it will break other functions. 
function Get-MerakiNetworks { #Meant to be called internally from this module - Not separately from command line. 

$uri = $masterendpoint + "/organizations/" + $oid.id + "/networks"
$request = Invoke-RestMethod -Method GET -Uri $uri -Headers $header
return $request

}


#This Function below is a function that, when called, will read data from .\blockediprange.txt (1 line per entry) and block them
#In each L7 firewall rule on every Network on every company ie: 192.168.0.0/24 is a valid entry for blocked ip range
#It will also read from .\blockedCountries.txt - each entry will be a 2 letter abbreviation for the country. If you do not supply any values for these files
#And decide to run it - it MAY set all values to nothing. (UNDESIRED)
<#
Current values for blockediprange.txt file is: 
redacted: Examples below
14.14.14.0/16
14.14.14.0/24
14.14.14.14/32

Current values for blockedcountries.txt file:
Examples:
CN
IR
MD
MN
RU
TH


#>
function Block-l7-firewall {
#Read above for description


   
    $blockrule = ""
    $preblock = @()    
    $preblock2 = ""
    foreach ($line in get-content .\blockedipRange.txt) {
    
    $preblock += @{
    policy = "deny"
    type = "ipRange"
    value = "$line"

    }
    $preblock2 = $preblock
    if ($line) {
    
    }
    
     
     }
    

    $blockrule = [PSCustomObject]@{
    "rules" = @( $preblock2 )
    }
    $blockrule2 = $blockrule | convertto-json
    
   
    write-host "----------------These are the rules being written across the board--------------"
    write-host $blockrule2
    write-host "--------------------------------------------------------------------------------"
    
    $c1 = @()
    $countryBlockArray = @()
    $countryPreblock2 = $preblock2 #This is the rules list from above
    
    $c2 = get-content .\blockedCountries.txt
    foreach($country in $c2) {
    $c1 += "$country" 
    }
   
    $countryPreBlock2 += @{
    policy = "deny"
    type = "blockedCountries"
    value = @( $c1 )
    }
    
    $countryBlockArray += $countryPreblock2
    $countryBlockArrayRules = [PSCustomObject]@{
        "rules" = ( $countryBlockArray )
    }
    $countryBlockArrayRules2 = $countryBlockArrayRules | ConvertTo-Json -depth 5
    
    <#
    This is the END of country blocking section

    #>
    if (!$orgid) {
    $orgids = Get-MerakiOrganizations
    $a = 0
    Foreach ($oid in $orgids) {

#Every time a new org is processed - It's written to the window. This is unnecessary for this task and can be removed its for testing
    Write-host "$a $($oid.name)" -ForegroundColor darkgreen -BackgroundColor black
    

    $networks = Get-MerakiNetworks $oid
    Foreach ($network in $networks) {
    $ids = "https://api.meraki.com/api/v0" + "/networks/" + $network.id + "/security/intrusionSettings"
    $l7 = $masterendpoint + "/networks/" + $network.id + "/appliance/firewall/l7FirewallRules"
    try {
    $request2 = ""
    $request2 = Invoke-RestMethod -Method GET -Uri $ids -Headers $header
    } catch {
$errcode = ""
$errcode = $_.Exception.Response.StatusCode.value__
if ($errcode -eq "400") { write-host $network.name "- No IDS Present - Processing normal rules" }
elseif ($errcode -eq "404") { Write-Host "Error code: 404 - Page not found " }
else { if ($errcode) { write-host "Error code: " + $errcode } }

}


$urlReplace2 = $network.url -split "/"
    $urlReplace3 = "https://" + $urlReplace2[2] + "/api/v1"
#Adjusting the URL to fit our needs as restmethod doesn't follow 308 redirects
    $urlReplaceUrl = $urlReplace3 + '/networks/' + $network.id + '/appliance/firewall/l7FirewallRules'

if ($request2.mode -eq "detection") {
write-host "IDS Present - Need to process rules separately" -ForegroundColor Red
$request6 = ""
write-host $request6
write-host $countryBlockArrayRules2
$request6 = Invoke-RestMethod -Method PUT -Uri $urlReplaceUrl -body $countryBlockArrayRules2 -Headers $header
}
else { 
try {
$request6 = ""
$request6 = Invoke-RestMethod -Method PUT -Uri $urlReplaceUrl -body $blockrule2 -Headers $header
write-host "Writing rules to " $urlReplaceUrl
#start-sleep -Seconds 2 --no longer needed unless another api call is thrown
    } catch {
    $errcode2 = ""
    $errcode2 = $_.Exception.Response.StatusCode.value__
    if ($errcode2 -eq "400") { write-host "Error: Not an MX device - Cannot write firewall rules" -ForegroundColor Red}
    elseif ($errcode2 -eq "404") { write-host "Error: Not authorized to write rules to device (NO API ACCESS)" -ForegroundColor Red}
    else { write-host "Error: " $errcode2 }
   
    }

    } 

    
    }



}
}
}



function Copy-MerakiAdmin {
#This function is designed to copy Admins from one org to another so you don't have to type them out Manually. 


if (!$allorg) { $allorg = Get-MerakiOrganizations }

    $menu = @{}
    $testOrg = $allorg.name | sort-object 
    #write-host $testOrg
    
    for ($i=1;$i -le $testOrg.count;$i++) {
        write-host "$i. $($testOrg[$i-1])" 
        $menu.Add($i,($testOrg[$i-1]))
    } 

    [int]$ans = Read-Host 'Enter selection'
    #$selection = $menu.Item($ans) ; write-host "Selection: " $selection
    $selection = ($allorg |?{ $_.name -eq $menu.item($ans)}).name
    $selection2 = ($allorg |?{ $_.name -eq $menu.item($ans)}).id

    foreach ($orgid in $allorg) { 
    #write-host $orgid.name
    
    if ($orgid.name -ne $selection) { continue }
    else {
        $org = $orgid
        write-output "-----------------------------------------------------"
        write-output "Copying Admins from: $masterOrg TO: $selection"
        write-output "-----------------------------------------------------"
        $orgreplace2 = $org.url -split "/"
        $orgreplace3 = "https://" + $orgreplace2[2] + "/api/v1"
        #Adjusting the URL to fit our needs to add a new admin
        $apiurl = $orgreplace3 + '/organizations/' + $org.id + '/admins'
    
    
    
    }
    
    
    }
    $admins = Get-MerakiAllAdmins 1
    
    foreach ($admin in $admins) {
    
    if ($masterBanCopy -contains $admin.email) { continue }
    

$auth = "Cisco SecureX Sign-On"
$Parameters = @{
    name = $admin.name
    email = $admin.email
    orgAccess = $admin.orgaccess
    authenticationMethod = $auth
    }
    
    $parm2 = $Parameters | ConvertTo-Json -depth 5





try {
$request = Invoke-RestMethod -Method POST -Uri $apiurl -Body $parm2 -Headers $header
}
catch {
    $errcode = $_.Exception.Response.StatusCode.value__
    if ($errcode -eq "400") { write-host -ForegroundColor Red "Error code: 400 - User is either already an ADMIN by method: EMAIL on ANY company in Meraki Dashboard or user is added to a companies client VPN list via e-mail (Meraki bug - Hint: This also applies to disabled or changed VPN types) - You cannot be both EMAIL AND Cisco SecureX authenticated and you can't have a previous VPN e-mail attached to ANY company." }
    else { write-host -ForegroundColor Red "Error code: " + $errcode }
}

Start-Sleep -Milliseconds 750


}



}







function Add-AllMerakiAdmin {
#Usage: import-module meraki-api.ps1 then 'Add-AllMerakiAdmin "First Last" joe@blow.com full|read-only' Don't put single quotes.
#Or Without importing: . .\meraki-api.ps1; Add-AllMerakiAdmin "First Last" joe@blow.com full|read-only' Don't put single quotes.
#IE: Add-AllMerakiAdmin "Joe Blow" Joe.Blow@joeblow.com full
#This will add the above person to every company the API at the beginning controls with full access ORG level
#If you just see the company name changing to other companies : The add is successful. If you see another message - not success.
       param (
            [string][Parameter(Mandatory=$true)]$name,
            [string][Parameter(Mandatory=$true)]$email,
            [string][Parameter(Mandatory=$true)]$orgaccess
            )
  
            $auth = "Cisco SecureX Sign-On"

#Sets parameters to pass in the body of the request which is converted to JSON (required by Meraki) 
#Cisco SecureX Sign-on requires Azure/DUO/MFA when using Microsoft account to sign in
   
    $Parameters = @{
    name = $name
    email = $email
    orgAccess = $orgaccess
    authenticationMethod = "Cisco SecureX Sign-On" #You can change this to email if you want
                    }
    $parm2 = $Parameters | ConvertTo-Json -depth 5
    
    
    
#Grabs all Org's and throws into JSON inserted into $orgids
    if (!$orgid) {
    $orgids = Get-MerakiOrganizations
    $a = 0
    Foreach ($oid in $orgids) {
#Every time a new org is processed - It's written to the window. If all you see is the company name - It's working. 
#Currently even if an admin exists - It will still display company name. Unknown why. Doesn't matter. 
    Write-host "$a $($oid.name)"
    $oidreplace2 = $oid.url -split "/"
    $oidreplace3 = "https://" + $oidreplace2[2] + "/api/v1"
#Adjusting the URL to fit our needs to add a new admin
    $apiurl = $oidreplace3 + '/organizations/' + $oid.id + '/admins'
#This is whats sent to the internet. If you comment this out - nothing will be processed on the internet for this function.
try {  
        $request = Invoke-RestMethod -Method POST -Uri $apiurl -Body $parm2 -Headers $header
    } catch {
        $errcode = $_.Exception.Response.StatusCode.value__
        if ($errcode -eq "400") { write-host "Error code: 400 - User is either already an ADMIN by method: EMAIL on ANY company in Meraki Dashboard or user is added to a companies client VPN list via e-mail (Meraki bug - Hint: This also applies to disabled or changed VPN types) - You cannot be both EMAIL AND Cisco SecureX authenticated and you can't have a previous VPN e-mail attached to ANY company." }
        else { write-host "Error code: " + $errcode }
    }
write-output "-----------------------------------------------------"
#This is why you see the numbers increasing
    $a++
    }
   
    }
    
   
}



<#GET-MERAKIORGANIZATIONS
--------------------------------------------------------------------------------------------------------------------
#>

#Returns all organizations controlled by this API, OrgID and Org URL
function Get-MerakiOrganizations {

    $uri = 'https://dashboard.meraki.com/api/v1/organizations'
    $request = Invoke-RestMethod -Method GET -Uri $uri -Headers $header
    return $request

}

<#DEL-MERAKIALLADMINS
--------------------------------------------------------------------------------------------------------------------
#>

function Del-MerakiAllAdmins {
#Usage Del-MerakiAllAdmins email@address.com - Removes specified e-mail from every company as admin - Can check after with Get-MerakiAllAdmins
#If you just see company names scrolling - It's working. If user doesn't exist - You'll see that pop up for each company as it goes.

     param (
            [string][Parameter(Mandatory=$true)]$email
            )

    
if (!$allorg) { $allorg = Get-MerakiOrganizations }


foreach ($orgid in $allorg) { #Formerly $allorg.id
$apiurl = '/organizations/'
$apiurl2 = '/admins'
    $uri = $masterendpoint + $apiurl + $orgid.id + $apiurl2
    $request = Invoke-RestMethod -Method GET -Uri $uri -Headers $header
    $value = $orgid
    write-output $orgid.name
    
$a = 0    

$oidreplace2 = $orgid.url -split "/"
    $oidreplace3 = "https://" + $oidreplace2[2] + "/api/v1"
    $apiurl = $oidreplace3 + '/organizations/' + $orgid.id + '/admins'

  $test3 = $request | where { $_.email -eq $email } # "joe@blow.com" } #change this to parameter once done
$test4 = $test3.id
$uri2 = $apiurl + "/" + $test4

try{
$request2 = Invoke-RestMethod -Method DELETE -Uri $uri2 -Headers $header
} catch {
$errcode = $_.Exception.Response.StatusCode.value__
if ($errcode -eq "404") { write-host "User doesn't exist to delete" }

}
write-output "-----------------------------------------------------"
$a++
}


}

<#GET-MERAKIALLADMINS
--------------------------------------------------------------------------------------------------------------------
#>

function Get-MerakiAllAdmins {

#Usage = Get-MerakiAllAdmins to list every admin in every org
#Usage2 = Get-MerakiAllAdmins email@address.com to list very specific details about specified admin in each org.
#Usage3 = Get-MerakiAllAdmins 1 - This will return admins in the master org (msp) only - used in Copy-MerakiAdmins
 param (
            [string][Parameter(Mandatory=$false)]$email
            
       )
    
    

if (!$allorg) { $allorg = Get-MerakiOrganizations }
#write-output $allorg
  
  
foreach ($orgid in $allorg) { 
if ($email -eq "1" -and $orgid.id -ne $masterId) { continue }
else {
$apiurl = '/organizations/'
$apiurl2 = '/admins'
    $uri = $masterendpoint + $apiurl + $orgid.id + $apiurl2
    $request = Invoke-RestMethod -Method GET -Uri $uri -Headers $header
    $value = $orgid
    write-host "-----------------------------------------------------"
    write-host $orgid.name
    write-host "-----------------------------------------------------"

<#You con comment out both of the lines below and uncomment the third if you want full detailed user info (name/id/email/auth/
orgaccess/etc) It becomes quite messy over all the orgs though.  
Supplying an individual email as a parameter will return detailed info however
#> 
    if ($email -eq "1") { return $request }
    
    if ($email -eq "" -or $email -eq "1") { write-output $request.email }
    else { write-output $request $orgid | where { $_.email -eq $email }    }
    #write-output $request    
}

#$a++
}

}


function Get-Meraki-Vlans {
#****Not intended to be used as a separate function outside this Module****
#write-host $network.id + "network pushed to get-meraki-vlans" + $network.name

$url = "https://api.meraki.com/api/v0/networks/" + $network.id + "/vlans"
#write-host $url + "url outwritten"

try {
$vlanTemp = Invoke-RestMethod -Method Get -Uri $url -Headers $header
#write-host $vlanTemp + "VLAN restapi result"
} catch {
$errcode = $_.Exception.Response.StatusCode.value__
if ($errcode -eq "400") { write-host "VLAN's are NOT enabled for network: " + $network.id }
elseif ($errcode) {write-host "Other Error: " + $errcode }
}
if($vlanTemp) { return $vlanTemp.subnet }

}

function Add-MerakiSitetoSite {
<#
This function is designed to make Site-TO-Site VPN's more seamless and automated. 
This function RELIES on many functions inside this module
Run this, select a company, and the site to site VPN will automatically apply - preserving existing site 
to site's and replacing any existing occurrences of the selected Client to VPN to. 

The Secret is a 25 character randomly generated value with all symbols removed and replaced with a's
This is to prevent symbols from breaking the site to site if it's got a symbol at the beginning or end

This function does NOT check if Site to Site VPN HUB/Spoke is on or off. If it's set to OFF - you just need to turn 
it on. The rules will apply either way. 

Known issue : MX64 public IP registering as NULL if there's a MX64 added to inventory but has no IP
I've accounted for this issue by checking for null values in publicIp, but not confirmed its gone entirely

#>

$sourceName = $masterOrg
$sourceID = $masterId
$sourceIP = $masterIp
$sourceSubnet = @()
$sourceSubnet += $masterSubnet
add-type -AssemblyName System.Web #Below won't work unless you add this. 
$sourcePass = [System.Web.Security.Membership]::GeneratePassword(25,0) ; $sourcePass = $sourcePass -replace '[^a-zA-Z0-9]','a'
$sourceArray = @()
$destArray = @()
$destSubnet = @()
$vlanArray = @()
$vlans = @()
$newArray = @()
$newArray2 = @()
#Initialize all the vars/arrays ahead of time

if (!$allorg) { $allorg = Get-MerakiOrganizations }


$menu = @{}
$testOrg = $allorg.name | sort-object # this properly sorts. but broke script- change testorg variables back to make work again (FIXED)

for ($i=1;$i -le $testOrg.count;$i++) {
write-host "$i. $($testOrg[$i-1])" 
$menu.Add($i,($testOrg[$i-1]))} 

[int]$ans = Read-Host 'Enter selection'
$selection = ($allorg |?{ $_.name -eq $menu.item($ans)}).name
$selection2 = ($allorg |?{ $_.name -eq $menu.item($ans)}).id
#This pulls OrgID based on menu selection - corresponding to previously pulled Org list
foreach ($org in $allorg) { 
#if ($org.name -eq $menu.item($ans)) { write-host "Menu item found in array" $menu.item($ans) ; $selId = ($allorg |?{ $_.name -eq $menu.item($ans)}).id ; $oid = $org }
if ($org.name -eq $menu.item($ans)) { write-host "Selection: " $menu.item($ans) ; $selId = ($allorg |?{ $_.name -eq $menu.item($ans)}).id ; $oid = $org }

}

#Need networks for ORG to get VLAN/Subnets
if (!$networks) { $networks = Get-MerakiNetworks $oid }

$url = $masterendpoint + "/organizations/" + $selId + "/appliance/vpn/thirdPartyVPNPeers"
$url3 = $masterendpoint + "/organizations/" + $masterId + "/appliance/vpn/thirdPartyVPNPeers"
write-host "Client URL to post VPN rules to: " + $url

#This pulls the existing rules on target company
$request = Invoke-RestMethod -Method Get -Uri $url -Headers $header
$request3 = Invoke-RestMethod -Method Get -Uri $url3 -Headers $header
$uri2 = "https://api.meraki.com/api/v0/organizations/" + $selId + "/inventory" #could use /devicestatuses but would need to alter a bit

#This request gets the public IP of the selected company
$request2 = Invoke-RestMethod -Method Get -Uri $uri2 -Headers $header

foreach ($device in $request2) { if ($device.model -match "MX64" -and $device.publicIp -ne $null) { $destIP = $device.publicIp } }
#This will pull VLAN info

foreach ($network in $networks) {
$vlans2 = Get-Meraki-Vlans $network
foreach ($sublan in $vlans2) { $vlans += $sublan }
}
foreach ($vlan in $vlans) { $vlanArray += $vlan }
start-sleep -Seconds 1


$destIpChk = ($request.peers |?{ $_.publicIp -eq $sourceIP } | remove-item ) #Remove-item will automatically remove it if it exists
#$newArray = $request
#Altered all of this because it wasn't removing sourceIP from $request/$newArray
foreach ($item in $request.peers) { if ($item.publicIp -ne $sourceIP) { $newArray += $item } }
#foreach ($item in $newArray.peers) { $newArray.peers | ?{ $_.publicIp -eq $sourceIP } | remove-item } #dest
#$newArray.peers | ?{ $_.publicIp -eq $sourceIP } | remove-item  #dest
if ($menu.item($ans).length -le '28') { $destName = $menu.item($ans) ; $destName = $destName -replace '[^a-zA-Z0-9]',''  }
else {
$destName = $menu.item($ans).substring(0,28) ; $destName = $destName -replace '[^a-zA-Z0-9]','' #32 char limit on names!
}

if (!$destIpChk) { 




$destArray += @{
"name" = $sourceName
"publicIp" = $sourceIp
"privateSubnets" =  $sourceSubnet
"secret" = $sourcePass
"ikeVersion" = "1"
"networkTags" = @( "all" )
"ipsecPoliciesPreset" = "default"


}




$sourceArray += @{
"name" = $destName
"publicIp" = $destIp
"privateSubnets" = $vlanArray
"secret" = $sourcePass
"ikeVersion" = "1"
"networkTags" = @( "all" )
"ipsecPoliciesPreset" = "default"

}




}
#Build existing source array then add dest company
foreach ($vpnSource in $request3.peers) { if ($vpnSource.publicIp -ne $destIP) { $newArray2 += $vpnSource } }



$destArray2 = [PSCustomObject]@{
    "peers" = @( $newArray ) #removed .peers 11/8/20
    }
#foreach ($item2 in $request.peers) {if ($item2.publicIp -ne $sourceIP) { $destArray2.peers += $item2 } }
$destArray2.peers += $destArray

    $destArray3 = $destArray2 | convertto-json -Depth 5
#write-host $destArray2.peers + "FINAL COUNTDOWN"
$sourceArray2 = [PSCustomObject]@{
    "peers" = @( $sourceArray )
    }
$sourceArray2.peers += $newArray2
    $sourceArray3 = $sourceArray2 | convertto-json -Depth 5


$destWrite = Invoke-RestMethod -Method Put -Uri $url -Body $destArray3 -Headers $header

$destWrite2 = Invoke-RestMethod -Method Put -Uri $Url3 -Body $sourceArray3 -Headers $header

write-host "If no errors displayed - Writing to both networks just occurred"



}
