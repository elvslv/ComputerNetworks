Import-Module activedirectory

$defaultRoot = "DC=dvfu,DC=ru"

#different event ids  for event-log, see http://www.windowsecurity.com/articles/event-ids-windows-server-2008-vista-revealed.html
Set-Variable EVENT_ACCOUNT_LOGGED_OFF -value 4634 
Set-Variable EVENT_SUCCESSFULLY_LOGON -value 4624 
Set-Variable EVENT_FAILED_LOGON -value 4625
Set-Variable EVENT_WORKSTATION_LOCKED -value 4800 
Set-Variable EVENT_WORKSTATION_UNLOCKED -value 4801
Set-Variable EVENT_SYSTEM_AUDIT_POLICY_CHANGED -value 4719  

function Get-UniversalDateTime($dateString){
    $d = [datetime]$dateString
    $DateString = $d.ToString("u") -Replace "-|:|\s"
    $DateString = $DateString -Replace "Z", ".0Z"
    $DateString
}

function Get-FilteredComputers{
    param ($root = $defaultRoot,
           $properties = @(),          
           $startDate = $null,
           $endDate = $null,
           $disabled = $null,
           $owner = $null,
           $distinguishedName = $null,
           $cn = $null
          )
    $filter = ""
    $ftParams = @('DistinguishedName', 'Enabled', 'Owner', 'OperatingSystem', 'OperatingSystemServicePack', 'SID')
    $ftParams = $ftParams + $properties
    $attributes = @('operatingsystem', 'operatingsystemservicepack', 'nTSecurityDescriptor')
    if ($startDate -ne $null) { 
        $filter = "$filter(whencreated>={0})" -f (Get-UniversalDateTime $startDate)
        $attributes = $attributes + 'whencreated'
        $ftParams = $ftParams + 'whencreated'
    }
    if ($endDate -ne $null) { 
        $filter = "$filter(whencreated<={0})" -f (Get-UniversalDateTime $endDate)
        $attributes = $attributes + 'whencreated'
        if ($startDate -eq $null) {
            $ftParams = $ftParams + 'whencreated'
        }
    }
    if ($disabled -ne $null) {
        $prefix = "!"
        if ($disabled) { $prefix = "" }
        $filter = "$filter(${prefix}userAccountControl:1.2.840.113556.1.4.803:=2)"
        $attributes = $attributes + 'userAccountControl'
    }
    if ($distinguishedName -ne $null){
        $filter = "$filter(DistinguishedName=$distinguishedName)" 
    }
    if ($cn -ne $null){
        $filter = "$filter(CN=$cn)" 
    }
	if ($filter -eq ""){
        $filter = "(objectClass=*)"
    }
    $attributes = $attributes + $properties
    Get-ADComputer -LDAPFilter $filter -SearchBase $root -Properties $attributes | ? {
        ($owner -eq $null) -or ($_.nTSecurityDescriptor.Owner -eq $owner) 
    } | % {
        $_.('owner') = $_.nTSecurityDescriptor.Owner
        $_
    } | Select-Object -property $ftParams 
}

function Get-FilteredUsers {
    param ($root = $defaultRoot,
		   $properties = @(),
           $startDateFailedLogon = $null,#
           $endDateFailedLogon = $null,#
           $startDateCreated = $null,#
           $endDateCreated = $null,#
           $startDateLogon = $null,#
           $endDateLogon = $null,#
           $startDateModified = $null,#
           $endDateModified = $null,#
           $disabled = $null,#
           $locked = $null,
           $owner = $null,
           $distinguishedName = $null,
           $cn = $null,
           $login = $null
           )
    $filter = ""
    $ftParams = @('DistinguishedName', 'Enabled', 'Owner', 'SID') 
    $ftParams = $ftParams  + $properties
    $attributes = @('nTSecurityDescriptor')
    if ($startDateFailedLogon -ne $null) { 
        $filter = "$filter(badPasswordTime>={0})" -f (Get-UniversalDateTime $startDateFailedLogon)
        $attributes = $attributes + 'badPasswordTime'
		$ftParams = $ftParams + 'failedLogon'
    }
    if ($endDateFailedLogon -ne $null) { 
        $filter = "$filter(badPasswordTime<={0})" -f (Get-UniversalDateTime $endDateFailedLogon)
        $attributes = $attributes + 'badPasswordTime'
		if ($startDateFailedLogon -eq $null){
			$ftParams = $ftParams + 'failedLogon'
		}
    }
    if ($startDateCreated -ne $null) { 
        $filter = "$filter(whencreated>={0})" -f (Get-UniversalDateTime $startDateCreated)
        $attributes = $attributes + 'whencreated'
		$ftParams = $ftParams + 'whencreated'
    }
    if ($endDateCreated -ne $null) { 
        $filter = "$filter(whencreated<={0})" -f (Get-UniversalDateTime $endDateCreated)
        $attributes = $attributes + 'whencreated'
		if ($startDateCreated -eq $null){
			$ftParams = $ftParams + 'whencreated'
		}
    }
    if ($startDateLogon -ne $null) { 
        $filter = "$filter(lastLogon>={0})" -f $startDateLogon 
        $attributes = $attributes + 'lastLogon'
		$ftParams = $ftParams + 'logon'
    }
    if ($endDateLogon -ne $null) { 
        $filter = "$filter(lastLogon<={0})" -f $endDateLogon
        $attributes = $attributes + 'lastLogon'
		if ($startDateLogon -eq $null){
			$ftParams = $ftParams + 'logon'
		}
    }
    if ($startDateModified -ne $null) { 
        $filter = "$filter(whenchanged>={0})" -f (Get-UniversalDateTime $startDateModified)
        $attributes = $attributes + 'whenchanged'
		$ftParams = $ftParams + 'whenchanged'
    }
    if ($endDateModified -ne $null) { 
        $filter = "$filter(whenchanged<={0})" -f (Get-UniversalDateTime $endDateModified)
        $attributes = $attributes + 'whenchanged'
		if ($startDateModified -eq $null){
			$ftParams = $ftParams + 'whenchanged'
		}
    }
    if ($disabled -ne $null) {
        $prefix = ""
        if ($disabled -eq $false) { $prefix = "!" }
        $filter = "$filter(${prefix}userAccountControl:1.2.840.113556.1.4.803:=2)"
        $attributes = $attributes + 'userAccountControl'
    }
    if ($locked -ne $null) { 
        $filter = "$filter(lockouttime>0)" 
        $attributes = $attributes + 'lockouttime'
        $ftParams = $ftParams + 'locked'
    }
    if ($distinguishedName -ne $null){
        $filter = "$filter(DistinguishedName=$distinguishedName)" 
    }
    if ($login -ne $null){
        $filter = "$filter(sAMAccountName=$login)"
    }
    if ($cn -ne $null){
        $filter = "$filter(CN=$cn)" 
    }
    if ($filter -eq ""){
        $filter = "(objectClass=*)"
    }
    $attributes = $attributes + $properties
    Get-ADUser -LDAPFilter $filter -SearchBase $root -Properties $attributes | ? {
        ($owner -eq $null) -or ($_.nTSecurityDescriptor.Owner -eq $owner) 
    } | % {
		if (($startDateFailedLogon -ne $null) -or ($endDateFailedLogon -ne $null)){
            $_.('failedLogon') = $_.('badPasswordTime')
        }
		if (($startDateLogon -ne $null) -or ($endDateLogon -ne $null)){
            $_.('logon') = $_.('lastLogon')
        }
		if ($locked -ne $null){
            $_.('locked') = $locked
        }
        $_.('owner') = $_.nTSecurityDescriptor.Owner
        $_
    } | Select-Object -property $ftParams
}

function Change-Computer{
    param ($obj = $null,
          $dict)
    if ($obj -eq $null){
        return
    }
    $entry = Get-ADComputer -Identity $obj.DistinguishedName
    foreach($v in $dict){
        if ($v['field'] -eq $null){
            break;
        }
			$entry.($v['field']) = $v['value']
		}
		Set-AdComputer -instance $entry  
    $entry
}

function Change-Computers {
    param ($root = $defaultRoot,
           $startDate = $null,
           $endDate = $null,
           $disabled = $null,
           $owner = $null,
           $distinguishedName = $null,
           $cn = $null,
		   $dict
          )
	Get-FilteredComputers -root $root -cn $cn -startDate $startDate -endDate $endDate -disabled $disabled -owner $owner -distinguishedName $distinguishedName| % {
		Change-Computer -obj $_ -dict $dict
	}
}

function Change-User{
    param ($obj = $null,
          $dict)
    if ($obj -eq $null){
        return
    }
    $entry = Get-ADUser -Identity $obj.DistinguishedName
    foreach($v in $dict){
        if ($v['field'] -eq $null){
            break;
        }
			$entry.($v['field']) = $v['value']
		}
		Set-AdUser -instance $entry  
    $entry
}

function Change-Users {
    param ($root = $defaultRoot,
           $startDateFailedLogon = $null,#
           $endDateFailedLogon = $null,#
           $startDateCreated = $null,#
           $endDateCreated = $null,#
           $startDateLogon = $null,#
           $endDateLogon = $null,#
           $startDateModified = $null,#
           $endDateModified = $null,#
           $disabled = $null,#
           $locked = $null,
           $owner = $null,
           $distinguishedName = $null,
           $cn = $null,
           $login = $null,
		   $dict
           )
	Get-FilteredUsers -root $root -login $login -cn $cn -distinguishedName $distinguishedName -startDateFailedLogon $startDateFailedLogon -endDateFailedLogon $endDateFailedLogon -startDateCreated $startDateCreated -endDateCreated $endDateCreated -startDateLogon $startDateLogon -endDateLogon $endDateLogon -startDateModified $startDateModified -endDateModified $sendDateModified -disabled $disabled -locked $locked -owner $owner | % {
		Change-User -obj $_ -dict $dict
	}
}

function Get-EventLogInfo{
    param(
        $computerName = $null,
        $userName = $null,
        $startDate = $null,
        $endDate = $null,
        $eventId = $null,
        $workstation = $null
    )
    $str = "Get-EventLog security"
    if ($computerName -ne $null){
        $str = "$str -ComputerName $computerName"
    }
    if ($userName -ne $null){
        $str = "$str -UserName $userName"
    }
    if ($startDate -ne $null){
        $str = "$str -after {0}" -f (get-date $startDate)
    }
    if ($endDate -ne $null){
        $str = "$str -before {0}" -f (get-date $endDate)
    }
    $events = invoke-expression $str
    if ($eventId -ne $null){
        $events = $events | ? {$_.eventid -eq $eventId }
    }
    $Data = New-Object System.Management.Automation.PSObject
    $Data | Add-Member NoteProperty Time ($null)
    $Data | Add-Member NoteProperty UserName ($null)
    $Data | Add-Member NoteProperty ComputerName ($null)
    $Data | Add-Member NoteProperty Workstation ($null)
    $Data | Add-Member NoteProperty Address ($null)
    $Data | Add-Member NoteProperty ErrorCode ($null)
    $Data | Add-Member NoteProperty EventId ($null)
    #$Data | Add-Member NoteProperty Message ($null)
        
    $events | %{

        $Data.Time = $_.TimeGenerated

        $message = $_.message.split("`n") | %{$_.trimstart()} | %{$_.trimend()}

        $Data.UserName = ($message | ? {[regex]::matches($_ , "(Имя учетной записи|Учетная запись входа):*")} | %{$_ -replace "^.+:."} )
        $Data.Address = ($message | ? {$_ -like "Адрес сети источника:*"} | %{$_ -replace "^.+:."})
        $Data.Workstation = ($message | ?{$_ -like "*станци?:*"} | %{$_ -replace "^.+:."})
        $Data.ErrorCode = ($message | ?{$_ -like "Код ошибки:*"} | %{$_ -replace "^.+:."})
        $Data.EventId = $_.eventid
        #$Data.Message = $_.message
        $Data
    } | ? { ($workstation -eq $null) -or ($Data.Workstation -like $workstation)}
}

clear

#Get-FilteredUsers -cn "test" -properties @("Name")| format-list

#Change-Users -cn "test" -dict @(@{'field' = 'info'; 'value' = 'tratata1234'})

#Get-FilteredUsers -disabled false -owner "DVFU\Администраторы домена" | ? {
#    $_.DistinguishedName -eq 'CN=test,OU=TemporaryUsers,DC=dvfu,DC=ru'
#} | % {
#    Change-User -obj $_ -dict @(@{'field' = 'info'; 'value' = 'tratata11'})
#} 

#Get-FilteredUsers -startDateCreated "4/17/2012 8:52:28 AM"
    
#Get-EventLogInfo -eventid 4624 -workstation  "*WIN*"

Get-FilteredUsers -cn "terent" | format-list