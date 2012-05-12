$defaultRoot = "DC=dvfu,DC=ru"
Import-Module activedirectory
function Get-UniversalDateTime($dateString){
    $d = [datetime]$dateString
    $DateString = $d.ToString("u") -Replace "-|:|\s"
    $DateString = $DateString -Replace "Z", ".0Z"
    $DateString
}

function Get-FilteredComputers{
    param ($root = $defaultRoot,
           $ftParams = @('DistinguishedName', 'Enabled', 'Owner', 'OperatingSystem', 'OperatingSystemServicePack', 'SID'),
           $startDate = $null,
           $endDate = $null,
           $disabled = $null,
           $owner = $null
          )
    $filter = ""
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
	if ($filter -eq ""){
        $filter = "(objectClass=*)"
    }
    Get-ADComputer -LDAPFilter $filter -SearchBase $root -Properties $attributes | ? {
        ($owner -eq $null) -or ($_.nTSecurityDescriptor.Owner -eq $owner) 
    } | % {
        $_.('owner') = $_.nTSecurityDescriptor.Owner
        $_
    } | Select-Object -property $ftParams 
}

function Get-FilteredUsers {
    param ($root = $defaultRoot,
		   $ftParams = @('DistinguishedName', 'Enabled', 'Owner', 'SID'),
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
           $owner = $null
           )
    $filter = ""
    $attributes = @('nTSecurityDescriptor')
    if ($startDateFailedLogon -ne $null) { 
        $filter = "$filter(msDS-LastFailedInteractiveLogonTime>={0})" -f (Get-UniversalDateTime $startDateFailedLogon)
        $attributes = $attributes + 'msDS-LastFailedInteractiveLogonTime'
		$ftParams = $ftParams + 'failedLogon'
    }
    if ($endDateFailedLogon -ne $null) { 
        $filter = "$filter(msDS-LastFailedInteractiveLogonTime<={0})" -f (Get-UniversalDateTime $endDateFailedLogon)
        $attributes = $attributes + 'msDS-LastFailedInteractiveLogonTime'
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
        $filter = "$filter(msDS-LastSuccessfulInteractiveLogonTime>={0})" -f $startDateLogon 
        $attributes = $attributes + 'msDS-LastSuccessfulInteractiveLogonTime'
		$ftParams = $ftParams + 'logon'
    }
    if ($endDateLogon -ne $null) { 
        $filter = "$filter(msDS-LastSuccessfulInteractiveLogonTime<={0})" -f $endDateLogon
        $attributes = $attributes + 'msDS-LastSuccessfulInteractiveLogonTime'
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
    if ($filter -eq ""){
        $filter = "(objectClass=*)"
    }
    
    Get-ADUser -LDAPFilter $filter -SearchBase $root -Properties $attributes | ? {
        ($owner -eq $null) -or ($_.nTSecurityDescriptor.Owner -eq $owner) 
    } | % {
		if (($startDateFailedLogon -ne $null) -or ($endDateFailedLogon -ne $null)){
            $_.('failedLogon') = $_.('msDS-LastFailedInteractiveLogonTime')
        }
		if (($startDateLogon -ne $null) -or ($endDateLogon -ne $null)){
            $_.('logon') = $_.('msDS-LastSuccessfulInteractiveLogonTime')
        }
		if ($locked -ne $null){
            $_.('locked') = $locked
        }
        $_.('owner') = $_.nTSecurityDescriptor.Owner
        $_
    } | Select-Object -property $ftParams 
}

function Change-Computer {
    param ($root = $defaultRoot,
           $startDate = $null,
           $endDate = $null,
           $disabled = $null,
           $owner = $null,
		   $dict
          )
	Get-FilteredComputers -root $root -startDate $startDate -endDate $endDate -disabled $disabled -owner $owner| % {
		foreach($v in $dict){
            if ($v['field'] -eq $null){
                break;
            }
			$_.($v['field']) = $v['value']
		}
		Set-ADComputer -Identity $_.DistinguishedName
        $_
	}
}

function Change-User {
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
		   $dict
           )
	Get-FilteredUsers -root $root -startDateFailedLogon $startDateFailedLogon -endDateFailedLogon $endDateFailedLogon -startDateCreated $startDateCreated -endDateCreated $endDateCreated -startDateLogon $startDateLogon -endDateLogon $endDateLogon -startDateModified $startDateModified -endDateModified $sendDateModified -disabled $disabled -locked $locked -owner $owner | % {
		foreach($v in $dict){
            if ($v['field'] -eq $null){
                break;
            }
			$_.($v['field']) = $v['value']
		}
		Set-ADUser -Identity $_.DistinguishedName
        $_
	}
}

function Get-EventLogInfo{
    param(
        $computerName = $null,
        $userName = $null,
        $startDate = $null,
        $endDate = $null,
        $eventId = $null
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
    $Data | Add-Member NoteProperty Address ($null)
    $Data | Add-Member NoteProperty EventId ($null)
    $Data | Add-Member NoteProperty Message ($null)
    
    $events | %{

        $Data.Time = $_.TimeGenerated

        $message = $_.message.split("`n") | %{$_.trimstart()} | %{$_.trimend()}

        $Data.UserName = ($message | ?{$_ -like "Пользователь:*"} | %{$_ -replace "^.+:."} )
        $Data.Address = ($message | ?{$_ -like "Адрес сети источника:*"} | %{$_ -replace "^.+:."})
        $Data.EventId = $_.eventid
        $Data.Message = $message
        $Data

    }
}

clear

Change-User -dict @{}

#Get-FilteredUsers -startDateCreated "4/17/2012 8:52:28 AM"
    
#Get-EventLogInfo -eventId 4616 