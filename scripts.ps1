$root = "LDAP://DC=mydomain,DC=local"
function Get-UniversalDateTime($dateString){
    $d = [datetime]$dateString
    $DateString = $d.ToString("u") -Replace "-|:|\s"
    $DateString = $DateString -Replace "Z", ".0Z"
    $DateString
}

function Create-FilteredItem{
    param($obj,
         $params)
    $hash = @{}
    foreach ($p in $params){
        if ($obj[$p] -eq $null){
            $hash.($p) = '-'
        } else {
            $hash.($p) = $obj[$p][0]
        }
    }
    $r1 = New-Object PSObject -Property $hash
    return $r1
}

function Get-FilteredItems{
    param ($rootName,
           $attributes,
           $filter = $null,
		   $returnEntry = $false
          )
	$root = [ADSI]$rootName
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
    $searcher.Filter = $filter;
	$attributes | % {
        $searcher.PropertiesToLoad.Add($_) | out-null
    }
    $searcher.FindAll() | % {
        if ($returnEntry){
			$_.GetDirectoryEntry()
		}
		else {
			Create-FilteredItem -obj $_.Properties -params $attributes
		}
    }
    $searcher.Dispose()
	$root.Dispose()
}

function Get-FilteredComputers{
    param ($root,
           $attributes,
           $startDate = $null,
           $endDate = $null,
           $disabled = $null,
		   $returnEntry = $false
          )
    $filter = "&(objectCategory=Computer)(objectClass=Computer)"
    if ($startDate -ne $null) { 
        $filter = "$filter(whencreated>={0})" -f (Get-UniversalDateTime $startDate)
    }
    if ($endDate -ne $null) { 
        $filter = "$filter(whencreated<={0})" -f (Get-UniversalDateTime $endDate)
    }
    if ($disabled -ne $null) {
        $prefix = "!"
        if ($disabled) { $prefix = "" }
        $filter = "$filter(${prefix}userAccountControl:1.2.840.113556.1.4.803:=2)"
    }
    Get-FilteredItems -rootName $root -filter "($filter)" -attributes $attributes -returnEntry $returnEntry
}

function Get-FilteredUsers {
    param ($root,
           $attributes,
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
		   $returnEntry = $false
           )
    $filter = "&(objectCategory=person)(objectClass=user)"
    if ($startDateFailedLogon -ne $null) { 
        $filter = "$filter(msDS-LastFailedInteractiveLogonTime>={0}" -f (Get-UniversalDateTime $startDateFailedLogon)
    }
    if ($endDateFailedLogon -ne $null) { 
        $filter = "$filter(msDS-LastFailedInteractiveLogonTime<={0})" -f (Get-UniversalDateTime $endDateFailedLogon)
    }
    if ($startDateCreated -ne $null) { 
        $filter = "$filter(whencreated>={0})" -f (Get-UniversalDateTime $startDateCreated)
    }
    if ($endDateCreated -ne $null) { 
        $filter = "$filter(whencreated<={0})" -f (Get-UniversalDateTime $endDateCreated)
    }
    if ($startDateLogon -ne $null) { 
        $filter = "$filter(msDS-LastSuccessfulInteractiveLogonTime>={0})" -f (Get-UniversalDateTime $startDateLogon) 
    }
    if ($endDateLogon -ne $null) { 
        $filter = "$filter(msDS-LastSuccessfulInteractiveLogonTime<={0})" -f (Get-UniversalDateTime $endDateLogon) 
    }
    if ($startDateModified -ne $null) { 
        $filter = "$filter(whenchanged>={0})" -f (Get-UniversalDateTime $startDateModified)
    }
    if ($endDateModified -ne $null) { 
        $filter = "$filter(whenchanged<={0})" -f (Get-UniversalDateTime $endDateModified)
    }
    if ($disabled -ne $null) {
        $prefix = ""
        if ($disabled -eq $false) { $prefix = "!" }
        $filter = "$filter(${prefix}userAccountControl:1.2.840.113556.1.4.803:=2)"
    }
    if ($locked -ne $null) { $filter = "$filter(lockouttime>0)" }
    Get-FilteredItems -rootName $root -filter "($filter)" -attributes $attributes -returnEntry $returnEntry 
}

function Change-Record {
    param( $record,
           $dict
          )
    foreach($v in $dict){
        $record.Put($v['field'], $v['value'])
    }
    $record.SetInfo()
    $record.displayname
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
    if ($eventId){
        $events = $events | ? {$_.eventid -eq $eventId }
    }
    $Data = New-Object System.Management.Automation.PSObject
    $Data | Add-Member NoteProperty Time ($null)
    $Data | Add-Member NoteProperty UserName ($null)
    $Data | Add-Member NoteProperty ComputerName ($null)
    $Data | Add-Member NoteProperty Address ($null)
    $Data | Add-Member NoteProperty EventId ($null)
    $Data | Add-Member NoteProperty Message ($null)
    
    $Events | %{

        $Data.time = $_.TimeGenerated

        $message = $_.message.split("`n") | %{$_.trimstart()} | %{$_.trimend()}

        $Data.UserName = ($message | ?{$_ -like "Пользователь:*"} | %{$_ -replace "^.+:."} )
        $Data.Address = ($message | ?{$_ -like "Адрес сети источника:*"} | %{$_ -replace "^.+:."})
        $Data.EventId = $_.eventid
        $Data.message = $message
        $Data

    }
}

clear

Get-FilteredComputers -root $root -attributes @('name',
    'operatingsystem',
    'operatingsystemservicepack',
    'whencreated',
    'useraccountcontrol') -startDate "4/15/2012 8:52:28 AM"
   

Get-FilteredUsers -root $root -attributes @('name',
    'whencreated',
    'whenchanged',
    'useraccountcontrol',
    'msDS-LastFailedInteractiveLogonTime',
    'msDS-LastSuccessfulInteractiveLogonTime',
    'lockouttime') -disabled false
    
Find-User -root $root -params @('name',
    'whencreated',
    'whenchanged',
    'useraccountcontrol',
    'msDS-LastFailedInteractiveLogonTime',
    'msDS-LastSuccessfulInteractiveLogonTime',
    'lockouttime') -returnEntry True | ? {
        $_.Properties['name'] -eq 'user3 u. u'
     } | % {
        Change-Record -record $_ -dict @(@{'field' = 'displayname'; 'value'= 'AAAAAAA'})
        $_.Owner
    } 
    
Get-EventLogInfo -eventId 4616 