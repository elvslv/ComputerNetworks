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

<#
.SYNOPSIS
	.
.DESCRIPTION
	Выводит список компьютеров, удовлетворяющих фильтру, со значениями их параметров.
.EXAMPLE
	Get-FilteredComputers -sd "4/17/2012 8:52:28 AM"
    Получает список всех компьютеров, созданных не ранее "4/17/2012 8:52:28 AM"
.EXAMPLE
    Get-FilteredComputers -sd "4/17/2012 8:52:28 AM" -ed "5/15/2012 8:52:28 AM"
    Получает список компьютеров, созданных в промежутке между "4/17/2012 8:52:28 AM" и "5/15/2012 8:52:28 AM"
.EXAMPLE
    Get-FilteredComputers -disabled false -owner "DVFU\Администраторы домена"
    Возвращает список отключенных компьютеров, владельцами которых является DVFU\Администраторы домена
.EXAMPLE 
    Get-FilteredComputers -cn "*V1059*"
    Компьютер, имя которого содержит "V1059"
.NOTES
	.
#>
function Get-FilteredComputers{
    param (
        [Parameter(HelpMessage="Путь в AD, в котором необходимо производить поиск, например'DC=dvfu,DC=ru'")]
        [ValidateNotNullOrEmpty()]
        [Alias("r")]
        [string]
        $root = $defaultRoot,
        [Parameter(HelpMessage="Список параметров для отображения")]
        [Alias("p")]
        [string[]]
        $properties = @(),       
        [Parameter(HelpMessage="Дата, после которой созданы искомые объекты")]
        [Alias("sd")]
        [datetime]   
        $startDate,
        [Parameter(HelpMessage="Дата, до которой созданы искомые объекты")]
        [Alias("ed")]
        [datetime]   
        $endDate,
        [Parameter(HelpMessage="Флаг, если он задан, ищем объекты, которые являются\не являются отключенными в зависимости от его значения")]
        [Alias("dis")]
        $disabled = $null,
        [Parameter(HelpMessage="Владелец объекта")]
        [Alias("o")]
        [string]   
        $owner,
        [Parameter(HelpMessage="Distinguished name объекта")]
        [Alias("dn")]
        [string]   
        $distinguishedName,
        [Parameter(HelpMessage="CN объекта")]
        [string]   
        $cn,
        [Parameter(HelpMessage="OU объекта")]
        [string]   
        $ou
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
    if ($distinguishedName -ne ""){
        $filter = "$filter(DistinguishedName=$distinguishedName)" 
    }
    if ($cn -ne ""){
        $filter = "$filter(CN=$cn)" 
    }
    if ($ou -ne ""){
        $root = "$root,OU=$ou"
    }
	if ($filter -eq ""){
        $filter = "(objectClass=*)"
    }
    $attributes = $attributes + $properties
    $allFields = (($cn -ne "") -and ($cn.IndexOf('*') -eq -1) -and ($cn.IndexOf('?') -eq -1)) -or (($distinguishedName -ne "") -and ($distinguishedName.IndexOf('*') -eq -1) -and ($distinguishedName.IndexOf('?') -eq -1))
    if ($allFields) {
        $attributes = "*"
    }
    Get-ADComputer -LDAPFilter $filter -SearchBase $root -Properties $attributes | ? {
        ($owner -eq "") -or ($_.nTSecurityDescriptor.Owner -eq $owner) 
    } | % {
        $_.('owner') = $_.nTSecurityDescriptor.Owner
        $_
        Write-Host $_
    } | % {
        if ($allFields) {
            $ftParams = @()
            $fields = $_ | gm -membertype property
            foreach($i in $fields){
                if ($_.($i.Name) -ne $null) {
                    $ftParams = $ftParams + $i.Name
                }
            }
        }
        $_ | Select-Object -property $ftParams
    }
}

<#
.SYNOPSIS
	.
.DESCRIPTION
	Выводит список пользователей, удовлетворяющих фильтру, со значениями их параметров.
.EXAMPLE
	Get-FilteredUsers -sdfl "4/17/2012 8:52:28 AM" -edfl "5/17/2012 8:52:28 AM"
    Возвращает список пользователей, которыми была осуществлена неудачная попытка входа в промежутке между "4/17/2012 8:52:28 AM" и "5/17/2012 8:52:28 AM"
.EXAMPLE
    Get-FilteredUsers -locked true -properties @("Name")
    Поиск всех заблокированных пользователей c выводом дополнительного поля "Name"
.EXAMPLE
    Get-FilteredUsers -o "DVFU\IDM" -cn "*Игнатюк*"| format-list
    Поиск всех пользователей по фамилии Игнатюк, созданных DVFU\IDM
.EXAMPLE
    Get-FilteredUsers -cn "*Пак*" -ou "Студенты"| format-list
    Поиск студента Пак
.EXAMPLE
    Get-FilteredUsers -l "test"
    Поиск пользователя по логину (возвращает все непустые поля)
.NOTES
	.
#>
function Get-FilteredUsers {
    param (
        [Parameter(HelpMessage="Путь в AD, в котором необходимо производить поиск, например 'DC=dvfu,DC=ru'")]
        [ValidateNotNullOrEmpty()]
        [Alias("r")]
        [string]
        $root = $defaultRoot,
        [Parameter(HelpMessage="Список параметров для отображения")]
        [Alias("p")]
        [string[]]
        $properties = @(),       
        [Parameter(HelpMessage="Флаг, если он задан, ищем объекты, которые являются\не являются отключенными в зависимости от его значения")]
        [Alias("dis")]
        $disabled = $null,
        [Parameter(HelpMessage="Владелец объекта")]
        [Alias("o")]
        [string]   
        $owner,
        [Parameter(HelpMessage="Distinguished name объекта")]
        [Alias("dn")]
        [string]   
        $distinguishedName,
        [Parameter(HelpMessage="CN объекта")]
        [string]   
        $cn,
        [Parameter(HelpMessage="Дата, после которой была неуспешная попытка входа")]
        [Alias("sdfl")]
        [datetime]   
        $startDateFailedLogon,
        [Parameter(HelpMessage="Дата, до которой была неуспешная попытка входа")]
        [Alias("edfl")]
        [datetime]   
        $endDateFailedLogon,
		[Parameter(HelpMessage="Дата, после которой созданы искомые объекты")]
        [Alias("sdc")]
        [datetime]   
        $startDateCreated,
		[Parameter(HelpMessage="Дата, до которой созданы искомые объекты")]
        [Alias("edc")]
        [datetime]  
        $endDateCreated,
		[Parameter(HelpMessage="Дата, после которой был осуществлен вход")]
        [Alias("sdl")]
        [datetime]   
        $startDateLogon,
		[Parameter(HelpMessage="Дата, до которой был осуществлен вход")]
        [Alias("edl")]
        [datetime]   
        $endDateLogonl,
		[Parameter(HelpMessage="Дата, после которой был изменен объект")]
        [Alias("sdm")]
        [datetime]  
        $startDateModified,
		[Parameter(HelpMessage="Дата, до которой был изменен объект")]
        [Alias("edm")]
        [datetime]  
        $endDateModified,
		[Parameter(HelpMessage="Флаг, если он задан, ищем объекты, которые являются\не являются заблокированными")]
        [Alias("lo")]
        $locked = $null,
		[Parameter(HelpMessage="Логин пользователя")]
        [Alias("l")]
        [string]  
        $login,
        [Parameter(HelpMessage="OU объекта")]
        [string]   
        $ou
    )
    $filter = ""
    $ftParams = @('DistinguishedName', 'Enabled', 'Owner', 'SID') 
    $ftParams = $ftParams  + $properties
    $attributes = @('nTSecurityDescriptor')
    if ($startDateFailedLogon -ne $null) { 
        $filter = "$filter(badPasswordTime>={0})" -f ($startDateFailedLogon.ToFileTime())
        $attributes = $attributes + 'badPasswordTime'
		$ftParams = $ftParams + 'badPasswordTime'
    }
    if ($endDateFailedLogon -ne $null) { 
        $filter = "$filter(badPasswordTime<={0})" -f ($endDateFailedLogon.ToFileTime())
        $attributes = $attributes + 'badPasswordTime'
		if ($startDateFailedLogon -eq $null){
			$ftParams = $ftParams + 'badPasswordTime'
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
        $filter = "$filter(lastLogonTimestamp>={0})" -f $($startDateLogon.ToFileTime())
        $attributes = $attributes + 'lastLogonTimestamp'
		$ftParams = $ftParams + 'lastLogonTimestamp'
    }
    if ($endDateLogon -ne $null) { 
        $filter = "$filter(lastLogonTimestamp<={0})" -f $($endDateLogon.ToFileTime())
        $attributes = $attributes + 'lastLogonTimestamp'
		if ($startDateLogon -eq $null){
			$ftParams = $ftParams + 'lastLogonTimestamp'
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
        $filter = "$filter(lockoutTime>=0)" 
        $attributes = $attributes + 'lockoutTime'
        $ftParams = $ftParams + 'locked'
    }
    if ($distinguishedName -ne "") {
        $filter = "$filter(DistinguishedName=$distinguishedName)" 
    }
    if ($login -ne "") {
        $filter = "$filter(sAMAccountName=$login)"
    }
    if ($cn -ne "") {
        $filter = "$filter(CN=$cn)" 
    }
    if ($ou -ne ""){
        $root = "OU=$ou,$root"
    }
    if ($filter -eq "") {
        $filter = "(objectClass=*)"
    }
    $attributes = $attributes + $properties
    $allFields = (($cn -ne "") -and ($cn.IndexOf('*') -eq -1) -and ($cn.IndexOf('?') -eq -1))`
        -or (($distinguishedName -ne "") -and ($distinguishedName.IndexOf('*') -eq -1) -and ($distinguishedName.IndexOf('?') -eq -1))`
        -or (($login -ne "") -and ($login.IndexOf('*') -eq -1) -and ($login.IndexOf('?') -eq -1))
    if ($allFields) {
        $attributes = "*"
    }
    Get-ADUser -LDAPFilter $filter -SearchBase $root -Properties $attributes | ? {
        ($owner -eq "") -or ($_.nTSecurityDescriptor.Owner -eq $owner) 
    } | % {
    	#if (($startDateFailedLogon -ne $null) -or ($endDateFailedLogon -ne $null)) {
        #        $a = [datetime]::FromFileTime($_.('badPasswordTime'))
        #        $_.('failedLogon') = $a
        #    }
    	#if (($startDateLogon -ne $null) -or ($endDateLogon -ne $null)) {
        #        $a = [datetime]::FromFileTime($_.('lastLogonTimestamp'))
        #        $_.('logon') = $a
        #    }
    	if ($locked -ne $null) {
                $_.('locked') = $locked
            }
        $_.('owner') = $_.nTSecurityDescriptor.Owner
        $_
    } | % {
        if ($allFields) {
            $ftParams = @()
            $fields = $_ | gm -membertype property
            foreach($i in $fields){
                if ($_.($i.Name) -ne $null) {
                    $ftParams = $ftParams + $i.Name
                }
            }
        }
        $_ | Select-Object -property $ftParams
    }
}

<#
.SYNOPSIS
	.
.DESCRIPTION
	Изменяет параметры одного компьютера согласно хэшу dict.
.EXAMPLE
	.
.NOTES
	.
#>
function Change-Computer{
	param (
		[ValidateNotNullOrEmpty()]
		[Alias("c")]
		$obj,
		[Parameter(HelpMessage="Хэш, ключи которого имена параметров пользователя, а значения -- их новые значения")]
		[Alias("d")]
		$dict
	)
    $entry = Get-ADComputer -Identity $obj.DistinguishedName
    foreach($k in $dict.keys){
		$entry.($k) = $dict[$k]
    }
    Set-AdComputer -instance $entry  
    $entry
}

<#
.SYNOPSIS
	.
.DESCRIPTION
	Изменяет параметры компьютеров удовлетворяющих фильтру согласно хэшу dict.
.EXAMPLE
	.
.NOTES
	.
#>
function Change-Computers {
    param (
        [Parameter(HelpMessage="Путь в AD, в котором необходимо производить поиск, например'DC=dvfu,DC=ru'")]
        [ValidateNotNullOrEmpty()]
        [Alias("r")]
        [string]
        $root = $defaultRoot,    
        [Parameter(HelpMessage="Дата, после которой созданы искомые объекты")]
        [Alias("sd")]
        [datetime]   
        $startDate,
        [Parameter(HelpMessage="Дата, до которой созданы искомые объекты")]
        [Alias("ed")]
        [datetime]   
        $endDate,
        [Parameter(HelpMessage="Флаг, если он задан, ищем объекты, которые являются\не являются отключенными в зависимости от его значения")]
        [Alias("dis")]
        $disabled = $null,
        [Parameter(HelpMessage="Владелец объекта")]
        [Alias("o")]
        [string]   
        $owner,
        [Parameter(HelpMessage="Distinguished name объекта")]
        [Alias("dn")]
        [string]   
        $distinguishedName,
        [Parameter(HelpMessage="CN объекта")]
        [string]   
        $cn,
		[Parameter(HelpMessage="Хэш, ключи которого имена параметров пользователя, а значения -- их новые значения")]
		$dict
	)
	Get-FilteredComputers -r $root -cn $cn -sd $startDate -ed $endDate -dis $disabled -o $owner -dn $distinguishedName| % {
		Change-Computer -obj $_ -dict $dict
	}
}

<#
.SYNOPSIS
	.
.DESCRIPTION
	Изменяет параметры одного пользователя согласно хэшу dict.
.EXAMPLE
	.
.NOTES
	.
#>
function Change-User{
    param (
		[ValidateNotNullOrEmpty()]
		[Alias("u")]
		$obj,
		[Parameter(HelpMessage="Хэш, ключи которого имена параметров пользователя, а значения -- их новые значения")]
		[Alias("d")]
		$dict
	)
    $entry = Get-ADUser -Identity $obj.DistinguishedName
    foreach($k in $dict.keys){
		$entry.($k) = $dict[$k]
    }
    Set-AdUser -instance $entry  
    $entry
}

<#
.SYNOPSIS
	.
.DESCRIPTION
	Изменяет параметры пользователей удовлетворяющих фильтру согласно хэшу dict.
.EXAMPLE
	.
.NOTES
	.
#>
function Change-Users {
    param (
        [Parameter(HelpMessage="Путь в AD, в котором необходимо производить поиск, например 'DC=dvfu,DC=ru'")]
        [ValidateNotNullOrEmpty()]
        [Alias("r")]
        [string]
        $root = $defaultRoot,      
        [Parameter(HelpMessage="Флаг, если он задан, ищем объекты, которые являются\не являются отключенными в зависимости от его значения")]
        [Alias("dis")]
        $disabled = $null,
        [Parameter(HelpMessage="Владелец объекта")]
        [Alias("o")]
        [string]   
        $owner,
        [Parameter(HelpMessage="Distinguished name объекта")]
        [Alias("dn")]
        [string]   
        $distinguishedName,
        [Parameter(HelpMessage="CN объекта")]
        [string]   
        $cn,
        [Parameter(HelpMessage="Дата, после которой была неуспешная попытка входа")]
        [Alias("sdfl")]
        [datetime]   
        $startDateFailedLogon = $null,
        [Parameter(HelpMessage="Дата, до которой была неуспешная попытка входа")]
        [Alias("edfl")]
        [datetime]   
        $endDateFailedLogon = $null,
		[Parameter(HelpMessage="Дата, после которой созданы искомые объекты")]
        [Alias("sdc")]
        [datetime]   
        $startDateCreated = $null,
		[Parameter(HelpMessage="Дата, до которой созданы искомые объекты")]
        [Alias("edc")]
        [datetime]  
        $endDateCreated = $null,
		[Parameter(HelpMessage="Дата, после которой был осуществлен вход")]
        [Alias("sdl")]
        [datetime]   
        $startDateLogon = $null,
		[Parameter(HelpMessage="Дата, до которой был осуществлен вход")]
        [Alias("edl")]
        [datetime]   
        $endDateLogon = $null,
		[Parameter(HelpMessage="Дата, после которой был изменен объект")]
        [Alias("sdm")]
        [datetime]  
        $startDateModified = $null,
		[Parameter(HelpMessage="Дата, до которой был изменен объект")]
        [Alias("edm")]
        [datetime]  
        $endDateModified = $null,
		[Parameter(HelpMessage="Флаг, если он задан, ищем объекты, которые являются\не являются заблокированными")]
        [Alias("lo")]
        $locked = $null,
		[Parameter(HelpMessage="Логин пользователя")]
        [Alias("l")]
        [string]  
        $login,
		[Parameter(HelpMessage="Хэш, ключи которого имена параметров пользователя, а значения -- их новые значения")]
		$dict
	)
	Get-FilteredUsers -r $root -l $login -cn $cn -dn $distinguishedName -sdfl $startDateFailedLogon -edfl $endDateFailedLogon -sdc $startDateCreated -edc $endDateCreated -sdl $startDateLogon -edl $endDateLogon -sdm $startDateModified -edm $sendDateModified -dis $disabled -lo $locked -o $owner | % {
		Change-User -obj $_ -dict $dict
	}
}

<#
.SYNOPSIS
	.
.DESCRIPTION
	Выводит сведения о событиях журнала Security.
.EXAMPLE
	.
.NOTES
	.
#>
function Get-EventLogInfo{
    param(
		[Parameter(HelpMessage="Имя компьютера из свойств события")]
		[Alias("pc")]
		[string]
		$computerName,
		[Parameter(HelpMessage="Имя пользователя из свойств события")]
		[Alias("u")]
		[string]
		$userName,
		[Alias("after")]
		[datetime]
		$startDate = $null,
		[Alias("before")]
		[datetime]
		$endDate = $null,
		[Parameter(HelpMessage="Event Id (см. http://www.windowsecurity.com/articles/event-ids-windows-server-2008-vista-revealed.html)")]
		[Alias("id")]
		[integer]
		$eventId = 0,
		[Parameter(HelpMessage="Имя рабочей станции из описания события")]
		[Alias("ws")]
		[string]
		$workstation
    )
    $str = "Get-EventLog security"
    if ($computerName -ne ""){
        $str = "$str -ComputerName $computerName"
    }
    if ($userName -ne ""){
        $str = "$str -UserName $userName"
    }
    if ($startDate -ne $null){
        $str = "$str -after {$startDate}"
    }
    if ($endDate -ne $null){
        $str = "$str -before {$endDate}"
    }
    $events = invoke-expression $str
    if ($eventId -ne 0){
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
        
    $events | %{

        $Data.Time = $_.TimeGenerated

        $message = $_.message.split("`n") | %{$_.trimstart()} | %{$_.trimend()}

        $Data.UserName = ($message | ? {[regex]::matches($_ , "(Имя учетной записи|Учетная запись входа):*")} | %{$_ -replace "^.+:."} )
        $Data.Address = ($message | ? {$_ -like "Адрес сети источника:*"} | %{$_ -replace "^.+:."})
        $Data.Workstation = ($message | ?{$_ -like "*станци?:*"} | %{$_ -replace "^.+:."})
        $Data.ErrorCode = ($message | ?{$_ -like "Код ошибки:*"} | %{$_ -replace "^.+:."})
        $Data.EventId = $_.eventid
        $Data
    } | ? { ($workstation -eq "") -or ($Data.Workstation -like $workstation)}
}

clear

Get-FilteredUsers -l "test"

#Get-FilteredUsers -cn "test" -properties @("Name")| format-list

#Change-Users -cn "test" -dict @{'info' = 'tratata1234'}

#Get-FilteredUsers -disabled false -owner "DVFU\Администраторы домена" | ? {
#    $_.DistinguishedName -eq 'CN=test,OU=TemporaryUsers,DC=dvfu,DC=ru'
#} | % {
#    Change-User -obj $_ -dict @{'info' = 'tratata11'}
#} 

#Get-FilteredUsers -startDateCreated "4/17/2012 8:52:28 AM"
    
#Get-EventLogInfo -eventid 4624 -workstation  "*WIN*"

#Get-FilteredUsers -cn "terent" | format-list