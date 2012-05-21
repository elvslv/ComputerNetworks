$commons = Join-Path (Get-ScriptDirectory) "common.ps1"
. $commons

Import-Module activedirectory

<#
.SYNOPSIS
	.
.DESCRIPTION
	Выводит список пользователей, удовлетворяющих фильтру, со значениями их параметров.
    timedelta* --параметры в формате [-]{ d | [d.]hh:mm[:ss[.ff]] }
    d -- дни, hh-часы, mm -- минуты, ss -- секунды, ff -- доли секунды
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
		[Parameter(HelpMessage="Разница между начальной (конечной) датой неуспешного входа, если одна из них задана, или между текущей датой и начальной, если начальная и конечная даты не заданы, игнорируется, если одновременно заданы startDate и endDate")]
        [Alias("tdfl")]
        [timespan]   
        $timedeltaFailedLogon,
		[Parameter(HelpMessage="Дата, после которой созданы искомые объекты")]
        [Alias("sdc")]
        [datetime]   
        $startDateCreated,
		[Parameter(HelpMessage="Дата, до которой созданы искомые объекты")]
        [Alias("edc")]
        [datetime]  
        $endDateCreated,
		[Parameter(HelpMessage="Разница между начальной (конечной) датой создания")]
        [Alias("tdс")]
        [timespan]   
        $timedeltaCreated,
		[Parameter(HelpMessage="Дата, после которой был осуществлен вход")]
        [Alias("sdl")]
        [datetime]   
        $startDateLogon,
		[Parameter(HelpMessage="Дата, до которой был осуществлен вход")]
        [Alias("edl")]
        [datetime]   
        $endDateLogon,
		[Parameter(HelpMessage="Разница между начальной (конечной) датой успешного входа")]
        [Alias("tdl")]
        [timespan]   
        $timedeltaLogon,
		[Parameter(HelpMessage="Дата, после которой был изменен объект")]
        [Alias("sdm")]
        [datetime]  
        $startDateModified,
		[Parameter(HelpMessage="Дата, до которой был изменен объект")]
        [Alias("edm")]
        [datetime]  
        $endDateModified,
		[Parameter(HelpMessage="Разница между начальной (конечной) датой успешного изменения объекта")]
        [Alias("tdm")]
        [timespan]   
        $timedeltaModified,
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

    if ($timedeltaFailedLogon -ne $null){
	   $startDateFailedLogon, $endDateFailedLogon = Change-Dates $timedeltaFailedLogon $startDateFailedLogon $endDateFailedLogon
    }
    if ($startDateFailedLogon -ne $null) { 
        $filter = "$filter(badPasswordTime>={0})" -f ($startDateFailedLogon.ToFileTime())
        $attributes = $attributes + 'badPasswordTime'
		$ftParams = $ftParams + 'failedLogon'
    }
    if ($endDateFailedLogon -ne $null) { 
        $filter = "$filter(badPasswordTime<={0})" -f ($endDateFailedLogon.ToFileTime())
        $attributes = $attributes + 'badPasswordTime'
		if ($startDateFailedLogon -eq $null){
			$ftParams = $ftParams + 'failedLogon'
		}
    }
    if ($timedeltaCreated -ne $null){
	   $startDateCreated, $endDateCreated = Change-Dates $timedeltaCreated $startDateCreated $endDateCreated
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
    
	if ($timedeltaLogon -ne $null){
	   $startDateLogon, $endDateLogon = Change-Dates $timedeltaLogon $startDateLogon $endDateLogon
    }
    if ($startDateLogon -ne $null) { 
        $filter = "$filter(lastLogonTimestamp>={0})" -f $($startDateLogon.ToFileTime())
        $attributes = $attributes + 'lastLogonTimestamp'
		$ftParams = $ftParams + 'logon'
    }
    if ($endDateLogon -ne $null) { 
        $filter = "$filter(lastLogonTimestamp<={0})" -f $($endDateLogon.ToFileTime())
        $attributes = $attributes + 'lastLogonTimestamp'
		if ($startDateLogon -eq $null){
			$ftParams = $ftParams + 'logon'
		}
    }
    
	if ($timedeltaModified -ne $null){	
	   $startDateModified, $endDateLogon = Change-Dates $timedeltaModified $startDateModified $endDateModified
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
	$ftParams = $ftParams + 'login'
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
    	if (($startDateFailedLogon -ne $null) -or ($endDateFailedLogon -ne $null)) {
                $a = [datetime]::FromFileTime($_.('badPasswordTime'))
                $_.('failedLogon') = $a.ToString()
            }
    	if (($startDateLogon -ne $null) -or ($endDateLogon -ne $null)) {
                $a = [datetime]::FromFileTime($_.('lastLogonTimestamp'))
                $_.('logon') = $a.ToString()
            }
    	if ($locked -ne $null) {
                $_.('locked') = $locked.ToString()
            }
	if ($login -ne $null) {
		$_.('login') = $_.('sAMAccountName')
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
        [hashtable]
		$dict
	)
    $entry = Get-ADUser -Identity $obj.DistinguishedName
    if (($dict -eq $null) -or ($dict.count -eq 0)){
        return $entry
    }
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
	Change-Users -cn "test" -dict @{'info' = 'tratata12345'}
    Изменяет поле info у пользователя с именем test
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
        $startDateFailedLogon,
        [Parameter(HelpMessage="Дата, до которой была неуспешная попытка входа")]
        [Alias("edfl")]
        [datetime]   
        $endDateFailedLogon,
		[Parameter(HelpMessage="Разница между начальной (конечной) датой неуспешного входа, если одна из них задана, или между текущей датой и начальной, если начальная и конечная даты не заданы, игнорируется, если одновременно заданы startDate и endDate")]
        [Alias("tdfl")]
        [timespan]   
        $timedeltaFailedLogon,
		[Parameter(HelpMessage="Дата, после которой созданы искомые объекты")]
        [Alias("sdc")]
        [datetime]   
        $startDateCreated,
		[Parameter(HelpMessage="Дата, до которой созданы искомые объекты")]
        [Alias("edc")]
        [datetime]  
        $endDateCreated,
		[Parameter(HelpMessage="Разница между начальной (конечной) датой создания")]
        [Alias("tdс")]
        [timespan]   
        $timedeltaCreated,
		[Parameter(HelpMessage="Дата, после которой был осуществлен вход")]
        [Alias("sdl")]
        [datetime]   
        $startDateLogon,
		[Parameter(HelpMessage="Дата, до которой был осуществлен вход")]
        [Alias("edl")]
        [datetime]   
        $endDateLogon,
		[Parameter(HelpMessage="Разница между начальной (конечной) датой успешного входа")]
        [Alias("tdl")]
        [timespan]   
        $timedeltaLogon,
		[Parameter(HelpMessage="Дата, после которой был изменен объект")]
        [Alias("sdm")]
        [datetime]  
        $startDateModified,
		[Parameter(HelpMessage="Дата, до которой был изменен объект")]
        [Alias("edm")]
        [datetime]  
        $endDateModified,
		[Parameter(HelpMessage="Разница между начальной (конечной) датой успешного изменения объекта")]
        [Alias("tdm")]
        [timespan]   
        $timedeltaModified,
		[Parameter(HelpMessage="Флаг, если он задан, ищем объекты, которые являются\не являются заблокированными")]
        [Alias("lo")]
        $locked = $null,
		[Parameter(HelpMessage="Логин пользователя")]
        [Alias("l")]
        [string]  
        $login,
        [Parameter(HelpMessage="OU объекта")]
        [string]   
        $ou,
		[Parameter(HelpMessage="Хэш, ключи которого имена параметров пользователя, а значения -- их новые значения")]
        [Alias("d")]
        [hashtable]
		$dict
	)
    Call-FunctionWithParams "Get-FilteredUsers" $PSBoundParameters | % {
		Change-User -u $_ -dict $dict
	}
}

