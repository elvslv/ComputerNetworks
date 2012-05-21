$commons = Join-Path (Get-ScriptDirectory) "common.ps1"
. $commons

Import-Module activedirectory

<#
.SYNOPSIS
	.
.DESCRIPTION
	Выводит список компьютеров, удовлетворяющих фильтру, со значениями их параметров.
	timedelta --параметр в формате [-]{ d | [d.]hh:mm[:ss[.ff]] }
	d -- дни, hh-часы, mm -- минуты, ss -- секунды, ff -- доли секунды
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
.EXAMPLE 
	Get-FilteredComputers -sd "4/17/2012 8:52:28 AM" -td "2.05:00"
	Возвращает компьютеры, созданные в течение двух дней 5 часов после 4/17/2012 8:52:28 AM
.NOTES
	.
#>
function Get-FilteredComputers{
	param (
		[parameter(HelpMessage="Путь в AD, в котором необходимо производить поиск, например'DC=dvfu,DC=ru'")]
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
		[Parameter(HelpMessage="Разница между начальной (конечной) датой, если одна из них задана, или между текущей датой и начальной, если начальная и конечная даты не заданы, игнорируется, если одновременно заданы startDate и endDate")]
		[Alias("td")]
		[timespan]   
		$timedelta,
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
	$ftParams = @('DistinguishedName', 'Enabled', 'Owner', 'OperatingSystem', 'OperatingSystemServicePack', 'SID', 'description')
	$ftParams = $ftParams + $properties
	$attributes = @('operatingsystem', 'operatingsystemservicepack', 'nTSecurityDescriptor', 'description')
	if ($timedelta -ne $null){
		$startDate, $endDate = Change-Dates $timedelta $startDate $endDate
	}
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
		[hashtable]
		$dict
	)
	$entry = Get-ADComputer -Identity $obj.DistinguishedName
	if (($dict -eq $null) -or ($dict.count -eq 0)){
		return $entry
	}
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
	Изменяет параметры компьютеров удовлетворяющих фильтру (см. функцию Get-FilteredComputers) согласно хэшу dict.
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
		[Parameter(HelpMessage="Разница между начальной (конечной) датой, если одна из них задана, или между текущей датой и начальной, если начальная и конечная даты не заданы, игнорируется, если одновременно заданы startDate и endDate")]
		[Alias("td")]
		[timespan]   
		$timedelta,
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
		$ou,
		[Parameter(HelpMessage="Хэш, ключи которого имена параметров пользователя, а значения -- их новые значения")]
		[Alias("d")]
		[hashtable]
		$dict
	)
	Call-FunctionWithParams "Get-FilteredComputers",  $PSBoundParameters | % {
		Change-Computer -c $_ -dict $dict
	}
}