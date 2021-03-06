$defaultRoot = "DC=dvfu,DC=ru"

#different event ids  for event-log, see http://www.windowsecurity.com/articles/event-ids-windows-server-2008-vista-revealed.html
Set-Variable EVENT_ACCOUNT_LOGGED_OFF -value 4634 
Set-Variable EVENT_SUCCESSFULLY_LOGON -value 4624 
Set-Variable EVENT_FAILED_LOGON -value 4625
Set-Variable EVENT_WORKSTATION_LOCKED -value 4800 
Set-Variable EVENT_WORKSTATION_UNLOCKED -value 4801
Set-Variable EVENT_SYSTEM_AUDIT_POLICY_CHANGED -value 4719  

function Get-UniversalDateTime ($dateString){
	$d = [datetime]$dateString
	$DateString = $d.ToString("u") -Replace "-|:|\s"
	$DateString = $DateString -Replace "Z", ".0Z"
	$DateString
}

function Call-FunctionWithParams ($funcName, $params){
	$expr = $funcName
	foreach($k in $params.keys){
		if ($k -eq "dict"){
			continue
		}
		$expr = "$expr -$k {0}" -f $params[$k]
	}
	return invoke-expression $expr
}

function Change-Dates([timespan]$timedelta, [datetime]$startDate, [datetime]$endDate){
	if (($startDate -eq $null) -and  ($endDate -eq $null)){
		$endDate = get-date
		$startDate = $endDate - $timedelta
	}
	elseif (($startDate -ne $null) -and (($endDate -eq $null))){
		$endDate = $startDate + $timedelta
	}
	elseif (($startDate -eq $null) -and (($endDate -ne $null))){
		$startDate = $endDate - $timedelta
	}
	return $startDate, $endDate
}
