clear
$root = [ADSI]"LDAP://DC=mydomain,DC=local"
function Create-PSObject{
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

function Find-Computer{
    param ($root,
           $params, 
           $startDate = $null,
           $endDate = $null,
           $disabled = $null,
           $returnEntry = $false
           )
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
    $searcher.Filter = "(&(objectCategory=Computer)(objectClass=Computer))"
    $params | % {
        $searcher.PropertiesToLoad.Add($_) | out-null
    }
    $searcher.FindAll() | ? {
        ($startDate -eq $null) -or 
        ($_.Properties['whencreated'][0] -ge [System.DateTime]$startDate) 
    } | ? {
        ($endDate -eq $null) -or 
        ($_.Properties['whencreated'][0] -le [System.DateTime]$endDate)
    } | ? {
        ($disabled -eq $null) -or 
        (($_.Properties['useraccountcontrol'][0] -band 2) -and $disabled)
    } | % {
        if ($returnEntry){
            $_.GetDirectoryEntry()
        }
        else {
            $r1 = Create-PSObject -obj $_.Properties -params $params
            $r1
        }
    }
    $searcher.Dispose()
}

function Find-User{
    param ($root,
           $params, 
           $startDateFailedLogon = $null,
           $endDateFailedLogon = $null,
           $startDateCreated = $null,
           $endDateCreated = $null,
           $startDateLogon = $null,
           $endDateLogon = $null,
           $startDateModified = $null,
           $endDateModified = $null,
           $disabled = $null,
           $locked = $null,
           $returnEntry = $false
           )
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
    $params | % {
        $searcher.PropertiesToLoad.Add($_) | out-null
    }
    $searcher.FindAll() | ? {
        ($startDateCreated -eq $null) -or 
        ($_.Properties['whencreated'][0] -ge [System.DateTime]$startDateCreated) 
    } | ? {
        ($endDateCreated -eq $null) -or 
        ($_.Properties['whencreated'][0] -le [System.DateTime]$endDateCreated)
    } | ? {
        ($startDateModified -eq $null) -or 
        ($_.Properties['whenchanged'][0] -ge [System.DateTime]$startDateModified) 
    } | ? {
        ($endDateModified -eq $null) -or 
        ($_.Properties['whenchanged'][0] -le [System.DateTime]$endDateModified)
    } | ? {
        ($startDateFailedLogon -eq $null) -or 
        ($_.Properties['msDS-LastFailedInteractiveLogonTime'][0] -ge [System.DateTime]$startDateFailedLogon) 
    } | ? {
        ($endDateFailedLogon -eq $null) -or 
        ($_.Properties['msDS-LastFailedInteractiveLogonTime'][0] -le [System.DateTime]$endDateFailedLogon)
    } | ? {
        ($startDateLogon -eq $null) -or 
        ($_.Properties['msDS-LastSuccessfulInteractiveLogonTime'][0] -ge [System.DateTime]$startDateLogon) 
    } | ? {
        ($endDateLogon -eq $null) -or 
        ($_.Properties['msDS-LastSuccessfulInteractiveLogonTime'][0] -le [System.DateTime]$endDateLogon)
    } | ? {
        ($disabled -eq $null) -or 
        (($_.Properties['useraccountcontrol'][0] -band 2) -and $disabled)
    } | ? {
        ($locked -eq $null) -or 
        ($_.Properties['lockouttime'][0] -gt 0)
    } | % {
        if ($returnEntry){
            $_.GetDirectoryEntry()
        }
        else {
            $r1 = Create-PSObject -obj $_.Properties -params $params
            $r1
        }
    }
    $searcher.Dispose()
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

Find-Computer -root $root -params @('name', 
    'operatingsystem', 
    'operatingsystemservicepack', 
    'whencreated',
    'useraccountcontrol') -disabled true -startDate "4/11/2012 4:50:46 AM" -endDate "4/14/2012 1:53:08 PM"

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
    } 

$root.Dispose()
