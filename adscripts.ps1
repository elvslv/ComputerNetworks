function Get-ScriptDirectory
{
	$Invocation = (Get-Variable MyInvocation -Scope 1).Value
	Split-Path $Invocation.MyCommand.Path
}

$users = Join-Path (Get-ScriptDirectory) "users.ps1"
. $users

$computers = Join-Path (Get-ScriptDirectory) "computers.ps1"
. $computers

$events = Join-Path (Get-ScriptDirectory) "events.ps1"
. $events