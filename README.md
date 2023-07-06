# Invoke-Pre2kSpray

Modified DomainPasswordSpray version to enumerate machine accounts and perform a pre2k password spray.

### Example Usage 

```powershell
# Current domain
Invoke-Pre2kSpray -OutFile valid-creds.txt

# Specify domain, disable confirmation prompt
Invoke-Pre2kSpray -OutFile valid-creds.txt -Domain test.local -Force

# Filter out accounts with pwdlastset in the last 30 days, to speed things up. Those are probably normal machine accounts that rotate their passwords
Invoke-Pre2kSpray -OutFile valid-creds.txt -Filter
```

### References / Credits

* https://github.com/dafthack/DomainPasswordSpray
* https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/
* @garrfoster for pointing out to me that the authentication via NTLM was wrong, which lead to false negatives and for providing me with the correct kerberos authentication code :)
