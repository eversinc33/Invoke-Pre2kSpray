# Invoke-Pre2kSpray

Modified DomainPasswordSpray version to enumerate machine accounts and perform a pre2k password spray.

### Usage 

```powershell
Invoke-Pre2kSpray -OutFile valid-creds.txt -Domain test.local -Force
```

### References / Credits

* https://github.com/dafthack/DomainPasswordSpray
* https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/
* @garrfoster for pointing out to me that the authentication via NTLM was wrong, which lead to false negatives and for providing me with the correct kerberos authentication code :)
