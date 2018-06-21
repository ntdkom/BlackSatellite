# Black Satellite

This PowerShell script allows you to hunt for the password reuse in your Active Directory installation.

## Concept

There should be no identical passwords in the your infrastructure, especially in the production environment.

If one (or many more) of your Sysdmins has a single password for his corp account (email, chat, workstation)
and his administrative account in production - you've got problems.

Since there's no easy way to obtain plain-text passwords for all of your users reliably, another approach can be used.

Password's hash can be used as a clear representation of a password string.

Why? Because 'The NT hash of the password is calculated by using an unsalted MD4 hash algorithm.'

Reference: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/hh994565(v=ws.11)

Hence, two identical passwords will have identical NT hash.

## How it works

The script uses the DSInternals PowerShell module to extract the authentication information from the ADDS.

One of the mandatory arguments is the name of the organizational unit to pull users from.
Only users with the administrative permissions (either members of: Builtin Administrators or Domain Administrators or Enterprise Administrators)
are checked.

## Example

It the following example script detects identical password for three different accounts: paul, paul-a, paul-ea

Pay attention that NTHash is only printend to the console if you use -Verbose switch.
The GUID value should be used to join the entries.

<img src="screenshots/example.png">
