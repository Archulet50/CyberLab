rule Credential_Dumping
{
    strings:
        $s1 = "Mimikatz" ascii
        $s2 = "CreateRemoteThread" ascii
        $s3 = "VirtualAllocEx" ascii
        $s4 = "cmd.exe" ascii
        $s5 = "powershell.exe" ascii
        $s6 = "lsass.exe" ascii

    condition:
        any of them
}
rule Credential_Dumping
{
    strings:
        $s1 = "Mimikatz" ascii
        $s2 = "CreateRemoteThread" ascii
        $s3 = "VirtualAllocEx" ascii
        $s4 = "cmd.exe" ascii
        $s5 = "powershell.exe" ascii
        $s6 = "lsass.exe" ascii

    condition:
        any of them
}