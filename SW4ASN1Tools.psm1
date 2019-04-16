[hashtable]$EkuNameToOidTable = @{

    # https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_hash_tables?view=powershell-6 
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa378132(v=vs.85).aspx

    CAExchange = "1.3.6.1.4.1.311.21.5";
    CertRequestAgent = "1.3.6.1.4.1.311.20.2.1";
    ClientAuth = "1.3.6.1.5.5.7.3.2";
    CodeSigning = "1.3.6.1.5.5.7.3.3";
    DocumentSigning = "1.3.6.1.4.1.311.10.3.12";
    EncryptingFileSystem = "1.3.6.1.4.1.311.10.3.4";
    FileRecovery = "1.3.6.1.4.1.311.10.3.4.1";
    IPSecEndSystem = "1.3.6.1.5.5.7.3.5";
    IPSecIKEIntermediate = "1.3.6.1.5.5.8.2.2";
    IPSecTunnelEndpoint = "1.3.6.1.5.5.7.3.6";
    IPSecUser = "1.3.6.1.5.5.7.3.7";
    KeyRecovery = "1.3.6.1.4.1.311.10.3.11";
    KDCAuth = "1.3.6.1.5.2.3.5";
    MicrosoftTrustListSigning = "1.3.6.1.4.1.311.10.3.1";
    QualifiedSubordination = "1.3.6.1.4.1.311.10.3.10";
    RootListSigner = "1.3.6.1.4.1.311.10.3.9";
    SecureEmail = "1.3.6.1.5.5.7.3.4";
    ServerAuth = "1.3.6.1.5.5.7.3.1";
    SmartCardLogon = "1.3.6.1.4.1.311.20.2.2";
    TimeStamping = "1.3.6.1.5.5.7.3.8";
    OCSPSigning = "1.3.6.1.5.5.7.3.9";
    RemoteDesktopAuth = "1.3.6.1.4.1.311.54.1.2";
    PrivateKeyArchival = "1.3.6.1.4.1.311.21.5";
    AMTProvisioning = "2.16.840.1.113741.1.2.3";
    
}

$ModuleRoot = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

# http://iextendable.com/2018/07/04/powershell-how-to-structure-a-module/

# The first gci block loads all of the functions in the Export and Private directories. 
# The -Recurse argument allows me to group functions into subdirectories as appropriate in larger modules.
Get-ChildItem -Path $ModuleRoot\Export,$ModuleRoot\Private -Filter *.ps1  -Recurse | ForEach-Object {

    . $_.FullName

}

# The second gci block exports only the functions in the Export directory. 
# Notice the use of the -Recurse argument again.
Get-ChildItem -Path $ModuleRoot\Export -Filter *.ps1 -Recurse | ForEach-Object {

    Export-ModuleMember $_.BaseName

}