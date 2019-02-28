<#
To Do:
- Rewrite to "native" COM Objects instead of certreq fiddling.
- Check if there is a native Interface for the AKI Extension
#>

Function New-OcspCertificateRequest {

    [cmdletbinding()]
    param(

        [Parameter(Mandatory=$True)]
        [ValidateScript({$_ -match "CN="})]
        [String]
        $Subject,

        [Parameter(Mandatory=$False)]
        [ValidateScript({$Null -ne (certutil -csplist | find "$($_)")})]
        [String]
        $Ksp = "Microsoft Enhanced Cryptographic Provider v1.0",

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^[0-9a-fA-F]{40}$")]
        [String]
        $Aki,

        [Parameter(Mandatory=$False)]
        [ValidateSet(2048,3072,4096)]
        [Int]
        $KeyLength = 2048

    )

    process {

        # Check for Elevation - we will create a Machine Key
        If(-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            throw "User is not a local Administrator"
        }

        # To Do: Specify Output Folder
        $InfFileName = "$($env:TEMP)\$(Get-Random)_OCSPRequestConfig.inf"
        $ReqFileName = ".\request.req"

        # Just to be sure, removing any Spaces and converting to upper case
        $Aki = $Aki.ToUpper()
        $Aki = $Aki -replace '\s',''

        Write-Verbose "AKI: $Aki"

        # Automagically building a Request Information File to feed certreq.exe with later on

        $InfFile = ''
        $InfFile += "[Version]`r`n"
        $InfFile += "Signature=""`$Windows NT$""`r`n"
        $InfFile += "`r`n"
        $InfFile += "[NewRequest]`r`n"
        $InfFile += "Subject = ""$Subject""`r`n"
        $InfFile += "KeyLength = $($KeyLength)`r`n"
        $InfFile += "KeyUsage = 0x80 ; CERT_DIGITAL_SIGNATURE_KEY_USAGE`r`n"
        $InfFile += "ProviderName = ""$($Ksp)""`r`n"
        $InfFile += "RequestType = PKCS10`r`n"
        $InfFile += "MachineKeySet = True`r`n"
        $InfFile += "UseExistingKeySet = False`r`n"
        $InfFile += "`r`n"
        $InfFile += "; see https://msdn.microsoft.com/en-us/library/windows/desktop/aa379070(v=vs.85).aspx`r`n"
        $InfFile += "[Strings]`r`n"
        #$InfFile += "szOID_SUBJECT_ALT_NAME2 = ""2.5.29.17""`r`n"
        $InfFile += "szOID_AUTHORITY_KEY_IDENTIFIER2 = ""2.5.29.35""`r`n"
        $InfFile += "szOID_PKIX_OCSP_NOCHECK = ""1.3.6.1.5.5.7.48.1.5""`r`n"
        $InfFile += "szOID_PKIX_KP_OCSP_SIGNING = ""1.3.6.1.5.5.7.3.9""`r`n"
        $InfFile += "`r`n"
        $InfFile += "[Extensions]`r`n"
        #$InfFile += "%szOID_SUBJECT_ALT_NAME2% = ""{text}dns=$($HostName)""`r`n"

        If ($Aki) {
            $InfFile += "%szOID_AUTHORITY_KEY_IDENTIFIER2% = ""$(New-AkiExtension -Aki $Aki)""`r`n"
        }

        $InfFile += "%szOID_PKIX_OCSP_NOCHECK% = Empty`r`n"
        $InfFile += "`r`n"
        $InfFile += "[EnhancedKeyUsageExtension]`r`n"
        $InfFile += "OID = %szOID_PKIX_KP_OCSP_SIGNING%`r`n"
        $InfFile += "`r`n"
        $InfFile += "[ApplicationPolicyStatementExtension]`r`n"
        $InfFile += "Policies = OCSPSigning`r`n"
        $InfFile += "Critical = FALSE`r`n"
        $InfFile += "`r`n"
        $InfFile += "[OCSPSigning]`r`n"
        $InfFile += "OID = %szOID_PKIX_KP_OCSP_SIGNING%`r`n"

        # Write the Request Information File
        $InfFile | Out-File $InfFileName -Encoding ascii -Force

        If (Test-Path $ReqFileName) {
            Remove-Item -Path $ReqFileName -Force
        }

        Try {
            # Creating the Certificate Signing Requests
            # To Do: Should we check if certreq is present, and check for Outpur Errors?
            certreq -new $InfFileName $ReqFileName

            # We no longer need the Request Information File, so we delete it
            Remove-Item $InfFileName
        }
        Catch {
            #
        }
        Finally {

            If (Test-Path $ReqFileName) {
                Get-ChildItem $ReqFileName
            }

        }

    }

}