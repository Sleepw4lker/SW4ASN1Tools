# Kudos to:
# https://blog.css-security.com/blog/creating-a-self-signed-ssl-certificate-using-powershell
# https://blogs.technet.microsoft.com/vishalagarwal/2009/08/21/generating-a-certificate-self-signed-using-powershell-and-certenroll-interfaces/
# https://gist.github.com/carnal0wnage/42f4d1a0c46fe9ebe8d5
# http://stackoverflow.com/questions/35864912/ix509extension-xcn-encoding
# https://social.technet.microsoft.com/Forums/en-US/f568edfa-7f93-46a4-aab9-a06151592dd9/converting-ascii-to-asn1-der?forum=winserverpowershell
# https://gallery.technet.microsoft.com/scriptcenter/Self-signed-certificate-5920a7c6

Function New-CraftedCertificate {

    [cmdletbinding()]
    param (

        # To Do: Combine them to Parameter Sets
        # http://wragg.io/create-dynamic-powershell-functions-with-parameter-sets/

        [Parameter(Mandatory=$False)]
        [Switch]
        $CA = $False,

        [Parameter(Mandatory=$False)]
        [ValidateScript({$EkuNameToOidTable.PSBase.Keys -contains $_})]
        [String[]]
        $Eku,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $CommonName = "",

        # Should distinguish between DnsName, UPN and the like
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $DnsName,

        # Should distinguish between DnsName, UPN and the like
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Upn,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^[0-9a-fA-F]{40}$")]
        [String]
        $Aki,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()] # anyone has a http and ldap regex?
        [String[]]
        $Cdp,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()] # anyone has a http and ldap regex?
        [String[]]
        $Aia,

        <#
        # Not implemented yet
        [Parameter(Mandatory=$False)]
        [ValidatePattern("^http\://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(/\S*)?$")]
        [String[]]
        $Ocsp,
        #>

        [Parameter(Mandatory=$False)]
        [ValidateScript({$Null -ne (certutil -csplist | find "$($_)")})] # Should be converted to PoSH only, but works for now
        [String]
        $Ksp = "Microsoft Enhanced RSA and AES Cryptographic Provider",

        [Parameter(Mandatory=$False)]
        [ValidateScript({$_.hasPrivateKey})]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $SigningCert,

        [Parameter(Mandatory=$False)]
        [ValidateSet(2048,3072,4096)]
        [Int]
        $KeyLength = 2048,

        [Parameter(Mandatory=$False)]
        [ValidateSet("Minutes","Hours","Days","Weeks","Months","Years")]
        [String]
        $ValidityPeriod = "Years",

        [Parameter(Mandatory=$False)]
        [ValidateRange(1,1000)]
        [Int]
        $ValidityPeriodUnits = 1,

        [Parameter(Mandatory=$False)]
        [ValidateRange(0,1440)] # One Day should be more than enough 
        [Int]
        $ClockSkew = 10,

        [Parameter(Mandatory=$False)]
        [ValidateSet("MD4","MD5","SHA1","SHA256","SHA384","SHA512")]
        [String]
        $SignatureHashAlgorithm = "SHA256",

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^[0-9a-fA-F]{1,100}$")] # Why 100? RFC?
        [String]
        $SerialNumber,

        [Parameter(Mandatory=$False)]
        [ValidateSet("PrintableString","UTF-8")]
        [String]
        $Encoding = "PrintableString",
        
        # Still broken
        [Parameter(Mandatory=$False)]
        [ValidateSet("Computer","User")]
        [String]
        $Scope = "User",

        [Parameter(Mandatory=$False)]
        [ValidateRange(-1,16)] # Should be sufficient...? RFC?
        [Int]
        $PathLength = -1, # -1 means none

        # The Csr Parameter dumps the Certificate Request before it is issued, which allows you 
        # to submit the Request to a Certification Authority
        [Parameter(Mandatory=$False)]
        [Switch]
        $Csr

    )

    process {

        # Instantly die if we have Computer Store as Target but do not run the Function with Elevation
        If ($Scope -eq "Computer") {

            # Check for Elevation - we will create a Machine Key
            If(-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                throw "User is not a local Administrator"
            }

        }

        New-Variable -Name UserContext -Value 0x1 -Option Constant
        New-Variable -Name MachineContext -Value 0x2 -Option Constant

        # https://docs.microsoft.com/en-us/windows/desktop/api/certenroll/ne-certenroll-x500nameflags
        # https://docs.microsoft.com/en-us/dotnet/api/microsoft.hpc.scheduler.store.x500nameflags?view=hpc-sdk-5.1.6115
        New-Variable -Name XCN_CERT_NAME_STR_NONE -Value 0 -Option Constant
        New-Variable -Name XCN_CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG -Value 0x80000 -Option Constant
        New-Variable -Name XCN_CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG -Value 0x100000 -Option Constant

        # https://blog.css-security.com/blog/creating-a-self-signed-ssl-certificate-using-powershell
        #New-Variable -Name XCN_CERT_ALT_NAME_UNKNOWN -Value 0 -Option Constant
        #New-Variable -Name XCN_CERT_ALT_NAME_OTHER_NAME -Value 1 -Option Constant
        #New-Variable -Name XCN_CERT_ALT_NAME_RFC822_NAME -Value 2 -Option Constant
        New-Variable -Name XCN_CERT_ALT_NAME_DNS_NAME -Value 3 -Option Constant
        #New-Variable -Name XCN_CERT_ALT_NAME_DIRECTORY_NAME -Value 5 -Option Constant
        #New-Variable -Name XCN_CERT_ALT_NAME_URL -Value 7 -Option Constant
        #New-Variable -Name XCN_CERT_ALT_NAME_IP_ADDRESS -Value 8 -Option Constant
        #New-Variable -Name XCN_CERT_ALT_NAME_REGISTERED_ID -Value 9 -Option Constant
        #New-Variable -Name XCN_CERT_ALT_NAME_GUID -Value 10 -Option Constant
        New-Variable -Name XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME -Value 11 -Option Constant

        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379367(v=vs.85).aspx
        New-Variable -Name XCN_OID_CRL_DIST_POINTS -Value '2.5.29.31' -Option Constant
        New-Variable -Name XCN_OID_AUTHORITY_INFO_ACCESS -Value '1.3.6.1.5.5.7.1.1' -Option Constant

        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa374936(v=vs.85).aspx
        New-Variable -Name XCN_CRYPT_STRING_BASE64 -Value 0x1 -Option Constant

        # Here's how you move the Certificate to a Smart Card later on: 
        # https://blogs.technet.microsoft.com/pki/2007/11/13/manually-importing-keys-into-a-smart-card/
        # certutil –csp "Microsoft Base Smart Card Crypto Provider" –importpfx "<Filename>.pfx"

        # Creating a new Private Key
        $TargetCertificatePrivateKey = New-Object -ComObject 'X509Enrollment.CX509PrivateKey'
        $TargetCertificatePrivateKey.ProviderName = $Ksp

        # 2 = CA certificate
        # 1 = all others
        $TargetCertificatePrivateKey.KeySpec = [int]($CA.IsPresent) + 1

        # 1 = Machine Context
        # 0 = User Context
        $TargetCertificatePrivateKey.MachineContext = [int]($Scope -eq "Computer")

        # We allow the private Key to be exported
        $TargetCertificatePrivateKey.ExportPolicy = [int]$True

        # Specifying the Key Length of the Private Key
        $TargetCertificatePrivateKey.Length = $KeyLength

        # Creating the Key (Pair)
        $TargetCertificatePrivateKey.Create()

        # Begin Assembling the Certificate Signing Request
        # https://docs.microsoft.com/en-us/windows/desktop/seccertenroll/certificate-request-functions
        If ($Csr.IsPresent) {
            # Represents a PKCS #10 certificate request. A PKCS #10 request can be sent directly to a CA, or it can be wrapped by a PKCS #7 or CMC request.
            $TargetCertificate = New-Object -ComObject 'X509Enrollment.CX509CertificateRequestPkcs10'
        }
        Else {
            # Enables you to create a certificate directly without applying to a certification authority (CA).
            $TargetCertificate = New-Object -ComObject 'X509Enrollment.CX509CertificateRequestCertificate'
        }

        $TargetCertificate.InitializeFromPrivateKey($UserContext, $TargetCertificatePrivateKey, "")

        # Determine if we shall encode Subject and Issuer in PrintableString (Default for AD CS, 
        # non-default for CX509CertificateRequestCertificate) or UTF-8
        If ($Encoding -eq "PrintableString") {
            $SubjectEncodingFlag = $XCN_CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG
        }
        ElseIf ($Encoding -eq "UTF-8") {
            $SubjectEncodingFlag = $XCN_CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG
        }

        # Set Certificate Subject Name

        $SubjectDistinguishedName = New-Object -ComObject 'X509Enrollment.CX500DistinguishedName'

        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379394(v=vs.85).aspx
        # $XCN_CERT_NAME_STR_NONE
        $SubjectDistinguishedName.Encode(
            "CN=$($CommonName)",
            $SubjectEncodingFlag
        )

        $TargetCertificate.Subject = $SubjectDistinguishedName

        If (-not $Csr.IsPresent) {

            # Set Signing Certificate and Issuer

            If ($SigningCert) {

                # Validating if our Signing Certificate is really a CA Certificate
                If (-not ($SigningCert.Extensions.CertificateAuthority)) {
                    Write-Warning "Signing Certificate seems not to be a CA certificate." 
                }

                # First Argument: MachineContext (0/1)
                # https://msdn.microsoft.com/en-us/library/windows/desktop/aa376832(v=vs.85).aspx
                # Alternative Method: $SigningCert.Initialize($SigningCert.PSParentPath, 0, 1, $([Convert]::ToBase64String($signer.RawData)))
                $SignerCertificateObject =  New-Object -ComObject 'X509Enrollment.CSignerCertificate'
                $SignerCertificateObject.Initialize(
                    [int]($SigningCert.PSParentPath -match "LocalMachine"), 
                    0, 
                    4, 
                    $SigningCert.Thumbprint
                )
                $TargetCertificate.SignerCertificate = $SignerCertificateObject

                # If we have a Signing Certificate, we copy its Subject to the Target Certificates Issuer
                $IssuerDistinguishedName = New-Object -ComObject 'X509Enrollment.CX500DistinguishedName'

                # We must have the CN encoded as printableString instead of UTF-8, otherwise CRL verification will fail
                # During certificate chain validation (from the end entity to a trusted root) the KeyId is used to create 
                # the certificate chain and it works independently of the subject and issuer codification (PrintableString or UTF8)
                # During revocation status validation, a binary comparison is made between the certificate issuer and the CRL issuer,
                # so both fields must use the same codification in order to match (PrintableString or UTF8)
                # https://social.technet.microsoft.com/Forums/windowsserver/en-US/0459983f-4f19-48ee-b099-dfd484483176/active-directory-certificate-services-cannot-verify-certificate-chain-bad-cert-issuer-base-crl?forum=winserversecurity
                # https://msdn.microsoft.com/en-us/library/windows/desktop/bb540814(v=vs.85).aspx
                # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379394(v=vs.85).aspx

                $IssuerDistinguishedName.Encode(
                    $SigningCert.Subject,
                    $SubjectEncodingFlag
                )

                $TargetCertificate.Issuer = $IssuerDistinguishedName

            }
            Else {

                # If no Signing Certificate is given, the Certificate is Self-Signed,
                # Thus it is its own Issuer
                $TargetCertificate.Issuer = $SubjectDistinguishedName

            }

            # Set Certificate Validity Period

            # Validity Periods are always written into the Cert as Universal Time
            $Now = (Get-Date).ToUniversalTime()

            Switch ($ValidityPeriod) {

                "Minutes"   { $NotAfter = $Now.AddMinutes($ValidityPeriodUnits) }
                "Hours"     { $NotAfter = $Now.AddHours($ValidityPeriodUnits) }
                "Days"      { $NotAfter = $Now.AddDays($ValidityPeriodUnits) }
                "Weeks"     { $NotAfter = $Now.AddWeeks($ValidityPeriodUnits) }
                "Months"    { $NotAfter = $Now.AddMonths($ValidityPeriodUnits) }
                "Years"     { $NotAfter = $Now.AddYears($ValidityPeriodUnits) }

            }

            # Backup $ClockSkew in Minutes (Default: 10) to avoid timing issues
            $TargetCertificate.NotBefore = $Now.AddMinutes($ClockSkew * -1)
            $TargetCertificate.NotAfter = $NotAfter.AddMinutes($ClockSkew) 

            # Set Serial Number of the Certificate if specified as Argument, otherwise use a random SN
            If ($SerialNumber) {

                $TargetCertificate.SerialNumber.InvokeSet(
                    $(Convert-StringToCertificateSerialNumber -SerialNumber $SerialNumber), 
                    1 # Document and set Constant
                )

            }

        }

        # Set the Key Usage Extension

        If ($CA) {

            # CA Certifcate Key Usages
            # https://security.stackexchange.com/questions/49229/root-certificate-key-usage-non-self-signed-end-entity
            # https://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509keyusageflags(v=vs.110).aspx
            # Since a CA is supposed to issue certificate and CRL, it should have, on a general basis, the keyCertSign and cRLSign flags. 
            # These two flags are sufficient.
            [Security.Cryptography.X509Certificates.X509KeyUsageFlags]$KeyUsage = "KeyCertSign, CrlSign, DigitalSignature"

        }
        Else {

            # Leaf Certificate Key Usages
            [Security.Cryptography.X509Certificates.X509KeyUsageFlags]$KeyUsage = "KeyEncipherment, DigitalSignature"

        }

        $KeyUsageExtension = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
        $KeyUsageExtension.InitializeEncode([Int]$KeyUsage)
        $KeyUsageExtension.Critical = $True

        # Adding the Key Usage Extension to the Certificate
        $TargetCertificate.X509Extensions.Add($KeyUsageExtension)

        # Set Basic Constraints Extension
        # only if we build a CA certificate

        If ($CA.IsPresent) {

            $BasicConstraintsExtension = New-Object -ComObject X509Enrollment.CX509ExtensionBasicConstraints

            # First Parameter: CA or not
            $BasicConstraintsExtension.InitializeEncode(
                $True, # Constant, Document
                $PathLength
            )

            # Only mark as critical if it is a CA certificate
            $BasicConstraintsExtension.Critical = $True

            # Adding the Extension to the Certificate
            $TargetCertificate.X509Extensions.Add($BasicConstraintsExtension)
        }

        # Set the Enhanced Key Usages Extension depending on Certificate Type
        If ($Eku) {
    
            $EnhancedKeyUsageExtension = New-Object -ComObject 'X509Enrollment.CX509ExtensionEnhancedKeyUsage'
            $EnhancedKeyUsageOids = New-Object -ComObject 'X509Enrollment.CObjectIds.1'

            $Eku | Sort-Object | Get-Unique | ForEach-Object {

                $EnhancedKeyUsageOid = New-Object -ComObject 'X509Enrollment.CObjectId'

                $EnhancedKeyUsageOid.InitializeFromValue($EkuNameToOidTable[$_])

                $EnhancedKeyUsageOids.Add($EnhancedKeyUsageOid)
    
            }

            $EnhancedKeyUsageExtension.InitializeEncode($EnhancedKeyUsageOids)

            # Adding the Extension to the Certificate
            $TargetCertificate.X509Extensions.Add($EnhancedKeyUsageExtension)

        }

        # Set the Subject Alternative Names Extension if specified as Argument
        If ($Upn -or $DnsName) {

            $SansExtension = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
            $Sans = New-Object -ComObject X509Enrollment.CAlternativeNames

            Foreach ($Entry in $Upn) {
            
                $SanType = $XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME
                # https://msdn.microsoft.com/en-us/library/aa374981(VS.85).aspx
                $SanEntry = New-Object -ComObject X509Enrollment.CAlternativeName
                $SanEntry.InitializeFromString($SanType, $Entry)
                $Sans.Add($SanEntry)

            }

            Foreach ($Entry in $DnsName) {
            
                $SanType = $XCN_CERT_ALT_NAME_DNS_NAME
                # https://msdn.microsoft.com/en-us/library/aa374981(VS.85).aspx
                $SanEntry = New-Object -ComObject X509Enrollment.CAlternativeName
                $SanEntry.InitializeFromString($SanType, $Entry)
                $Sans.Add($SanEntry)

            }
            
            $SansExtension.InitializeEncode($Sans)

            # Adding the Extension to the Certificate
            $TargetCertificate.X509Extensions.Add($SansExtension)

        }
    
        # Set the Authority Key Identifier Extension if specified as Argument
        If ($Aki) {

            $AkiExtension = New-Object -ComObject X509Enrollment.CX509ExtensionAuthorityKeyIdentifier 

            # https://docs.microsoft.com/en-us/windows/desktop/api/certenroll/nf-certenroll-ix509extensionauthoritykeyidentifier-initializeencode
            $AkiExtension.InitializeEncode(
                $XCN_CRYPT_STRING_BASE64, 
                $(Convert-DERToBASE64 -String $Aki)
            )

            # Adding the Extension to the Certificate
            $TargetCertificate.X509Extensions.Add($AkiExtension)

        }

        # Set the CRL Distribution Points Extension if specified as Argument
        If ($Cdp) {

            # No Interface for this OID, see https://msdn.microsoft.com/en-us/library/windows/desktop/aa378077(v=vs.85).aspx
            # Therefore, we will build the data by hand (Function New-CdpExtension)
            $CdpExtension = New-Object -ComObject X509Enrollment.CX509Extension
            $CdpExtensionOid = New-Object -ComObject X509Enrollment.CObjectId
            $CdpExtensionOid.InitializeFromValue($XCN_OID_CRL_DIST_POINTS)
            $CdpExtension.Critical = $False
            # https://msdn.microsoft.com/en-us/library/windows/desktop/aa378511(v=vs.85).aspx
            $CdpExtension.Initialize(
                $CdpExtensionOid, 
                $XCN_CRYPT_STRING_BASE64, 
                $(New-CdpExtension -Url $Cdp)
            )

            # Adding the Extension to the Certificate
            $TargetCertificate.X509Extensions.Add($CdpExtension)

        }

        # Set the Authority Information Access Extension if specified as Argument
        If ($Aia) {

            # No Interface for this OID, see https://msdn.microsoft.com/en-us/library/windows/desktop/aa378077(v=vs.85).aspx
            # Therefore, we will build the data by hand (Function New-AiaExtension)
            $AiaExtension = New-Object -ComObject X509Enrollment.CX509Extension
            $AiaExtensionOid = New-Object -ComObject X509Enrollment.CObjectId
            $AiaExtensionOid.InitializeFromValue($XCN_OID_AUTHORITY_INFO_ACCESS)
            $AiaExtension.Critical = $False
            # https://msdn.microsoft.com/en-us/library/windows/desktop/aa378511(v=vs.85).aspx
            $AiaExtension.Initialize(
                $AiaExtensionOid, 
                $XCN_CRYPT_STRING_BASE64, 
                $(New-AiaExtension -Url $Aia)
            )

            # Adding the Extension to the Certificate
            $TargetCertificate.X509Extensions.Add($AiaExtension)

        }

        # Specifying the Hashing Algorithm to use
        $HashAlgorithmObject = New-Object -ComObject X509Enrollment.CObjectId
        $HashAlgorithmObject.InitializeFromAlgorithmName(
            1, # Document, Constant
            0, # Document, Constant
            0, # Document, Constant
            $SignatureHashAlgorithm
        )
        $TargetCertificate.HashAlgorithm = $HashAlgorithmObject

        # Encoding the Certificate Signing Request
        $TargetCertificate.Encode()

        # Enrolling for the Certificate
        $EnrollmentObject = New-Object -ComObject 'X509Enrollment.CX509Enrollment'
        $EnrollmentObject.InitializeFromRequest($TargetCertificate)
        $TargetCertificateCsr = $EnrollmentObject.CreateRequest(0)

        If ($Csr.IsPresent) {

            $TargetCertificateCsr

        }
        Else {

            # Signing the Certificate
            $EnrollmentObject.InstallResponse(
                2, # Document, Constant
                $TargetCertificateCsr, 
                0, # Document, Constant
                "" # Document, Constant
            )

            # We load the Certificate into an X509Certificate2 Object so that we can call Certificate Properties
            $CertificateObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $CertificateObject.Import([Convert]::FromBase64String($EnrollmentObject.Certificate()))
            
            # This would return it directly as an X509Certificate2 Object, but this cannot be used as 
            # -SigningCertificate afterwards as the Powershell-specific stuff is missing, but perhaps we can get it working?
            # $CertificateObject
            
            # Returning the Certificate as PowerShell Object
            Get-ChildItem Cert:\CurrentUser\My\$($CertificateObject.Thumbprint)

        }

    }

}