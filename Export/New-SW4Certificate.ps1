# Kudos to:
# https://blog.css-security.com/blog/creating-a-self-signed-ssl-certificate-using-powershell
# https://blogs.technet.microsoft.com/vishalagarwal/2009/08/21/generating-a-certificate-self-signed-using-powershell-and-certenroll-interfaces/
# https://gist.github.com/carnal0wnage/42f4d1a0c46fe9ebe8d5
# http://stackoverflow.com/questions/35864912/ix509extension-xcn-encoding
# https://social.technet.microsoft.com/Forums/en-US/f568edfa-7f93-46a4-aab9-a06151592dd9/converting-ascii-to-asn1-der?forum=winserverpowershell
# https://gallery.technet.microsoft.com/scriptcenter/Self-signed-certificate-5920a7c6

Function New-SW4Certificate {

    # Creates a rouge Certificate signed with a given signing Certificate
    # Usually, a stolen CA Certificate and it's private Key
    # Intended to demonstrate why it is important to properly secure your CA
    [cmdletbinding()]
    param (

        # Parameter Sets
        # http://wragg.io/create-dynamic-powershell-functions-with-parameter-sets/

        # What about an -EKU Parameter instead? Like -EKU "ClientAuthentication","SmartCardLogon"
        # Then, Distinguish only between "CA" or not
        [Parameter(Mandatory=$True)]
        [ValidateSet("CA","SmartCardLogon","WebServer","CodeSigning")]
        [String]
        $Type,

        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $CommonName,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $San,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Cdp,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Aia,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^http\://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(/\S*)?$")]
        [String[]]
        $Ocsp,

        [Parameter(Mandatory=$False)]
        [ValidateScript({$Null -ne (certutil -csplist | find "$($_)")})]
        [String]
        $Ksp = "Microsoft Enhanced RSA and AES Cryptographic Provider",

        [Parameter(Mandatory=$True)] # Should be enhanced to use the own Key if not specified = Self-Signed
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
        [ValidateSet("MD4","MD5","SHA1","SHA256","SHA384","SHA512")]
        [String]
        $SignatureHashAlgorithm = "SHA256",

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^[0-9a-fA-F]{1,100}$")] # Why 100?
        [String]
        $SerialNumber,

        # Nothing implemented yet
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
        [ValidateRange(-1,16)] # Should be sufficient...?
        [Int]
        $PathLength = -1 # -1 means none

    )

    process {

        If ($Scope -eq "Computer") {

            # Check for Elevation - we will create a Machine Key
            If(-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                throw "User is not a local Administrator"
            }

        }

        # To Do:
        # - More Input validation
        # - I would like to see all relevant Numbers as Constants here

        New-Variable -Name UserContext -Value 0x1 -Option Constant
        New-Variable -Name MachineContext -Value 0x2 -Option Constant

        New-Variable -Name XCN_CERT_NAME_STR_NONE -Value 0 -Option Constant
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

        # https://msdn.microsoft.com/de-de/library/windows/desktop/aa378132(v=vs.85).aspx
        New-Variable -Name XCN_OID_PKIX_KP_SERVER_AUTH -Value '1.3.6.1.5.5.7.3.1' -Option Constant
        New-Variable -Name XCN_OID_PKIX_KP_CLIENT_AUTH -Value '1.3.6.1.5.5.7.3.2' -Option Constant
        New-Variable -Name XCN_OID_PKIX_KP_CODE_SIGNING -Value '1.3.6.1.5.5.7.3.3' -Option Constant
        New-Variable -Name XCN_OID_KP_SMARTCARD_LOGON -Value '1.3.6.1.4.1.311.20.2.2' -Option Constant

        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379367(v=vs.85).aspx
        New-Variable -Name XCN_OID_CRL_DIST_POINTS -Value '2.5.29.31' -Option Constant
        New-Variable -Name XCN_OID_AUTHORITY_INFO_ACCESS -Value '1.3.6.1.5.5.7.1.1' -Option Constant

        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa374936(v=vs.85).aspx
        New-Variable -Name XCN_CRYPT_STRING_BASE64 -Value 0x1 -Option Constant

        # Validating if our Signing Certificate is really a CA Certificate
        If (-not ($SigningCert.Extensions.CertificateAuthority)) {
            Write-Warning "Signing Certificate seems not to be a CA certificate." 
        }

        # Validating the Type Parameter
        Switch ($Type) {

            "CA" {

                # CA Certificate
                $TargetCertificatePrivateKeyKeySpec = 2

            }

            "SmartCardLogon" {

                # Validating if we have a CDP Extension specified
                # Mandatory for Smartcard Logon, see https://support.microsoft.com/en-us/kb/281245
                If (-not ($Cdp)) {
                    Write-Warning "The CDP Extension is mandatory for Smartcard Logon Certificates." 
                }

                # Validating if we have a Subject Alternative Name specified
                # Mandatory for Smartcard Logon, see https://support.microsoft.com/en-us/kb/281245
                If (-not ($San)) {
                    Write-Warning "The SAN Extension with an UPN is mandatory for Smartcard Logon Certificates." 
                }

                # Not a CA Certificate
                $TargetCertificatePrivateKeyKeySpec = 1

                # Client Authentication and Smart Card Logon EKU
                $EnhancedKeyUsageOidList = $XCN_OID_PKIX_KP_CLIENT_AUTH,$XCN_OID_KP_SMARTCARD_LOGON
                $SanType = $XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME
            }

            "WebServer" {

                # Not a CA Certificate
                $TargetCertificatePrivateKeyKeySpec = 1

                # Server Authentication EKU
                $EnhancedKeyUsageOidList = $XCN_OID_PKIX_KP_SERVER_AUTH
                $SanType = $XCN_CERT_ALT_NAME_DNS_NAME
            }

            "CodeSigning" {

                # Not a CA Certificate
                $TargetCertificatePrivateKeyKeySpec = 1

                # Code Signing EKU
                $EnhancedKeyUsageOidList = $XCN_OID_PKIX_KP_CODE_SIGNING
                $SanType = $XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME
            }

        }

        # Here's how you move the Certificate to a Smart Card later on: 
        # https://blogs.technet.microsoft.com/pki/2007/11/13/manually-importing-keys-into-a-smart-card/
        # certutil –csp "Microsoft Base Smart Card Crypto Provider" –importpfx "<Filename>.pfx"
        $TargetCryptoProvider = $Ksp

        # Creating a new Private Key
        $TargetCertificatePrivateKey = New-Object -ComObject 'X509Enrollment.CX509PrivateKey'
        $TargetCertificatePrivateKey.ProviderName = $TargetCryptoProvider

        # 2 = CA certificate
        # 1 = all others
        $TargetCertificatePrivateKey.KeySpec = $TargetCertificatePrivateKeyKeySpec

        # 1 = Machine Context
        # 0 = User Context
        $TargetCertificatePrivateKey.MachineContext = [int]($Scope -eq "Computer")

        # We allow the private Key to be exported
        $TargetCertificatePrivateKey.ExportPolicy = [int]$True

        # Specifying the Key Length of the Private Key
        $TargetCertificatePrivateKey.Length = $KeyLength

        # Creating the Key (Pair)
        $TargetCertificatePrivateKey.Create()

        #
        # Assembling the Certificate
        #

        $TargetCertificate = New-Object -ComObject 'X509Enrollment.CX509CertificateRequestCertificate'
        $TargetCertificate.InitializeFromPrivateKey($UserContext, $TargetCertificatePrivateKey, "")

        # Subject Name

        $SubjectDistinguishedName = New-Object -ComObject 'X509Enrollment.CX500DistinguishedName'

        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379394(v=vs.85).aspx
        $SubjectDistinguishedName.Encode("CN=$($CommonName)", $XCN_CERT_NAME_STR_NONE)

        $TargetCertificate.Subject = $SubjectDistinguishedName

        # Issuer
        $IssuerDistinguishedName = New-Object -ComObject 'X509Enrollment.CX500DistinguishedName'

        # We must have the CN encoded as printableString instead of UTF-8, otherwise CRL verification will fail
        # During certificate chain validation (from the end entity to a trusted root) the KeyId is used to create 
        # the certificate chain and it works independently of the subject and issuer codification (PrintableString or UTF8)
        # During revocation status validation, a binary comparison is made between the certificate issuer and the CRL issuer,
        # so both fields must use the same codification in order to match (PrintableString or UTF8)
        # https://social.technet.microsoft.com/Forums/windowsserver/en-US/0459983f-4f19-48ee-b099-dfd484483176/active-directory-certificate-services-cannot-verify-certificate-chain-bad-cert-issuer-base-crl?forum=winserversecurity
        # https://msdn.microsoft.com/de-de/library/windows/desktop/bb540814(v=vs.85).aspx
        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379394(v=vs.85).aspx
        $IssuerDistinguishedName.Encode($SigningCert.Subject, $XCN_CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG)

        $TargetCertificate.Issuer = $IssuerDistinguishedName

        # Validity  Period

        # Backup One day to Avoid Timing Issues
        $TargetCertificate.NotBefore = (Get-Date).AddDays(-1)
        $TargetCertificate.NotAfter = (Get-Date).AddYears($ValidityPeriodUnits).AddDays(1)

        # Serial Number of the Certificate
        If ($SerialNumber) {

            $TargetCertificate.SerialNumber.InvokeSet($(Convert-StringToCertificateSerialNumber -SerialNumber $SerialNumber), 1)

        }

        # Specify Signing Certificate

        # First Argument: MachineContext (0/1)
        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa376832(v=vs.85).aspx
        # Alternative Method: $SigningCert.Initialize($SignerCertificateStore, 0, 1, $([Convert]::ToBase64String($signer.RawData)))
        $SignerCertificateObject =  New-Object -ComObject 'X509Enrollment.CSignerCertificate'
        $SignerCertificateObject.Initialize($SignerCertificateStore, 0, 4, $SigningCert.Thumbprint)
        $TargetCertificate.SignerCertificate = $SignerCertificateObject

        # Key Usage Extension 

        If ($Type -eq "CA") {
            # CA Certifcate Key Usages
            # https://security.stackexchange.com/questions/49229/root-certificate-key-usage-non-self-signed-end-entity
            # https://msdn.microsoft.com/de-de/library/system.security.cryptography.x509certificates.x509keyusageflags(v=vs.110).aspx
            # Since a CA is supposed to issue certificate and CRL, it should have, on a general basis, the keyCertSign and cRLSign flags. 
            # These two flags are sufficient.
            [Security.Cryptography.X509Certificates.X509KeyUsageFlags]$KeyUsage = "KeyCertSign, CrlSign, DigitalSignature"
        } Else {
            # Leaf Certificate Key Usages
            [Security.Cryptography.X509Certificates.X509KeyUsageFlags]$KeyUsage = "KeyEncipherment, DigitalSignature"
        }

        $KeyUsageExtension = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
        $KeyUsageExtension.InitializeEncode([Int]$KeyUsage)
        $KeyUsageExtension.Critical = $True

        # Adding the Extension to the Certificate
        $TargetCertificate.X509Extensions.Add($KeyUsageExtension)

        # Basic Constraints Extension
        # only if we build a CA certificate

        If ($Type -eq "CA") {

            $IsCA = $True

            $BasicConstraintsExtension = New-Object -ComObject X509Enrollment.CX509ExtensionBasicConstraints

            # First Parameter: CA or not
            $BasicConstraintsExtension.InitializeEncode($IsCA, $PathLength)

            # Only mark as critical if it is a CA certificate
            $BasicConstraintsExtension.Critical = $IsCA

            # Adding the Extension to the Certificate
            $TargetCertificate.X509Extensions.Add($BasicConstraintsExtension)
        }

        # Enhanced Key Usages Extension
        If ($EnhancedKeyUsageOidList) {
    
            $EnhancedKeyUsageExtension = New-Object -ComObject 'X509Enrollment.CX509ExtensionEnhancedKeyUsage'
            $EnhancedKeyUsageOids = New-Object -ComObject 'X509Enrollment.CObjectIds.1'

            ForEach ($EnhancedKeyUsage in $EnhancedKeyUsageOidList) {

                $EnhancedKeyUsageOid = New-Object -ComObject 'X509Enrollment.CObjectId'
                $EnhancedKeyUsageOid.InitializeFromValue($EnhancedKeyUsage)
                $EnhancedKeyUsageOids.Add($EnhancedKeyUsageOid)

            }

            $EnhancedKeyUsageExtension.InitializeEncode($EnhancedKeyUsageOids)

            # Adding the Extension to the Certificate
            $TargetCertificate.X509Extensions.Add($EnhancedKeyUsageExtension)

        }

        # Subject Alternative Names Extension
        If ($San) {

            $SansExtension = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
            $Sans = New-Object -ComObject X509Enrollment.CAlternativeNames

            Foreach ($Entry in $San) {
            
                # https://msdn.microsoft.com/en-us/library/aa374981(VS.85).aspx
                $SanEntry = New-Object -ComObject X509Enrollment.CAlternativeName
                $SanEntry.InitializeFromString($SanType, $Entry)
                $Sans.Add($SanEntry)

            }
            
            $SansExtension.InitializeEncode($Sans)

            # Adding the Extension to the Certificate
            $TargetCertificate.X509Extensions.Add($SansExtension)

        }

        # CRL Distribution Points Extension
        If ($Cdp) {

            # No Interface for this OID, see https://msdn.microsoft.com/en-us/library/windows/desktop/aa378077(v=vs.85).aspx
            # Therefore, we will build the data by hand (Function New-CdpExtension)
            $CdpExtension = New-Object -ComObject X509Enrollment.CX509Extension
            $CdpExtensionOid = New-Object -ComObject X509Enrollment.CObjectId
            $CdpExtensionOid.InitializeFromValue($XCN_OID_CRL_DIST_POINTS)
            $CdpExtension.Critical = $False
            # https://msdn.microsoft.com/en-us/library/windows/desktop/aa378511(v=vs.85).aspx
            $CdpExtension.Initialize($CdpExtensionOid, $XCN_CRYPT_STRING_BASE64, $(New-CdpExtension -Url $Cdp))

            # Adding the Extension to the Certificate
            $TargetCertificate.X509Extensions.Add($CdpExtension)

        }

        # Authority Information Access Extension
        If ($Aia) {

            # No Interface for this OID, see https://msdn.microsoft.com/en-us/library/windows/desktop/aa378077(v=vs.85).aspx
            # Therefore, we will build the data by hand (Function New-AiaExtension)
            $AiaExtension = New-Object -ComObject X509Enrollment.CX509Extension
            $AiaExtensionOid = New-Object -ComObject X509Enrollment.CObjectId
            $AiaExtensionOid.InitializeFromValue($XCN_OID_AUTHORITY_INFO_ACCESS)
            $AiaExtension.Critical = $False
            # https://msdn.microsoft.com/en-us/library/windows/desktop/aa378511(v=vs.85).aspx
            $AiaExtension.Initialize($AiaExtensionOid, $XCN_CRYPT_STRING_BASE64, $(New-AiaExtension -Url $Aia))

            # Adding the Extension to the Certificate
            $TargetCertificate.X509Extensions.Add($AiaExtension)

        }

        # Specifying the Hashing Algorithm to use
        $HashAlgorithmObject = New-Object -ComObject X509Enrollment.CObjectId
        $HashAlgorithmObject.InitializeFromAlgorithmName(1, 0, 0, $SignatureHashAlgorithm)
        $TargetCertificate.HashAlgorithm = $HashAlgorithmObject

        # Encoding the Certificate Signing Request
        $TargetCertificate.Encode()

        # Enrolling for the Certificate
        $EnrollmentObject = New-Object -ComObject 'X509Enrollment.CX509Enrollment'
        $EnrollmentObject.InitializeFromRequest($TargetCertificate)
        $TargetCertificateCsr = $EnrollmentObject.CreateRequest(0)

        # Signing the Certificate
        $EnrollmentObject.InstallResponse(2, $TargetCertificateCsr, 0, "")

        # Returning the Certificate
        Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -match $CommonName } | Sort-Object -Descending NotAfter | Select-Object -First 1

    }

}