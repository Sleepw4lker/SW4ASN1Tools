# SW4ASN1Tools

Some helpful functions to play with Certificates in Powershell.

Exported Functions:
* `New-CraftedCertificate` crafts a Certificate based on the given Arguments. Can both create self-signed Certificates as well as sign with a different Key. You can specify the following Enhanced Key Usages (EKUs):
 * CAExchange
 * CertRequestAgent
 * ClientAuth
 * CodeSigning
 * DocumentSigning
 * EncryptingFileSystem
 * FileRecovery
 * IPSecEndSystem
 * IPSecIKEIntermediate
 * IPSecTunnelEndpoint
 * IPSecUser
 * KeyRecovery
 * KDCAuth
 * MicrosoftTrustListSigning
 * QualifiedSubordination
 * RootListSigner
 * SecureEmail
 * ServerAuth
 * SmartCardLogon
 * TimeStamping
 * OCSPSigning
 * RemoteDesktopAuth
 * PrivateKeyArchival
 * AMTProvisioning
* `New-OCSPCertificateRequest` creates a Certificate Signing Request for the Microsoft OCSP Responder that contains the AKI Extension, which allows for manual Enrollment, e.g. in a DMZ Scenario. Supports specifying the KSP, thus the usage of a HSM is possible.
* `New-CDPExtension` creates a DER Encoded CDP Extension for Usage with the above Functions.
* `New-AIAExtension` creates a DER Encoded AIA Extension for Usage with the above Functions.
* `New-AKIExtension` creates a DER Encoded AKI Extension for Usage with the above Functions.

## Usage Samples:

### Creating a Certificate Hierarchy in a 3-Liner
```powershell
$a = New-CraftedCertificate -CA -CommonName "Root CA"
$b = New-CraftedCertificate -CA -CommonName "Sub CA" -SigningCert $a -PathLength 0
$c = New-CraftedCertificate -Eku "ServerAuth" -CommonName "www.demo.org" -DnsName "www.demo.org" -SigningCert $b
$a,$b,$c
```

### Demonstrating a Path length Constraint violation
```powershell
$a = New-CraftedCertificate -CA -CommonName "Root CA" 
$b = New-CraftedCertificate -CA -CommonName "Sub CA" -SigningCert $a -PathLength 0
$c = New-CraftedCertificate -CA -CommonName "Invalid Path Length CA" -SigningCert $b
$d = New-CraftedCertificate -Eku "ServerAuth" -CommonName "Invalid Path Length Certificate" -DnsName "www.demo.org" -SigningCert $c
$a,$b,$c,$d
```

### Demonstrating an EKU Constraint violation
```powershell
$a = New-CraftedCertificate -CA -CommonName "Root CA" 
$c = New-CraftedCertificate -CA -Eku "ClientAuth" -CommonName "Sub CA 1" -SigningCert $a
$c = New-CraftedCertificate -Eku "ServerAuth" -CommonName "Invalid EKU Certificate" -DnsName "www.demo.org" -SigningCert $b
$a,$b,$c
```

### Creating a manual OCSP Request specifying AKI and a HSM
```powershell
New-OcspCertificateRequest -Subject "CN=My-Responder" -Ksp "nCipher Security World Key Storage Provider" -Aki "060DDD83737C311EDA5E5B677D8C4D663ED5C5BF" -KeyLength 4096
```