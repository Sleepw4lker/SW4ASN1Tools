# SW4ASN1Tools

Some helpful functions to play with Certificates in Powershell.

Exported Functions:
* `New-SW4Certificate` Can both create self-signed Certificates as well as sign with a different Key.
* `New-OCSPCertificateRequest` Creates a Certificate Signing Request for the Microsoft OCSP Responder that contains the AKI Extension, which allows for manual Enrollment, e.g. in a DMZ Scenario. Supports specifying the KSP, thus the usage of a HSM is possible.
* `New-CDPExtension` creates a DER Encoded CDP Extension for Usage with the above Functions
* `New-AIAExtension` creates a DER Encoded AIA Extension for Usage with the above Functions
* `New-AKIExtension` creates a DER Encoded AKI Extension for Usage with the above Functions

## Usage Samples:

### Creating a Certificate Hierarchy in a 3-Liner
```powershell
$a = New-CraftedCertificate -Type "CA" -CommonName "Root CA"
$b = New-CraftedCertificate -Type "CA" -CommonName "Sub CA" -SigningCert $a -PathLength 0
$c = New-CraftedCertificate -Type "WebServer" -San "www.demo.org" -SigningCert $b
$a,$b,$c
```

### Demonstrating a Path length Constraint violation
```powershell
$a = New-CraftedCertificate -Type "CA" -CommonName "Root CA" 
$b = New-CraftedCertificate -Type "CA" -CommonName "Sub CA" -SigningCert $a -PathLength 0
$c = New-CraftedCertificate -Type "CA" -CommonName "Invalid CA" -SigningCert $b
$d = New-CraftedCertificate -Type "WebServer" -CommonName "www.demo.org" -San "www.demo.org" -SigningCert $c
$a,$b,$c,$d
```

### Creating a manual OCSP Request specifying AKI and a HSM
```powershell
New-OcspCertificateRequest -Subject "CN=My-Responder" -Ksp "nCipher Security World Key Storage Provider" -Aki "060DDD83737C311EDA5E5B677D8C4D663ED5C5BF" -KeyLength 4096
```