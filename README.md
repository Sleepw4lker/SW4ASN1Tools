# SW4ASN1Tools

Some helpful functions to play with Certificates in Powershell.

Exported Functions:
* `New-SW4Certificate` Can both create self-signed Certificates as well as sign with a different Key.
* `New-OCSPCertificateRequest` Creates a Certificate Signing Request for the Microsoft OCSP Responder that contains the AKI Extension, which allows for manual Enrollment, e.g. in a DMZ Scenario. Supports specifying the KSP, thus the usage of a HSM is possible.
* `New-CDPExtension` creates a DER Encoded CDP Extension for Usage with the above Functions
* `New-AIAExtension` creates a DER Encoded AIA Extension for Usage with the above Functions
* `New-AKIExtension` creates a DER Encoded AKI Extension for Usage with the above Functions

## Usage Samples:
### Creating a PKI in a 3-Liner
```powershell
$a = New-SW4Certificate -CommonName "Root CA" -Type "CA"
$b = New-SW4Certificate -CommonName "Sub CA" -Type "CA" -SigningCert $a -PathLength 1
$c = New-SW4Certificate -CommonName "www.lol.de" -Type "WebServer" -SigningCert $b
$a,$b,$c
```

### Creating a manual OCSP Request specifying AKI and a HSM
```powershell
New-OcspCertificateRequest -Subject "CN=My-Responder" -Ksp "nCipher Security World Key Storage Provider" -Aki "060DDD83737C311EDA5E5B677D8C4D663ED5C5BF" -KeyLength 4096
```