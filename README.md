# SW4ASN1Tools

Some helpful functions to play with Certificates in Powershell.

Exported Functions:
* `New-SW4Certificate` Can both create self-signed Certificates as well as sign with a different Key.
* `New-OCSPCertificateRequest` Creates a Certificate Signing Request for the Microsoft OCSP Responder that contains the AKI Extension, which allows for manual Enrollment, e.g. in a DMZ Scenario. Supports specifying the KSP, thus the usage of a HSM is possible.
* `New-CDPExtension` creates a DER Encoded CDP Extension for Usage with the above Functions
* `New-AIAExtension` creates a DER Encoded AIA Extension for Usage with the above Functions
* `New-AKIExtension` creates a DER Encoded AKI Extension for Usage with the above Functions

## Usage Sample:
```powershell
$a = New-SW4Certificate -CommonName "Root CA" -Type "CA"
$b = New-SW4Certificate -CommonName "Sub CA" -Type "CA" -SigningCert $a -PathLength 1
$c = New-SW4Certificate -CommonName "www.lol.de" -Type "WebServer" -SigningCert $b
$a,$b,$c
```