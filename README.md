# SW4ASN1Tools

## Usage Sample:
```powershell
$a = New-SW4Certificate -CommonName "Root CA" -Type "CA"
$b = New-SW4Certificate -CommonName "Sub CA" -Type "CA" -SigningCert $a -PathLength 1
$c = New-SW4Certificate -CommonName "www.lol.de" -Type "WebServer" -SigningCert $b
$a,$b,$c
```