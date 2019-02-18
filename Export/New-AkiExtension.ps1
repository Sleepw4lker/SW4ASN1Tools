Function New-AkiExtension {

    # Returns BASE64 Encoded DER Object for the AKI Extension
    # ToDo: Replace Identifier Octets with Constants, and implement and Identifier to BER/DER Encoder

    # Example:
    # New-AkiExtension -Aki "060DDD83737C311EDA5E5B677D8C4D663ED5C5BF"
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()] # Implement a Validation RegEx (40 Chars, Lower, Upper, 0-9), shouldnt be too hard
        [String]
        $Aki
    )

    process {

        # Just to be sure, removing any Spaces and converting to upper case
        $Aki = $Aki -replace '\s','' # Obsolete once Validation RegEx is in place
        $Aki = $Aki.ToUpper()

        $Output = Convert-StringToDER `
                    -IdentifierOctets "80" `
                    -ContentOctets $Aki

        # Sequence
        $Output = Convert-StringToDER `
                    -IdentifierOctets "30" `
                    -ContentOctets $Output

        Convert-DERToBASE64 -String $Output
    }

}