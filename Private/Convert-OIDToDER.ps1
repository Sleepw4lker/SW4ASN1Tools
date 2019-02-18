Function Convert-OIDToDER {

    param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Oid
    )

    process {

        <#
            Convert-OIDToDER
            BER encoding. Primitive. Contents octets are as follows, where value1, ..., valuen denote 
            the integer values of the components in the complete object identifier:
            The first octet has value 40 * value1 + value2. 
            (This is unambiguous, since value1 is limited to values 0, 1, and 2; value2 is limited to the 
            range 0 to 39 when value1 is 0 or 1; and, according to X.208, n is always at least 2.)
            The following octets, if any, encode value3, ..., valuen.
            Each value is encoded base 128, most significant digit first, with as few digits as possible, 
            and the most significant bit of each octet except the last in the value's encoding set to "1." 
            Example: The first octet of the BER encoding of RSA Data Security, Inc.'s object identifier 
            is 40 * 1 + 2 = 42 = 2a16.
            The encoding of 840 = (6 * 128 + 4816) is 86 48 and 
            the encoding of 113549 = (6 * 1282 + 7716 * 128 + d16) is 86 f7 0d. 
            This leads to the following BER encoding:
            06 06 2a 86 48 86 f7 0d
            DER encoding. Primitive. Contents octets are as for a primitive BER encoding. 
        #>

        $i = 1
        $peter = ''

        $Oid.Split(".") | ForEach-Object {

            If ($i -eq 1) {
                $peter = $_
            }

            If ($i -eq 2) {
                $peter = 40 * $peter + $_
            }

            If ($i -ge 3) {

            }

            $i++

        }

        $peter

    }

}