# What about Convert-StringToDER

Function Convert-StringToDER {

    # Encodes a String in DER
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $IdentifierOctets, # Identifier Octets... WTF, why is this String and not Int?

        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ContentOctets # Content Octets
    )

    process {

        # Length of hex fqdn, in hex
        $LengthOctets = Get-Asn1LengthOctets -strLen $($ContentOctets.Length)

        # Constructed, definite-length method
        # This method applies to simple string types, structured types, types derived simple
        #  string types and structured types by implicit tagging, and types derived from 
        # anything by explicit tagging. It requires that the length of the value be known in advance. 
        # The parts of the BER encoding are as follows:

        # Identifier octets.
        #  These identify the class and tag number of the ASN.1 value, and indicate whether the 
        #  method is primitive or constructed.

        # Length octets.
        #   For the definite-length methods, these give the number of contents octets.

        # Contents octets.
        #   For the primitive, definite-length method, these give a concrete representation of the value.

        # Assembling the node
        "${IdentifierOctets}${LengthOctets}${ContentOctets}"

    }

}