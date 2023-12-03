# Multisig

A Rust implementation of a multicodec format for digital signatures. There
alread exists a multicodec format called Varsig but it has some serious
deficiencies in design. Here is the Varsig
["spec"](https://github.com/ChainAgnostic/varsig).

This implementation supports building Multisig objects by converting Varsig 
signature but for now it is fairly limited.

This new Multisig implementation uses a new multicodec sigil `0x39` instead of 
the Varsig `0x34` to distinguish the two formats.

## Varsig Format 

```
                         payload encoding
     key codec                codec
         |                      |
         v                      v
0x34 <varuint> N(<varuint>) <varuint> N(OCTET)
^                    ^                    ^
|                    |                    |
varsig      variable number of     variable number
sigil       signature specific    of signature data
                   values              octets
```

The Varsig format unfortunately has a variable number of signature-specific 
values immediately following the key codec and before the encoding codec. This
makes it impossible for a tool to decode the encoding codec when it doesn't
recognize the key codec. Since there are no counts or lengths encoded in the 
Varsig data, it is impossible to know the full length of any Varsig without
having complete support for every key codec. Multikey seeks to fix that by 
adding counts for the variable number of varuints and a length to the variable 
number of octets (i.e. [`Varbytes`](https://github.com/cryptidtech/multiutil/blob/main/src/varbytes.rs)).

## Multisig Format 

```
                       combined signature
     key codec            message bytes
         |                      |
         v                      v
0x39 <varuint> <attributes> <message> <signature-payloads>
^                   ^                           ^
|                   |                           |
multisig    signature specific         signature payloads
sigil           attributes


<attributes> ::= <varuint> N(<varuints>)
                     ^           ^
                    /             \
            count of               variable number
    attribute values               attribute values


<message> ::= <varbytes>


<signature-payloads> ::= <varuint> N(<varbytes>)
                             ^           ^
                            /             \
                    count of               variable number
          signature payloads               signature payloads


<varbytes> ::= <varuint> N(OCTET)
                   ^        ^
                  /          \
          count of            variable number
            octets            of octets
```

The Multikey format allows tools that don't recognize the key codec to at least
know how many octets are in the Multisig data so that it can skip over it. This
format is also designed to support any kind of digital signature, even 
signatures with multiple signature payloads such as threshold signatures. This
also supports building combined signatures that contain the signed data in the 
<`message`> part of the signature.
