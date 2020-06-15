# dcs-python-client

This is a sample client for the [Document Checking Service (DCS) API](https://dcs-pilot-docs.cloudapps.digital/). It serves as an example of how to create a request for the DCS and how to decrypt the response.

**⚠️ This is not a production ready client library. It is only an example of how to build a connection to the DCS ⚠️**

## Installation

Run `pip3 install .`

## Usage

```
$ dcs-client -h

Make a test passport request to the Document Checking Service (DCS)

Usage: dcs-client [--url <url>] --client-signing-certificate <PATH> --client-signing-key <PATH> --server-encryption-certificate <PATH> --client-encryption-key <PATH> --server-signing-certificate <PATH> --client-ssl-certificate <PATH> --client-ssl-key <PATH> --server-ssl-ca-bundle <PATH>

Options:
    -h --help                               Show this screen.
    --url <url>                             The DCS passport endpoint [default: https://dcs-integration.ida.digital.cabinet-office.gov.uk/checks/passport]
    --client-signing-certificate <PATH>     The certificate with which the client signs requests
    --client-signing-key <PATH>             The key with which the client signs requests
    --server-encryption-certificate <PATH>  The server certificate for which the client encrypts requests
    --client-encryption-key <PATH>          The key with which the client decrypts responses
    --server-signing-certificate <PATH>     The certificate with which the server signs responses
    --client-ssl-certificate <PATH>         The client certificate used for mutual TLS
    --client-ssl-key <PATH>                 The client key used for mutual TLS
    --server-ssl-ca-bundle <PATH>           The server SSL CA bundle

This client is intended as an example of how to write a DCS client. It should not be used against a production DCS.
See https://dcs-pilot-docs.cloudapps.digital/ for public documentation of the DCS API.
```

## Support and raising issues

If you think you have discovered a security issue in this code, please consult the [Alphagov Security policy](https://github.com/alphagov/.github/blob/master/SECURITY.md)

If your bug or issue is not security related, please [raise an issue](https://github.com/alphagov/dcs-python-client/issues/new) in the GitHub issue tracker.

## Code of Conduct
This project is developed under the [Alphagov Code of Conduct](https://github.com/alphagov/.github/blob/master/CODE_OF_CONDUCT.md)
