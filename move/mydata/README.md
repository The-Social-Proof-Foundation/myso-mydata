# MyData Package

MyData is a decentralized secrets management (DSM) service that relies on access control policies defined and validated on [MySocial](https://docs.mysocial.network/mysocial/mydata/overview). Application developers and users can use MyData to secure sensitive data at rest on decentralized storage like [MyData](https://www.mysocial.network/mydata), or on any other onchain / offchain storage.

This Move package provides the onchain functionality for:
- Registering and managing key servers
- Performing decryption using Boneh-Franklin key encapsulation (over BLS12-381) and HMAC-256-CTR as the data encapsulation mechanism (DEM)