# py-vault-udp

own python udp wrapper class, used in other projects:

- uses mtu to determine max length of package (error for symetric encryption package)
- can send/ receive strings
- data packed in json
- packages are padded (except for error)
- play around with nacl for asymetric encryption -> should not be used in production
- play around with PyNewHope for symmetric enryption -> should not beused in production
- pysignal used for callbacks to send and receive
  
