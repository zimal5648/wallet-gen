# Octra Key and Wallet Generator

This software is released under the **Octra Labs Proprietary Testnet License** (All Rights Reserved).

- **Non-distributable**: You may not fork, redistribute, or repurpose this code in other projects.
- **Testnet Only**: Your use is strictly limited to Octra’s testnet phase, as authorized by Octra Labs.
- **No Warranties**: This software is provided on an “AS IS” basis.

## Pre-requisites

**Note** If you haven't setup `ocaml` environment yet, please follow the instructions below:

- Install `opam` (OCaml Package Manager) https://opam.ocaml.org/doc/Install.html
- Initialize `opam` environment
```shell
opam init --disable-sandboxing -y
eval $(opam env)
```

## Generating a new wallet

```shell
git clone https://github.com/octra-labs/wallet-gen.git
cd wallet-gen
eval $(opam env)
opam install . --deps-only --yes
make
make generate
```

As a result you will get a binary file (encrypted `wallet.oct`) which has all your account info (don’t lose this file because you will need it to link your wallet address for using and signing in the test client as your terminal wallet)

## Decrypting your wallet

Additionally, after you have generated your wallet, you can decrypt it using the following command:

```shell
make verify
```
