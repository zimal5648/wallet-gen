# Octra Key and Wallet Generator

This software is released under the **Octra Labs Proprietary Testnet License** (All Rights Reserved).

- **Non-distributable**: You may not fork, redistribute, or repurpose this code in other projects.
- **Testnet Only**: Your use is strictly limited to Octra’s testnet phase, as authorized by Octra Labs.
- **No Warranties**: This software is provided on an “AS IS” basis.

## Generating a new wallet

```shell
git clone https://github.com/octra-labs/wallet-gen.git
cd wallet-gen
opam install . --deps-only --yes
dune build --profile release
dune exec ./bin/main.exe
```

As a result you will get a binary file (encrypted `wallet.oct`) which has all your account info (don’t lose this file because you will need it to link your wallet address for using and signing in the test client as your terminal wallet)

**Note**: If you're getting errors during the build process, you can follow `Step 1` of [node_configuration](https://github.com/octra-labs/node_configuration) instructions to prepare your environment.
