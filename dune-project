(lang dune 3.17)

(name wallet_gen)

(generate_opam_files true)

(authors "Octra Labs <dev@octra.org>")

(maintainers "Octra Labs <dev@octra.org>")

(license custom)

(source
 (github octra-labs/wallet-gen))

(homepage "https://github.com/octra-labs/wallet-gen")

(bug_reports "https://github.com/octra-labs/wallet-gen/issues")

(package
 (name wallet_gen)
 (synopsis "Octra Wallet Generator")
 (description "Key pair generator for Octra Test Network")
 (depends
  (ocaml
   (>= 4.08))
  dune
  digestif
  mirage-crypto
  mirage-crypto-ec
  mirage-crypto-pk
  mirage-crypto-rng
  yojson
  zarith
  cstruct
  hex)
 (allow_empty))
