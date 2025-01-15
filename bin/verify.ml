open Helpers

let () =
  let ic = open_in_bin "wallet.oct" in
  let pass = get_password () in
  let secret = slow_pbkdf pass 1 "" in
  let key_length = 32 in
  let key = Mirage_crypto.AES.GCM.of_secret (String.sub secret 0 key_length) in

  verify ic key
