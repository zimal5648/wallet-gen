open Mirage_crypto_ec

module Console = struct
  let c = "\027[36m"
  let g = "\027[32m"
  let y = "\027[33m"
  let b = "\027[34m"
  let r = "\027[0m"
  let bd = "\027[1m"
  let s t = Printf.printf "\n\n%s%s=== %s ===%s\n\n" c bd t r
  let h t = Printf.printf "\n\n%s%s▶ %s%s\n" b bd t r
  let st t = Printf.printf "\n  %s→ %s%s" b t r
  let sc t = Printf.printf "  %s✓ %s%s\n" g t r
  let e t = Printf.printf "\n  %s✗ %s%s\n" y t r
  let dt t = Printf.printf "\n    \027[90m%s\027[0m" t
  let x l xx = Printf.printf "\n      %-15s : \027[35m%s\027[0m" l xx
  let sep () = Printf.printf "\n\n  \027[90m%s\027[0m\n" (String.make 50 '=')
  let sp () = Printf.printf "\n"
end

let validate_password p =
  let length_valid = String.length p >= 9 in
  if not length_valid then
    Printf.printf "Password must be at least 9 characters long.\n";
  length_valid

let rec get_password () =
  Printf.printf "\nPassword must be strong and at least 9 characters long.\n";
  Printf.printf "Please enter your password: ";

  let p = read_line () in
  let is_valid = validate_password p in
  if is_valid then (
    Printf.printf "Password is accepted.\n";
    p)
  else (
    Printf.printf
      "\nThe password does not meet the length requirement. Please try again.\n";
    get_password ())

let hs ~key msg =
  let open Digestif in
  let kb =
    if String.length key > 128 then SHA512.(to_raw_string (digest_string key))
    else key
  in

  let pad = Bytes.make 128 '\x00' in
  Bytes.blit_string kb 0 pad 0 (String.length kb);

  let opad = Bytes.map (fun c -> Char.chr (Char.code c lxor 0x5c)) pad in
  let ipad = Bytes.map (fun c -> Char.chr (Char.code c lxor 0x36)) pad in

  let ih =
    SHA512.(digest_string (Bytes.to_string ipad ^ msg)) |> SHA512.to_raw_string
  in
  let oh =
    SHA512.(digest_string (Bytes.to_string opad ^ ih)) |> SHA512.to_raw_string
  in
  oh

let xor_many s times =
  let rec aux current_str remaining_times =
    match remaining_times with
    | 0 -> current_str
    | _ ->
        let digested = hs ~key:current_str current_str in
        let combined =
          String.init (String.length current_str) (fun i ->
              let a = Char.code current_str.[i] in
              let b = Char.code digested.[i mod String.length digested] in
              Char.chr (a lxor b))
        in
        aux combined (remaining_times - 1)
  in
  aux s times

let base = "octra-encrypt"

let rec slow_pbkdf p n accum =
  if String.length accum >= 32 then String.sub accum 0 32
  else
    let block_data =
      let base_data = base in
      let padding = String.init 3 (fun _ -> '\x00') in
      let index_byte = String.make 1 (Char.chr (n land 0xff)) in
      base_data ^ padding ^ index_byte
    in

    let dig =
      let intermediate_digest = hs ~key:p block_data in
      let final_digest = xor_many intermediate_digest 99999 in
      final_digest
    in

    let updated_accum =
      let combined = accum ^ dig in
      combined
    in

    slow_pbkdf p (n + 1) updated_accum

let verify ic key =
  Console.st "Verifying wallet.oct...";
  let nonce_len = input_binary_int ic in
  let nonce_read = really_input_string ic nonce_len in
  let cipher_len = input_binary_int ic in
  let cipher_read = really_input_string ic cipher_len in
  close_in ic;

  match
    Mirage_crypto.AES.GCM.authenticate_decrypt ~key ~nonce:nonce_read ~adata:""
      cipher_read
  with
  | None ->
      Console.e "Failed to decrypt wallet";
      failwith "Decryption failed"
  | Some decrypted -> (
      Console.sc "Wallet verified successfully";
      Console.st "Wallet contents:";
      match String.split_on_char '\n' decrypted with
      | [ m; priv_hex; pub_hex ] ->
          Console.x "Mnemonic" m;
          Console.x "Private Key" priv_hex;
          Console.x "Public Key" pub_hex
      | _ ->
          Console.e "Invalid wallet format";
          Console.dt
            ("Found parts: "
            ^ string_of_int (List.length (String.split_on_char '\n' decrypted))
            );
          failwith "Invalid wallet format")
