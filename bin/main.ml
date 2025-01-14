(*
 * Copyright (c) 2025, Octra Labs.
 * All rights reserved.
 *
 * Permission is hereby granted to designated Octra early adopters and validators
 * to use this software solely for testing and validating the Octra blockchain network
 * during the testnet phase, under the terms and conditions provided in the
 * "Octra Labs Proprietary Testnet License" (the "License").
 *
 * Except as stated in the License, you may not copy, modify, distribute, or
 * re-license this software or any parts thereof. Reverse-engineering,
 * disassembling, or attempting to derive the source code outside of authorized
 * repository access is strictly prohibited.
 *
 * This software is provided on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * You should have received a copy of the License along with this software.
 * If not, please contact legal@octra.org for a copy.
 *)

open Hex
open Mirage_crypto_ec

module Console = struct
  let c = "\027[36m"
  let g = "\027[32m"
  let y = "\027[33m"
  let b = "\027[34m"
  let r = "\027[0m"
  let bd = "\027[1m"

  let s t = 
    Printf.printf "\n\n%s%s=== %s ===%s\n\n" c bd t r

  let h t =
    Printf.printf "\n\n%s%s▶ %s%s\n" b bd t r

  let st t =
    Printf.printf "\n  %s→ %s%s" b t r

  let sc t =
    Printf.printf "  %s✓ %s%s\n" g t r

  let e t =
    Printf.printf "\n  %s✗ %s%s\n" y t r

  let dt t = 
    Printf.printf "\n    \027[90m%s\027[0m" t

  let x l xx =
    Printf.printf "\n      %-15s : \027[35m%s\027[0m" l xx

  let sep () =
    Printf.printf "\n\n  \027[90m%s\027[0m\n" (String.make 50 '=')

  let sp () =
    Printf.printf "\n"
end

type network_type = 
 | MainCoin 
 | SubCoin of int 
 | Contract of int 
 | Subnet of int 
 | Account of int

let get_coin_type = function
 | MainCoin -> 0
 | SubCoin n -> n
 | Contract n -> 10 + n
 | Subnet n -> 100 + n
 | Account n -> 200 + n

let string_map2 f s1 s2 =
 let len = min (String.length s1) (String.length s2) in
 let r = Bytes.create len in
 for i = 0 to len - 1 do
   Bytes.set r i (f s1.[i] s2.[i])
 done;
 Bytes.unsafe_to_string r
 
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
      p
    ) else (
      Printf.printf "\nThe password does not meet the length requirement. Please try again.\n";
      get_password ()
    )

let bip39_wordlist =
 let file = "data/english.txt" in
 if not (Sys.file_exists file) then 
   failwith ("File not found: " ^ file);
 
 let ic = open_in file in
 let rec loop acc =
   match input_line ic with
   | line -> loop (line :: acc)
   | exception End_of_file -> 
       close_in ic;
       List.rev acc
 in
 Array.of_list (List.map String.trim (loop []))

let generate_entropy () =
 Mirage_crypto_rng.generate 16

let hs ~key msg =
 let open Digestif in
 let kb = 
   if String.length key > 128 then 
     SHA512.(to_raw_string (digest_string key)) 
   else 
     key 
 in
 
 let pad = Bytes.make 128 '\x00' in
 Bytes.blit_string kb 0 pad 0 (String.length kb);
 
 let opad = Bytes.map (fun c -> Char.chr ((Char.code c) lxor 0x5c)) pad in
 let ipad = Bytes.map (fun c -> Char.chr ((Char.code c) lxor 0x36)) pad in
 
 let ih = SHA512.(digest_string (Bytes.to_string ipad ^ msg)) |> SHA512.to_raw_string in
 let oh = SHA512.(digest_string (Bytes.to_string opad ^ ih)) |> SHA512.to_raw_string in
 oh

let take n lst =
 let rec aux acc k xs =
   if k = 0 then 
     List.rev acc
   else 
     match xs with
     | [] -> List.rev acc 
     | y::ys -> aux (y::acc) (k-1) ys
 in
 aux [] n lst

let drop n lst =
 let rec aux k xs =
   if k = 0 then 
     xs
   else 
     match xs with
     | [] -> []
     | _::ys -> aux (k-1) ys
 in
 aux n lst

let entropy_to_mnemonic e =
 let open Digestif in
 let cb = SHA256.digest_string e in
 let cbyte = int_of_char (SHA256.to_raw_string cb).[0] in
 let csum = cbyte lsr 4 in
 
 let to_bits b =
   let rec lp acc i =
     if i >= 8 then 
       acc
     else 
       lp (((b lsr i) land 1)::acc) (i+1)
   in
   lp [] 0
 in
 
 let e_bits = List.flatten (List.init (String.length e) 
   (fun i -> to_bits (int_of_char e.[i]))) in
   
 let c_bits = List.init 4 (fun i -> (csum lsr (3-i)) land 1) in
 let bits = e_bits @ c_bits in
 
 let rec tk11 bs acc =
   match bs with
   | [] -> List.rev acc
   | _ ->
       let part = take 11 bs in
       let idx = List.fold_left (fun n b -> n*2 + b) 0 part in
       tk11 (drop 11 bs) (bip39_wordlist.(idx)::acc)
 in
 tk11 bits []

let mnemonic_to_seed words passphrase =
 let password = String.concat " " words in
 let salt = "mnemonic" ^ passphrase in
 
 let rec iter prev i acc =
   if i = 0 then
     acc
   else
     let nx = hs ~key:password prev in
     let acc = string_map2 (fun x y -> 
       Char.chr (Char.code x lxor Char.code y)) acc nx 
     in
     iter nx (i-1) acc
 in
 
 let rec blocks n acc =
   if String.length acc >= 64 then
     String.sub acc 0 64
   else
     let block_data = salt ^ String.make 3 '\x00' ^ 
       String.make 1 (Char.chr (n land 0xff)) 
     in
     let first = hs ~key:password block_data in
     let block = iter first 2047 first in
     blocks (n+1) (acc ^ block)
 in
 blocks 1 ""

let derive_master_key seed =
 let h = hs ~key:"Octra seed" seed in
 (String.sub h 0 32, String.sub h 32 32)

let derive_child_key (key, chain) i =
 let open P256.Dsa in
 let pk = match priv_of_octets key with
   | Ok x -> x
   | Error _ -> failwith "Invalid private key"
 in
 
 let d =
   if i land 0x80000000 <> 0 then
     String.make 1 '\x00' ^ key
   else
     pub_to_octets ~compress:false (pub_of_priv pk)
 in
 
 let d = d ^ String.make 4 '\x00' in
 let d = String.sub d 0 (String.length d - 1) ^ 
   String.make 1 (Char.chr (i land 0xff)) 
 in
 
 let h = hs ~key:chain d in
 (String.sub h 0 32, String.sub h 32 32)

let derive_path seed path =
 let rec loop (k, c) = function
   | [] -> (k, c)
   | x::xs ->
       let ck, ch = derive_child_key (k, c) x in
       loop (ck, ch) xs
 in
 loop (derive_master_key seed) path

let derive_for_network ?(token=0) ?(subnet=0) seed ~network_type ~network ~contract ~account ~index =
  let base_path = [
    0x80000000 lor 345;
    0x80000000 lor (get_coin_type network_type);
    0x80000000 lor network;
  ] in
  let contract_path = [
    0x80000000 lor contract;
    0x80000000 lor account;
  ] in
  let optional_path = [
    0x80000000 lor token;
    0x80000000 lor subnet;
  ] in
  let final_path = [
    index
  ] in
  let path = base_path @ contract_path @ optional_path @ final_path in
  derive_path seed path

let xor_many s times =
  let rec aux current_str remaining_times =
    match remaining_times with
    | 0 -> current_str
    | _ ->
      let digested = hs ~key:current_str current_str in
      let combined =
        String.init (String.length current_str) (fun i ->
          let a = Char.code current_str.[i] in
          let b = Char.code digested.[i mod (String.length digested)] in
          Char.chr (a lxor b)
        )
      in
      aux combined (remaining_times - 1)
  in
  aux s times

let save_oct mnemonic master_priv master_pub =
    let pass = get_password () in
    let base = "octra-encrypt" in

    let rec slow_pbkdf p n accum =
  if String.length accum >= 32 then
    String.sub accum 0 32
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
in

    let secret = slow_pbkdf pass 1 "" in
    let key_length = 32 in
    let key = Mirage_crypto.AES.GCM.of_secret (String.sub secret 0 key_length) in
    let nonce = Mirage_crypto_rng.generate 12 in
    let hex_priv = Hex.show (Hex.of_string master_priv) in
    let hex_pub = Hex.show (Hex.of_string master_pub) in
    let msg = String.concat "\n" [mnemonic; hex_priv; hex_pub] in
    
    let ciphered = Mirage_crypto.AES.GCM.authenticate_encrypt 
      ~key ~nonce ~adata:"" msg 
    in
    
    let oc = open_out_bin "wallet.oct" in
    output_binary_int oc (String.length nonce);
    output_string oc nonce;
    output_binary_int oc (String.length ciphered);
    output_string oc ciphered;
    close_out oc;
  
    Console.st "Verifying wallet.oct...";
    let ic = open_in_bin "wallet.oct" in
    let nonce_len = input_binary_int ic in
    let nonce_read = really_input_string ic nonce_len in
    let cipher_len = input_binary_int ic in
    let cipher_read = really_input_string ic cipher_len in
    close_in ic;
  
    match Mirage_crypto.AES.GCM.authenticate_decrypt ~key ~nonce:nonce_read ~adata:"" cipher_read with
    | None -> 
        Console.e "Failed to decrypt wallet";
        failwith "Decryption failed"
    | Some decrypted ->
        Console.sc "Wallet verified successfully";
        Console.sp ();
        Console.st "Wallet contents:";
        match String.split_on_char '\n' decrypted with
        | [m; priv_hex; pub_hex] ->
            Console.x "Mnemonic" m;
            Console.x "Private Key" priv_hex;
            Console.x "Public Key" pub_hex
        | _ -> 
            Console.e "Invalid wallet format";
            Console.dt ("Found parts: " ^ string_of_int (List.length (String.split_on_char '\n' decrypted)));
            failwith "Invalid wallet format"

let print_network_info seed (nt, nw, ct, ac, ix) =
 let k, ch = derive_for_network 
   seed ~network_type:nt ~network:nw ~contract:ct ~account:ac ~index:ix 
 in
 
 let open P256.Dsa in
 let pk = match priv_of_octets k with
   | Ok x -> x
   | Error _ -> failwith "Invalid derived private key"
 in
 
 let pb = pub_of_priv pk in
 let name = match nt with
   | MainCoin -> "MainCoin"
   | SubCoin n -> "SubCoin " ^ string_of_int n
   | Contract n -> "Contract " ^ string_of_int n
   | Subnet n -> "Subnet " ^ string_of_int n
   | Account n -> "Account " ^ string_of_int n
 in
 
 Console.h (Printf.sprintf "Network: %s" name);
 Console.x "Private Key" (show (of_string k));
 Console.x "Public Key" (show (of_string (pub_to_octets ~compress:false pb)));
 Console.x "Chain Code" (show (of_string ch));
 Console.sep ()

let () =
 Console.s "OCTRA WALLET GENERATION";
 
 Console.h "Initialization";
 Console.st "Setting up RNG...";
 Mirage_crypto_rng_unix.initialize (module Mirage_crypto_rng.Fortuna);
 Console.sc "RNG initialized";
 Console.sp ();

 Console.st "Generating entropy...";
 let entropy = generate_entropy () in
 Console.sc "Entropy generated";
 Console.sp ();

 Console.h "Creating Mnemonic";
 let words = entropy_to_mnemonic entropy in
 let phrase = String.concat " " words in
 Console.dt phrase;

 Console.h "Deriving seed";
 let seed = mnemonic_to_seed words "" in
 let master_priv, master_chain = derive_master_key seed in
 
 let open P256.Dsa in
 let pv = match priv_of_octets master_priv with
   | Ok x -> x
   | Error _ -> failwith "Invalid master key"
 in
 
 let pub = pub_of_priv pv in
 let mpub = pub_to_octets ~compress:false pub in
 
 Console.st "Master keys";
 Console.x "Master Chain" (show (of_string master_chain));
 Console.x "Master Priv" (show (of_string master_priv));
 Console.x "Master Pub" (show (of_string mpub));
 Console.sp ();

 let configs = [
   (MainCoin, 0, 0, 0, 0);
   (SubCoin 1, 0, 0, 0, 0);
   (Contract 1, 0, 1, 0, 0);
   (Subnet 1, 0, 0, 0, 0);
   (Account 1, 0, 0, 0, 0)
 ] in

 List.iter (print_network_info seed) configs;

 Console.h "Saving encrypted wallet (wallet.oct)";
 save_oct phrase master_priv mpub;
 Console.sc "Wallet saved";
 Console.sp ();
 Console.s "COMPLETED"