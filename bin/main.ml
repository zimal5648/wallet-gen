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
open Helpers

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

let bip39_wordlist =
  let file = "data/english.txt" in
  if not (Sys.file_exists file) then failwith ("File not found: " ^ file);

  let ic = open_in file in
  let rec loop acc =
    match input_line ic with
    | line -> loop (line :: acc)
    | exception End_of_file ->
        close_in ic;
        List.rev acc
  in
  Array.of_list (List.map String.trim (loop []))

let generate_entropy () = Mirage_crypto_rng.generate 16

let take n lst =
  let rec aux acc k xs =
    if k = 0 then List.rev acc
    else
      match xs with [] -> List.rev acc | y :: ys -> aux (y :: acc) (k - 1) ys
  in
  aux [] n lst

let drop n lst =
  let rec aux k xs =
    if k = 0 then xs else match xs with [] -> [] | _ :: ys -> aux (k - 1) ys
  in
  aux n lst

let entropy_to_mnemonic e =
  let open Digestif in
  let cb = SHA256.digest_string e in
  let cbyte = int_of_char (SHA256.to_raw_string cb).[0] in
  let csum = cbyte lsr 4 in

  let to_bits b =
    let rec lp acc i =
      if i >= 8 then acc else lp (((b lsr i) land 1) :: acc) (i + 1)
    in
    lp [] 0
  in

  let e_bits =
    List.flatten
      (List.init (String.length e) (fun i -> to_bits (int_of_char e.[i])))
  in

  let c_bits = List.init 4 (fun i -> (csum lsr (3 - i)) land 1) in
  let bits = e_bits @ c_bits in

  let rec tk11 bs acc =
    match bs with
    | [] -> List.rev acc
    | _ ->
        let part = take 11 bs in
        let idx = List.fold_left (fun n b -> (n * 2) + b) 0 part in
        tk11 (drop 11 bs) (bip39_wordlist.(idx) :: acc)
  in
  tk11 bits []

let mnemonic_to_seed words passphrase =
  let password = String.concat " " words in
  let salt = "mnemonic" ^ passphrase in

  let rec iter prev i acc =
    if i = 0 then acc
    else
      let nx = hs ~key:password prev in
      let acc =
        string_map2 (fun x y -> Char.chr (Char.code x lxor Char.code y)) acc nx
      in
      iter nx (i - 1) acc
  in

  let rec blocks n acc =
    if String.length acc >= 64 then String.sub acc 0 64
    else
      let block_data =
        salt ^ String.make 3 '\x00' ^ String.make 1 (Char.chr (n land 0xff))
      in
      let first = hs ~key:password block_data in
      let block = iter first 2047 first in
      blocks (n + 1) (acc ^ block)
  in
  blocks 1 ""

let derive_master_key seed =
  let h = hs ~key:"Octra seed" seed in
  (String.sub h 0 32, String.sub h 32 32)

let derive_child_key (key, chain) i =
  let open P256.Dsa in
  let pk =
    match priv_of_octets key with
    | Ok x -> x
    | Error _ -> failwith "Invalid private key"
  in

  let d =
    if i land 0x80000000 <> 0 then String.make 1 '\x00' ^ key
    else pub_to_octets ~compress:false (pub_of_priv pk)
  in

  let d = d ^ String.make 4 '\x00' in
  let d =
    String.sub d 0 (String.length d - 1)
    ^ String.make 1 (Char.chr (i land 0xff))
  in

  let h = hs ~key:chain d in
  (String.sub h 0 32, String.sub h 32 32)

let derive_path seed path =
  let rec loop (k, c) = function
    | [] -> (k, c)
    | x :: xs ->
        let ck, ch = derive_child_key (k, c) x in
        loop (ck, ch) xs
  in
  loop (derive_master_key seed) path

let derive_for_network ?(token = 0) ?(subnet = 0) seed ~network_type ~network
    ~contract ~account ~index =
  let base_path =
    [
      0x80000000 lor 345;
      0x80000000 lor get_coin_type network_type;
      0x80000000 lor network;
    ]
  in
  let contract_path = [ 0x80000000 lor contract; 0x80000000 lor account ] in
  let optional_path = [ 0x80000000 lor token; 0x80000000 lor subnet ] in
  let final_path = [ index ] in
  let path = base_path @ contract_path @ optional_path @ final_path in
  derive_path seed path

let save_oct mnemonic master_priv master_pub =
  let pass = get_password () in

  let secret = slow_pbkdf pass 1 "" in
  let key_length = 32 in
  let key = Mirage_crypto.AES.GCM.of_secret (String.sub secret 0 key_length) in
  let nonce = Mirage_crypto_rng.generate 12 in
  let hex_priv = Hex.show (Hex.of_string master_priv) in
  let hex_pub = Hex.show (Hex.of_string master_pub) in
  let msg = String.concat "\n" [ mnemonic; hex_priv; hex_pub ] in

  let ciphered =
    Mirage_crypto.AES.GCM.authenticate_encrypt ~key ~nonce ~adata:"" msg
  in

  let oc = open_out_bin "wallet.oct" in
  output_binary_int oc (String.length nonce);
  output_string oc nonce;
  output_binary_int oc (String.length ciphered);
  output_string oc ciphered;
  close_out oc

let print_network_info seed (nt, nw, ct, ac, ix) =
  let k, ch =
    derive_for_network seed ~network_type:nt ~network:nw ~contract:ct
      ~account:ac ~index:ix
  in

  let open P256.Dsa in
  let pk =
    match priv_of_octets k with
    | Ok x -> x
    | Error _ -> failwith "Invalid derived private key"
  in

  let pb = pub_of_priv pk in
  let name =
    match nt with
    | MainCoin -> "MainCoin"
    | SubCoin n -> "SubCoin " ^ string_of_int n
    | Contract n -> "Contract " ^ string_of_int n
    | Subnet n -> "Subnet " ^ string_of_int n
    | Account n -> "Account " ^ string_of_int n
  in

  Console.h (Printf.sprintf "Network: %s" name);
  Console.x "Chain Code" (show (of_string ch));
  Console.x "Private Key" (show (of_string k));
  Console.x "Public Key" (show (of_string (pub_to_octets ~compress:false pb)));
  Console.sep ()

let () =
  Console.s "OCTRA WALLET GENERATION";

  Console.h "Initialization";
  Console.st "Setting up RNG...";
  Mirage_crypto_rng_unix.initialize (module Mirage_crypto_rng.Fortuna);
  Console.sc "RNG initialized";

  Console.st "Generating entropy...";
  let entropy = generate_entropy () in
  Console.sc "Entropy generated";

  Console.st "Creating Mnemonic...";
  let words = entropy_to_mnemonic entropy in
  let phrase = String.concat " " words in
  Console.sc "Mnemonic created";

  let seed = mnemonic_to_seed words "" in
  let master_priv, master_chain = derive_master_key seed in

  let open P256.Dsa in
  let pv =
    match priv_of_octets master_priv with
    | Ok x -> x
    | Error _ -> failwith "Invalid master key"
  in

  let pub = pub_of_priv pv in
  let mpub = pub_to_octets ~compress:false pub in

  let configs =
    [
      (MainCoin, 0, 0, 0, 0);
      (SubCoin 1, 0, 0, 0, 0);
      (Contract 1, 0, 1, 0, 0);
      (Subnet 1, 0, 0, 0, 0);
      (Account 1, 0, 0, 0, 0);
    ]
  in

  List.iter (print_network_info seed) configs;

  Console.h "Saving encrypted wallet";
  save_oct phrase master_priv mpub;
  Console.sc "Wallet saved in ./wallet.oct";

  Console.st "Wallet contents:";
  Console.x "Mnemonic" phrase;
  Console.x "Private Key" (show (of_string master_priv));
  Console.x "Public Key" (show (of_string mpub));

  Console.s "COMPLETED"
