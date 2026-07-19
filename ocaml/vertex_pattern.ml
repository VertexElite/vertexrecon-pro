(* ═══════════════════════════════════════════════════════════════
   VERTEX-PATTERN — OCaml Binary Pattern Matcher
   Signature scanning, hex pattern matching, entropy sectioning,
   structure anomaly detection, format identification
   ═══════════════════════════════════════════════════════════════ *)

let red    = "\027[0;31m"
let green  = "\027[0;32m"
let yellow = "\027[1;33m"
let cyan   = "\027[0;36m"
let purple = "\027[0;35m"
let bold   = "\027[1m"
let rst    = "\027[0m"

(* ─── File magic signatures ─────────────────────────────────── *)

type file_sig = {
  name: string;
  magic: int list;
  offset: int;
  risk: string; (* none, low, medium, high *)
}

let signatures = [
  { name = "ELF Binary";         magic = [0x7F; 0x45; 0x4C; 0x46]; offset = 0; risk = "medium" };
  { name = "PE/Windows EXE";     magic = [0x4D; 0x5A];             offset = 0; risk = "high" };
  { name = "Mach-O (64-bit)";    magic = [0xCF; 0xFA; 0xED; 0xFE]; offset = 0; risk = "medium" };
  { name = "Mach-O (32-bit)";    magic = [0xCE; 0xFA; 0xED; 0xFE]; offset = 0; risk = "medium" };
  { name = "Java Class";         magic = [0xCA; 0xFE; 0xBA; 0xBE]; offset = 0; risk = "medium" };
  { name = "DEX (Android)";      magic = [0x64; 0x65; 0x78; 0x0A]; offset = 0; risk = "medium" };
  { name = "ZIP/APK/JAR";        magic = [0x50; 0x4B; 0x03; 0x04]; offset = 0; risk = "low" };
  { name = "RAR Archive";        magic = [0x52; 0x61; 0x72; 0x21]; offset = 0; risk = "low" };
  { name = "GZIP";               magic = [0x1F; 0x8B];             offset = 0; risk = "none" };
  { name = "7z Archive";         magic = [0x37; 0x7A; 0xBC; 0xAF]; offset = 0; risk = "low" };
  { name = "PDF";                magic = [0x25; 0x50; 0x44; 0x46]; offset = 0; risk = "low" };
  { name = "PNG Image";          magic = [0x89; 0x50; 0x4E; 0x47]; offset = 0; risk = "none" };
  { name = "JPEG Image";         magic = [0xFF; 0xD8; 0xFF];       offset = 0; risk = "none" };
  { name = "GIF Image";          magic = [0x47; 0x49; 0x46; 0x38]; offset = 0; risk = "none" };
  { name = "SQLite DB";          magic = [0x53; 0x51; 0x4C; 0x69]; offset = 0; risk = "low" };
  { name = "Shell Script";       magic = [0x23; 0x21; 0x2F];       offset = 0; risk = "low" };
]

(* Malware-specific byte patterns *)
type threat_sig = {
  threat_name: string;
  pattern: int list;
  description: string;
}

let threat_patterns = [
  { threat_name = "Metasploit Shellcode (x86)";
    pattern = [0x31; 0xC0; 0x50; 0x68; 0x2F; 0x2F; 0x73; 0x68];
    description = "xor eax,eax; push eax; push '//sh'" };
  { threat_name = "Metasploit Shellcode (x64)";
    pattern = [0x48; 0x31; 0xF6; 0x56; 0x48; 0xBF; 0x2F; 0x62];
    description = "xor rsi,rsi; push rsi; movabs rdi,'/b'" };
  { threat_name = "Cobalt Strike Beacon";
    pattern = [0xFC; 0x48; 0x83; 0xE4; 0xF0; 0xE8];
    description = "Classic CS stager prologue" };
  { threat_name = "PHP Webshell";
    pattern = [0x3C; 0x3F; 0x70; 0x68; 0x70; 0x20; 0x65; 0x76; 0x61; 0x6C];
    description = "<?php eval" };
  { threat_name = "Base64 Exec Pattern";
    pattern = [0x62; 0x61; 0x73; 0x65; 0x36; 0x34; 0x20; 0x2D; 0x64];
    description = "base64 -d" };
  { threat_name = "Reverse Shell Pattern";
    pattern = [0x2F; 0x64; 0x65; 0x76; 0x2F; 0x74; 0x63; 0x70; 0x2F];
    description = "/dev/tcp/" };
  { threat_name = "LD_PRELOAD Hijack";
    pattern = [0x4C; 0x44; 0x5F; 0x50; 0x52; 0x45; 0x4C; 0x4F; 0x41; 0x44];
    description = "LD_PRELOAD" };
  { threat_name = "Ptrace Anti-Debug";
    pattern = [0x70; 0x74; 0x72; 0x61; 0x63; 0x65];
    description = "ptrace call (anti-debugging)" };
]

(* ─── Byte utilities ──────────────────────────────────────── *)

let read_file path =
  let ic = open_in_bin path in
  let n = in_channel_length ic in
  let buf = Bytes.create n in
  really_input ic buf 0 n;
  close_in ic;
  Bytes.to_string buf

let byte_at s i = Char.code (String.get s i)

let matches_at data offset pattern =
  let len = List.length pattern in
  if offset + len > String.length data then false
  else
    let rec check i = function
      | [] -> true
      | b :: rest ->
        if byte_at data (offset + i) = b then check (i + 1) rest
        else false
    in
    check 0 pattern

(* ─── Shannon entropy ─────────────────────────────────────── *)

let shannon_entropy data =
  let len = String.length data in
  if len = 0 then 0.0
  else begin
    let freq = Array.make 256 0 in
    String.iter (fun c -> freq.(Char.code c) <- freq.(Char.code c) + 1) data;
    let flen = float_of_int len in
    Array.fold_left (fun acc count ->
      if count = 0 then acc
      else
        let p = float_of_int count /. flen in
        acc -. p *. (log p /. log 2.0)
    ) 0.0 freq
  end

let entropy_color e =
  if e > 7.5 then red
  else if e > 6.5 then yellow
  else if e > 4.0 then green
  else cyan

let entropy_label e =
  if e > 7.5 then "PACKED/ENCRYPTED"
  else if e > 6.5 then "HIGH (compressed/encoded)"
  else if e > 4.0 then "NORMAL"
  else "LOW (mostly text)"

(* ─── Hex pattern search ──────────────────────────────────── *)

let hex_search data pattern_hex =
  (* Convert hex string like "7f454c46" to int list *)
  let hex_to_bytes hex_str =
    let len = String.length hex_str in
    let rec parse i acc =
      if i >= len then List.rev acc
      else
        let byte = int_of_string ("0x" ^ String.sub hex_str i 2) in
        parse (i + 2) (byte :: acc)
    in
    parse 0 []
  in
  let pattern = hex_to_bytes pattern_hex in
  let results = ref [] in
  for i = 0 to String.length data - List.length pattern do
    if matches_at data i pattern then
      results := i :: !results
  done;
  List.rev !results

(* ─── File identification ─────────────────────────────────── *)

let identify_file data =
  List.filter (fun sig ->
    matches_at data sig.offset sig.magic
  ) signatures

(* ─── Threat scan ─────────────────────────────────────────── *)

let scan_threats data =
  let findings = ref [] in
  List.iter (fun threat ->
    let offsets = ref [] in
    for i = 0 to String.length data - List.length threat.pattern do
      if matches_at data i threat.pattern then
        offsets := i :: !offsets
    done;
    if !offsets <> [] then
      findings := (threat, List.rev !offsets) :: !findings
  ) threat_patterns;
  List.rev !findings

(* ─── Section entropy map ─────────────────────────────────── *)

let entropy_map data block_size =
  let len = String.length data in
  let blocks = ref [] in
  let i = ref 0 in
  while !i + block_size <= len do
    let section = String.sub data !i block_size in
    let ent = shannon_entropy section in
    blocks := (!i, ent) :: !blocks;
    i := !i + block_size
  done;
  (* Handle remainder *)
  if !i < len then begin
    let section = String.sub data !i (len - !i) in
    let ent = shannon_entropy section in
    blocks := (!i, ent) :: !blocks
  end;
  List.rev !blocks

(* ─── Display functions ───────────────────────────────────── *)

let section title =
  Printf.printf "\n%s══════════════════════════════════════════════════%s\n" green rst;
  Printf.printf "%s  %s%s\n" green title rst;
  Printf.printf "%s══════════════════════════════════════════════════%s\n" green rst

let print_hex_dump data offset length =
  let actual_len = min length (String.length data - offset) in
  let i = ref 0 in
  while !i < actual_len do
    Printf.printf "    %08X  " (offset + !i);
    (* Hex bytes *)
    for j = 0 to 15 do
      if !i + j < actual_len then
        Printf.printf "%02X " (byte_at data (offset + !i + j))
      else
        Printf.printf "   "
    done;
    Printf.printf " |";
    (* ASCII *)
    for j = 0 to 15 do
      if !i + j < actual_len then begin
        let b = byte_at data (offset + !i + j) in
        if b >= 0x20 && b < 0x7F then
          Printf.printf "%c" (Char.chr b)
        else
          Printf.printf "."
      end
    done;
    Printf.printf "|\n";
    i := !i + 16
  done

(* ─── Main analysis ──────────────────────────────────────── *)

let analyze_file path =
  let data = read_file path in
  let len = String.length data in

  Printf.printf "\n%sVERTEX-PATTERN%s — Binary Analysis\n" purple rst;
  Printf.printf "  File: %s%s%s\n" bold path rst;
  Printf.printf "  Size: %d bytes\n" len;

  (* File identification *)
  section "FILE IDENTIFICATION";
  let types = identify_file data in
  if types = [] then
    Printf.printf "  %s[?]%s Unknown file format\n" yellow rst
  else
    List.iter (fun sig ->
      let risk_color = match sig.risk with
        | "high" -> red | "medium" -> yellow | "low" -> cyan | _ -> green in
      Printf.printf "  %s[→]%s %s (risk: %s%s%s)\n" yellow rst sig.name risk_color sig.risk rst
    ) types;

  (* Overall entropy *)
  section "ENTROPY ANALYSIS";
  let ent = shannon_entropy data in
  let ec = entropy_color ent in
  Printf.printf "  Overall: %s%.4f%s bits/byte — %s%s%s\n" ec ent rst ec (entropy_label ent) rst;

  (* Entropy map *)
  let block_size = 4096 in
  let blocks = entropy_map data block_size in
  let num_blocks = List.length blocks in
  Printf.printf "  Blocks: %d x %d bytes\n\n" num_blocks block_size;

  (* Visual entropy bar chart *)
  Printf.printf "  %sEntropy Map:%s\n" bold rst;
  List.iter (fun (offset, e) ->
    let bar_len = int_of_float (e *. 6.0) in
    let bar = String.make bar_len '#' in
    let ec = entropy_color e in
    Printf.printf "    0x%06X |%s%-42s%s| %.3f\n" offset ec bar rst e
  ) blocks;

  (* Flag high-entropy sections *)
  let high_blocks = List.filter (fun (_, e) -> e > 7.5) blocks in
  if high_blocks <> [] then begin
    Printf.printf "\n  %s[!] High-entropy sections (possible encryption/packing):%s\n" red rst;
    List.iter (fun (offset, e) ->
      Printf.printf "    Offset 0x%06X: %.4f\n" offset e;
      print_hex_dump data offset 64
    ) high_blocks
  end;

  (* Threat signature scan *)
  section "THREAT SIGNATURE SCAN";
  let threats = scan_threats data in
  if threats = [] then
    Printf.printf "  %s[✓] No known threat signatures detected%s\n" green rst
  else begin
    Printf.printf "  %s[!] %d threat signature(s) matched:%s\n" red (List.length threats) rst;
    List.iter (fun (threat, offsets) ->
      Printf.printf "\n  %s%s%s — %s\n" red threat.threat_name rst threat.description;
      List.iter (fun offset ->
        Printf.printf "    Found at offset 0x%06X:\n" offset;
        print_hex_dump data offset 32
      ) offsets
    ) threats
  end;

  (* String analysis *)
  section "INTERESTING STRINGS";
  let strings = ref [] in
  let current = Buffer.create 64 in
  let current_start = ref 0 in
  for i = 0 to len - 1 do
    let b = byte_at data i in
    if b >= 0x20 && b < 0x7F then begin
      if Buffer.length current = 0 then current_start := i;
      Buffer.add_char current (Char.chr b)
    end else begin
      if Buffer.length current >= 8 then
        strings := (!current_start, Buffer.contents current) :: !strings;
      Buffer.clear current
    end
  done;
  let all_strings = List.rev !strings in

  let suspicious_keywords = [
    "password"; "passwd"; "shadow"; "token"; "secret"; "api_key";
    "/bin/sh"; "/bin/bash"; "eval("; "exec("; "system(";
    "base64"; "wget"; "curl"; "reverse"; "shell"; "payload";
    "C2"; "beacon"; "callback"; "exfil"; "dropper";
    "LD_PRELOAD"; "ptrace"; "mprotect"; "/dev/tcp";
  ] in

  let sus_strings = List.filter (fun (_, s) ->
    let lower = String.lowercase_ascii s in
    List.exists (fun kw -> 
      try let _ = Str.search_forward (Str.regexp_string (String.lowercase_ascii kw)) lower 0 in true
      with Not_found -> false
    ) suspicious_keywords
  ) all_strings in

  Printf.printf "  Total strings (≥8 chars): %d\n" (List.length all_strings);
  Printf.printf "  Suspicious matches: %s%d%s\n" 
    (if sus_strings <> [] then red else green) (List.length sus_strings) rst;

  if sus_strings <> [] then begin
    Printf.printf "\n  %sFlagged strings:%s\n" bold rst;
    List.iter (fun (offset, s) ->
      let display = if String.length s > 80 then String.sub s 0 80 ^ "..." else s in
      Printf.printf "  %s[0x%06X]%s %s\n" yellow offset rst display
    ) sus_strings
  end;

  Printf.printf "\n"

let scan_hex_pattern path pattern_hex =
  let data = read_file path in
  section (Printf.sprintf "HEX PATTERN SEARCH: %s" pattern_hex);
  let results = hex_search data pattern_hex in
  if results = [] then
    Printf.printf "  %s[✓] Pattern not found%s\n" green rst
  else begin
    Printf.printf "  %s[!] Found %d occurrence(s):%s\n" yellow (List.length results) rst;
    List.iter (fun offset ->
      Printf.printf "    Offset 0x%06X:\n" offset;
      print_hex_dump data offset 48
    ) results
  end

(* ─── CLI ─────────────────────────────────────────────────── *)

let () =
  let args = Sys.argv in
  if Array.length args < 2 then begin
    Printf.printf "\n%sVERTEX-PATTERN%s — OCaml Binary Pattern Matcher\n\n" purple rst;
    Printf.printf "Usage:\n";
    Printf.printf "  vertex-pattern analyze <file>           Full binary analysis\n";
    Printf.printf "  vertex-pattern entropy <file>           Entropy analysis only\n";
    Printf.printf "  vertex-pattern threats <file>           Threat signature scan\n";
    Printf.printf "  vertex-pattern hex <file> <hex_pattern> Search hex pattern\n";
    Printf.printf "  vertex-pattern identify <file>          File type identification\n\n"
  end else
    let cmd = args.(1) in
    match cmd with
    | "analyze" when Array.length args >= 3 ->
      analyze_file args.(2)
    | "entropy" when Array.length args >= 3 ->
      let data = read_file args.(2) in
      section "ENTROPY ANALYSIS";
      let blocks = entropy_map data 4096 in
      List.iter (fun (offset, e) ->
        let ec = entropy_color e in
        Printf.printf "  0x%06X: %s%.4f%s %s\n" offset ec e rst (entropy_label e)
      ) blocks
    | "threats" when Array.length args >= 3 ->
      let data = read_file args.(2) in
      section "THREAT SCAN";
      let threats = scan_threats data in
      if threats = [] then
        Printf.printf "  %s[✓] Clean%s\n" green rst
      else
        List.iter (fun (t, offsets) ->
          Printf.printf "  %s[!] %s%s at offsets: %s\n" red t.threat_name rst
            (String.concat ", " (List.map (Printf.sprintf "0x%X") offsets))
        ) threats
    | "hex" when Array.length args >= 4 ->
      scan_hex_pattern args.(2) args.(3)
    | "identify" when Array.length args >= 3 ->
      let data = read_file args.(2) in
      let types = identify_file data in
      List.iter (fun s -> Printf.printf "  %s (risk: %s)\n" s.name s.risk) types
    | _ ->
      Printf.eprintf "Unknown command or missing args: %s\n" cmd
