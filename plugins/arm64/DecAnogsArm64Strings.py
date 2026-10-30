#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDA Pro String Decryption Plugin for ARM64 (AArch64)
Specialized for libanogs.so (Tencent ACE / Anti-Cheat Expert)

Adapted from 32-bit ARM version to full ARM64 support:
- Automatic target function resolution / fallback auto-detection
- Dynamic extraction of STRING_ARRAY_RVA from accessor instructions
- ARM64 instruction decoder for W0/X0 argument loading (including WZR/XZR)
- Static analysis of decryption loops to extract xor_key and increment
- Disassembly and Hex-Rays decompiler commenting with batching optimization
"""

import idaapi
import idc
import ida_kernwin
import ida_funcs
import idautils
import ida_xref
import ida_ua
import ida_bytes
import os
import json

try:
    import ida_hexrays
    HAS_HEXRAYS = ida_hexrays.init_hexrays_plugin()
except Exception:
    HAS_HEXRAYS = False

# Default targets for libanogs.so (ARM64)
# TARGETS[0] returns pointer to encrypted string table (.rodata)
# TARGETS[1] returns pointer to decrypted buffer (.bss / .data)
TARGETS = ["sub_4F6518", "sub_4F652C"]
STRING_ARRAY_RVA = 0x109230


def log(msg):
    """Output message to both IDA message log and standard output."""
    ida_kernwin.msg(msg)
    print(msg, end="")


def resolve_ea(spec):
    """Resolve an address from int, hex string, or function name."""
    if spec is None:
        return idc.BADADDR
    if isinstance(spec, int):
        return spec
    try:
        return int(spec, 0)
    except Exception:
        pass
    ea = idc.get_name_ea_simple(str(spec))
    if ea != idc.BADADDR:
        return ea
    return idc.BADADDR


def is_call_xref(xref_type):
    """Check if xref corresponds to a function call."""
    try:
        return xref_type in (ida_xref.fl_CN, ida_xref.fl_CF)
    except Exception:
        return xref_type in (16, 17)


def extract_string_array_rva(func_ea):
    """
    Extract the string array address by inspecting ADR, ADRL or ADRP+ADD
    instructions in the table accessor function.
    """
    cur = func_ea
    insn = ida_ua.insn_t()
    adrp_val = None
    for _ in range(8):
        if ida_ua.decode_insn(insn, cur) == 0:
            break
        mnem = idc.print_insn_mnem(cur).upper()
        # ADR or ADRL pseudo-instruction in IDA
        if mnem in ("ADR", "ADRL") and insn.ops[1].type in (ida_ua.o_imm, ida_ua.o_near, ida_ua.o_mem):
            return insn.ops[1].value
        # Split ADRP + ADD
        if mnem == "ADRP":
            adrp_val = insn.ops[1].value
        elif mnem == "ADD" and adrp_val is not None:
            if insn.ops[2].type == ida_ua.o_imm:
                return adrp_val + insn.ops[2].value
        cur = idc.next_head(cur)
    return None


def auto_detect_targets():
    """
    Auto-detect TARGETS by finding functions that are called together
    by dozens of common functions and access .rodata.
    """
    candidates = {}
    for f_ea in idautils.Functions():
        f = ida_funcs.get_func(f_ea)
        if not f or (f.end_ea - f.start_ea) > 0x40:
            continue
        xrefs = [xr.frm for xr in idautils.XrefsTo(f_ea, 0) if is_call_xref(xr.type)]
        if len(xrefs) >= 40:
            candidates[f_ea] = set(ida_funcs.get_func(frm).start_ea for frm in xrefs if ida_funcs.get_func(frm))

    # Find pairs with shared callers where at least one accesses .rodata
    rodata_pairs = []
    c_list = list(candidates.keys())
    for i in range(len(c_list)):
        for j in range(i + 1, len(c_list)):
            f0, f1 = c_list[i], c_list[j]
            common = candidates[f0].intersection(candidates[f1])
            if len(common) >= 40:
                rva0, rva1 = extract_string_array_rva(f0), extract_string_array_rva(f1)
                seg0 = idc.get_segm_name(rva0) if rva0 else ""
                seg1 = idc.get_segm_name(rva1) if rva1 else ""
                if "rodata" in seg0.lower() or "rodata" in seg1.lower():
                    pair = [f0, f1] if "rodata" in seg0.lower() else [f1, f0]
                    rodata_pairs.append((len(common), pair))

    if rodata_pairs:
        rodata_pairs.sort(key=lambda x: x[0], reverse=True)
        best_count, best_pair = rodata_pairs[0]
        log(f"[AutoDetect] Found target accessor pair: 0x{best_pair[0]:X}, 0x{best_pair[1]:X} (shared callers: {best_count})\n")
        return best_pair

    # Fallback to general pair search if no rodata match found
    best_pair = None
    best_count = 0
    for i in range(len(c_list)):
        for j in range(i + 1, len(c_list)):
            common = candidates[c_list[i]].intersection(candidates[c_list[j]])
            if len(common) > best_count:
                best_count = len(common)
                best_pair = [c_list[i], c_list[j]]

    if best_pair and best_count >= 40:
        log(f"[AutoDetect] Found fallback accessor pair: 0x{best_pair[0]:X}, 0x{best_pair[1]:X} (shared callers: {best_count})\n")
        return best_pair
    return None


def get_call_arg_imm_arm64(call_ea):
    """
    Trace backwards from call_ea to find the immediate value passed to W0 / X0.
    Handles:
      - MOV  W0, #imm / MOV X0, #imm
      - MOVZ W0, #imm
      - MOVN W0, #imm (bit-inverted immediate)
      - ORR  W0, WZR, #imm
      - MOV  W0, WZR / MOV X0, XZR (0)
    Stops if W0/X0 is clobbered by another operation or across control flow boundaries.
    """
    func = ida_funcs.get_func(call_ea)
    min_ea = func.start_ea if func else max(0, call_ea - 0x100)
    ea = idc.prev_head(call_ea)
    insn = ida_ua.insn_t()

    while ea != idc.BADADDR and ea >= min_ea and (call_ea - ea) <= 0x80:
        if ida_ua.decode_insn(insn, ea) == 0:
            break
        mnem = idc.print_insn_mnem(ea).upper()
        op0 = idc.print_operand(ea, 0).upper()
        op1 = idc.print_operand(ea, 1).upper()

        if mnem in ("MOV", "MOVZ", "MOVN", "ORR") and op0 in ("W0", "X0"):
            if insn.ops[1].type == ida_ua.o_imm:
                val = insn.ops[1].value
                if mnem == "MOVN":
                    val = (~val) & 0xFFFFFFFF
                return val
            elif op1 in ("WZR", "XZR"):
                return 0
            else:
                return None

        # Any other instruction modifying W0/X0 indicates non-immediate argument
        if op0 in ("W0", "X0"):
            return None

        # Stop at control flow boundaries
        if mnem in ("BL", "BLR", "RET"):
            break

        ea = idc.prev_head(ea)
    return None


def get_byte_at_rva(base, rva):
    """Read a single byte from base + rva."""
    try:
        actual_address = base + rva
        byte_data = ida_bytes.get_bytes(actual_address, 1)
        if byte_data is None:
            return None
        return byte_data[0]
    except Exception:
        return None


def decrypt_string(base_address, string_array_rva, main_key, xor_key=None, increment_size=None):
    """
    Execute string decryption algorithm for libanogs.so.
    
    Data format at STRING_ARRAY_RVA + main_key:
      [0]        : Initial key (k0)
      [1]        : Encrypted length (length = byte ^ k0)
      [2..len+1] : Encrypted ciphertext
      [len+2]    : Checksum byte (expected: byte ^ k0 == XOR_SUM(plaintext))
    """
    try:
        xor_key = (xor_key or 0) & 0xFF
        delta = (increment_size or 7) & 0xFF
        src_rva = string_array_rva + main_key

        k0 = get_byte_at_rva(base_address, src_rva + 0)
        if k0 is None:
            return None, "Failed to read k0"

        length_byte = get_byte_at_rva(base_address, src_rva + 1)
        if length_byte is None:
            return None, "Failed to read length"

        length = (length_byte ^ k0) & 0xFF
        if length > 1024:
            return None, f"Length too large ({length})"

        result_storage = []
        k = k0
        for j in range(length):
            enc = get_byte_at_rva(base_address, src_rva + 2 + j)
            if enc is None:
                return None, f"Failed to read byte at offset {j}"
            result_storage.append((enc ^ k) & 0xFF)
            k = (((k + j) & 0xFF) ^ xor_key)
            k = (k + delta) & 0xFF

        check_byte = get_byte_at_rva(base_address, src_rva + 2 + length)
        if check_byte is not None:
            x = 0
            for b in result_storage:
                x ^= b
            ok = ((check_byte ^ k0) & 0xFF) == (x & 0xFF)
        else:
            ok = False

        return bytes(result_storage), "OK" if ok else "CHECKSUM_FAIL"
    except Exception as e:
        return None, str(e)


def bytes_to_string(byte_data):
    """Convert decrypted raw bytes into a readable string."""
    if not byte_data:
        return ""
    if isinstance(byte_data, (list, bytearray)):
        data = bytes(byte_data)
    else:
        data = byte_data

    for encoding in ("utf-8", "gb18030", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return repr(data)[2:-1]


def analyze_decrypt_function_arm64(func_ea):
    """
    Analyze the ARM64 machine code of a decryptor function to extract:
    - xor_key
    - increment (delta)

    Algorithm inspection:
    The inner decryption loop has:
      LDRB  W_val, [X_src, X_j]
      EOR   W_val, W_val, W_k      <-- W_k is the key register
      ADD   W_k, W_k, W_j          <-- k += j
      STRB  W_val, [X_dst, X_j]
      ADD   X_j, X_j, #1           <-- j++
      (optional: EOR W_k, W_k, W_xor / #imm)
      (optional: ADD W_k, W_k, #delta)
      CMP   X_len, X_j
      B.NE  loop_start
    """
    f = ida_funcs.get_func(func_ea)
    if not f:
        return None, None

    cur = f.start_ea
    insns = []
    while cur < f.end_ea:
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, cur) > 0:
            insns.append((cur, idc.print_insn_mnem(cur).upper(), insn))
        cur = idc.next_head(cur)

    # Locate the backwards B.NE loop branch
    bne_insn = None
    for i, (addr, mnem, insn) in enumerate(insns):
        if mnem == "B.NE":
            target = insn.ops[0].addr
            if f.start_ea <= target < addr:
                bne_insn = (addr, target)
                break

    if not bne_insn:
        return None, None

    bne_addr, target_addr = bne_insn
    loop_insns = [x for x in insns if target_addr <= x[0] <= bne_addr]

    # Identify W_k register from: EOR W_val, W_val, W_k
    w_k_reg = None
    for x in loop_insns:
        addr, mnem, insn = x
        if mnem == "EOR" and insn.ops[0].type == ida_ua.o_reg and insn.ops[1].type == ida_ua.o_reg and insn.ops[2].type == ida_ua.o_reg:
            if insn.ops[0].reg == insn.ops[1].reg:
                w_k_reg = insn.ops[2].reg
                break

    xor_key = None
    increment = None

    for x in loop_insns:
        addr, mnem, insn = x
        if w_k_reg is not None and insn.ops[0].reg == w_k_reg and insn.ops[1].reg == w_k_reg:
            # ADD W_k, W_k, #imm
            if mnem == "ADD" and insn.ops[2].type == ida_ua.o_imm:
                increment = insn.ops[2].value
            # EOR W_k, W_k, #imm or reg
            elif mnem == "EOR":
                if insn.ops[2].type == ida_ua.o_imm:
                    xor_key = insn.ops[2].value
                elif insn.ops[2].type == ida_ua.o_reg:
                    xor_reg = insn.ops[2].reg
                    # Find MOV xor_reg, #imm in function
                    for y in insns:
                        if y[1] == "MOV" and y[2].ops[0].reg == xor_reg and y[2].ops[1].type == ida_ua.o_imm:
                            xor_key = y[2].ops[1].value
                            break

    # Default fallback: if increment is not detected in loop, check for single ADD W_k
    if increment is None and w_k_reg is not None:
        for x in loop_insns:
            if x[1] == "ADD" and x[2].ops[0].reg == w_k_reg and x[2].ops[2].type == ida_ua.o_imm:
                increment = x[2].ops[2].value
                break

    return xor_key, increment


def find_functions_with_targets(target_eas):
    """Find all decryptor functions that call all given targets."""
    all_funcs = {}

    def record_xrefs(to_ea):
        new_funcs = []
        for xref in idautils.XrefsTo(to_ea, 0):
            if not is_call_xref(xref.type):
                continue
            call_ea = int(xref.frm)
            f = ida_funcs.get_func(call_ea)
            if f:
                func_start = f.start_ea
                func_name = ida_funcs.get_func_name(func_start) or idc.get_name(func_start) or f"sub_{func_start:X}"
            else:
                func_start = call_ea
                func_name = f"unknown_{call_ea:X}"

            rec = all_funcs.get(func_start)
            if rec is None:
                rec = {"name": func_name, "sites": {}}
                all_funcs[func_start] = rec
                new_funcs.append(func_start)
            rec["sites"].setdefault(to_ea, []).append(call_ea)
        return new_funcs

    for ea in target_eas:
        record_xrefs(ea)

    funcs = {}
    for func_start, rec in all_funcs.items():
        if all(t in rec["sites"] for t in target_eas):
            funcs[func_start] = rec
    return funcs


def find_callers_arm64(func_ea):
    """Find all BL call sites calling func_ea and extract their immediate arguments."""
    callers = []
    for xref in idautils.XrefsTo(func_ea, 0):
        call_ea = int(xref.frm)
        mnem = idc.print_insn_mnem(call_ea).upper()
        if mnem != "BL":
            continue

        f = ida_funcs.get_func(call_ea)
        if f:
            caller_name = ida_funcs.get_func_name(f.start_ea) or idc.get_name(f.start_ea) or f"sub_{f.start_ea:X}"
        else:
            caller_name = f"unknown_{call_ea:X}"

        arg = get_call_arg_imm_arm64(call_ea)
        callers.append((caller_name, call_ea, arg))
    return callers


def set_hexrays_comment(call_ea, comment):
    """Set user comment in Hex-Rays decompiler for a specific call statement."""
    if not HAS_HEXRAYS:
        return False
    try:
        f = ida_funcs.get_func(call_ea)
        if not f:
            return False
        cfunc = ida_hexrays.decompile(f)
        if not cfunc:
            return False
        tl = ida_hexrays.treeloc_t()
        tl.ea = call_ea
        tl.itp = ida_hexrays.ITP_SEMI
        if hasattr(cfunc, "set_user_cmt"):
            cfunc.set_user_cmt(tl, comment)
        elif hasattr(ida_hexrays, "set_user_cmt"):
            ida_hexrays.set_user_cmt(cfunc, tl, comment)
        cfunc.save_user_cmts()
        return True
    except Exception:
        return False


def export_decrypted_strings(export_dir, base_address, string_array_rva, strings_by_offset, calls_list):
    """Export all decrypted strings to formatted TXT and JSON files."""
    try:
        os.makedirs(export_dir, exist_ok=True)
        txt_path = os.path.join(export_dir, "decrypted_strings.txt")
        json_path = os.path.join(export_dir, "decrypted_strings.json")

        sorted_offsets = sorted(strings_by_offset.keys())

        # Write TXT report
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("  DECRYPTED STRINGS LIST - libanogs.so (ARM64-v8a)\n")
            f.write("  Tencent Anti-Cheat Expert (ACE) / Anogs String Table\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"String Table Base RVA: 0x{string_array_rva:X}\n")
            f.write(f"Total Unique Strings:  {len(sorted_offsets)}\n")
            f.write(f"Total Call Sites:      {len(calls_list)}\n\n")
            f.write(f"{'Address':<12} {'Offset':<10} {'Hits':<6} {'String':<40} {'Callers / References'}\n")
            f.write("-" * 120 + "\n")

            for off in sorted_offsets:
                item = strings_by_offset[off]
                rodata_addr = item["rodata_addr"]
                s_val = item["string"]
                clean_str = repr(s_val)[1:-1]
                if len(clean_str) > 38:
                    clean_str = clean_str[:35] + "..."

                call_refs = []
                for ea_str, caller_fn in item["call_sites"][:3]:
                    call_refs.append(f"{caller_fn} ({ea_str})")
                if len(item["call_sites"]) > 3:
                    call_refs.append(f"... (+{len(item['call_sites']) - 3} more)")
                call_str = ", ".join(call_refs)

                f.write(f"{rodata_addr:<12} {item['offset']:<10} x{len(item['call_sites']):<5} {clean_str:<40} {call_str}\n")

        # Write JSON data
        json_data = {
            "binary": "libanogs.so",
            "architecture": "ARM64-v8a",
            "imagebase": hex(base_address),
            "string_array_rva": hex(string_array_rva),
            "total_unique_strings": len(sorted_offsets),
            "total_call_sites": len(calls_list),
            "strings": []
        }

        for off in sorted_offsets:
            item = strings_by_offset[off]
            json_data["strings"].append({
                "offset": item["offset"],
                "offset_dec": off,
                "rodata_address": item["rodata_addr"],
                "string": item["string"],
                "status": item["status"],
                "decryptors": sorted(list(item["decryptors"])),
                "call_count": len(item["call_sites"]),
                "call_sites": [{"call_ea": ea, "caller": fn} for ea, fn in item["call_sites"]]
            })

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, ensure_ascii=False, indent=2)

        log(f"[Export] Saved text table: {txt_path} ({os.path.getsize(txt_path)} bytes)\n")
        log(f"[Export] Saved JSON data:  {json_path} ({os.path.getsize(json_path)} bytes)\n")
    except Exception as e:
        log(f"[Export Error] Failed to write export files: {e}\n")


def main(target_specs=None, custom_string_rva=None, export_dir=None):
    log("=" * 70 + "\n")
    log("  IDA Pro ARM64 String Decryptor for libanogs.so (Anti-Cheat Expert)\n")
    log("=" * 70 + "\n")

    if target_specs is None:
        target_specs = TARGETS

    target_eas = []
    for spec in target_specs:
        ea = resolve_ea(spec)
        if ea != idc.BADADDR:
            target_eas.append(ea)
        else:
            log(f"[Warn] Target symbol not found: {spec}\n")

    if len(target_eas) < 2:
        log("[Info] Attempting target auto-detection...\n")
        detected = auto_detect_targets()
        if detected:
            target_eas = detected
        else:
            log("[Error] Failed to resolve target functions.\n")
            return

    # Extract or verify STRING_ARRAY_RVA
    string_array_rva = custom_string_rva
    if string_array_rva is None:
        string_array_rva = extract_string_array_rva(target_eas[0])
    if string_array_rva is None:
        string_array_rva = STRING_ARRAY_RVA

    base_address = idaapi.get_imagebase()
    log(f"[Config] Targets: {[f'0x{ea:X}' for ea in target_eas]}\n")
    log(f"[Config] Image Base: 0x{base_address:X}\n")
    log(f"[Config] STRING_ARRAY_RVA: 0x{string_array_rva:X} (VA: 0x{base_address + string_array_rva:X})\n")
    log(f"[Config] Hex-Rays Decompiler: {'Available' if HAS_HEXRAYS else 'Not available'}\n\n")

    # Locate all decryptor functions
    decryptors = find_functions_with_targets(target_eas)
    log(f"[FindCalls] Found {len(decryptors)} decryptor wrapper functions.\n")

    if not decryptors:
        log("[Error] No decryptor functions found.\n")
        return

    # Sort decryptors by address for deterministic order
    sorted_decryptors = sorted(decryptors.keys())

    total_callers = 0
    resolved_args = 0
    decrypted_ok = 0
    decrypted_failed = 0

    # Cache decompiler comments by caller function to minimize re-decompilations
    func_comments = {}
    strings_by_offset = {}
    calls_list = []

    for idx, func_start in enumerate(sorted_decryptors):
        rec = decryptors[func_start]
        func_name = rec["name"]

        xor_key, increment = analyze_decrypt_function_arm64(func_start)
        # Fallback to mathematical sequence formula if analysis missed any parameter
        if increment is None:
            increment = 7 - (idx % 7)
        if xor_key is None and idx > 0:
            xor_key = idx

        algo_name = f"v2(xor=0x{xor_key:X}, inc={increment})" if xor_key is not None else f"v1(inc={increment})"

        callers = find_callers_arm64(func_start)
        total_callers += len(callers)

        for caller_name, call_ea, arg in callers:
            if arg is None:
                continue

            resolved_args += 1
            dec_bytes, status = decrypt_string(base_address, string_array_rva, arg, xor_key, increment)

            if dec_bytes is not None and status == "OK":
                decrypted_ok += 1
                dec_str = bytes_to_string(dec_bytes)
                comment_text = f'"{dec_str}" ({algo_name})'
                string_addr = base_address + string_array_rva + arg

                # Track for file export
                calls_list.append({
                    "call_ea": hex(call_ea),
                    "caller_name": caller_name,
                    "decryptor": func_name,
                    "arg": hex(arg),
                    "rodata_addr": hex(string_addr),
                    "string": dec_str
                })
                if arg not in strings_by_offset:
                    strings_by_offset[arg] = {
                        "offset": hex(arg),
                        "offset_int": arg,
                        "rodata_addr": hex(string_addr),
                        "string": dec_str,
                        "status": status,
                        "decryptors": set(),
                        "call_sites": []
                    }
                strings_by_offset[arg]["decryptors"].add(func_name)
                strings_by_offset[arg]["call_sites"].append((hex(call_ea), caller_name))

                # Set comment in disassembly at call instruction
                idc.set_cmt(call_ea, comment_text, 0)

                # Set comment at encrypted string data table offset
                idc.set_cmt(string_addr, comment_text, 0)

                # Queue Hex-Rays comment
                if HAS_HEXRAYS:
                    f = ida_funcs.get_func(call_ea)
                    if f:
                        func_comments.setdefault(f.start_ea, []).append((call_ea, comment_text))
            else:
                decrypted_failed += 1

    # Batch apply Hex-Rays decompiler comments
    if HAS_HEXRAYS and func_comments:
        log(f"[Hex-Rays] Applying decompilation comments across {len(func_comments)} functions...\n")
        applied_hx = 0
        for f_start, cmts in func_comments.items():
            f = ida_funcs.get_func(f_start)
            if not f:
                continue
            try:
                cfunc = ida_hexrays.decompile(f)
                if not cfunc:
                    continue
                for call_ea, cmt_text in cmts:
                    tl = ida_hexrays.treeloc_t()
                    tl.ea = call_ea
                    tl.itp = ida_hexrays.ITP_SEMI
                    if hasattr(cfunc, "set_user_cmt"):
                        cfunc.set_user_cmt(tl, cmt_text)
                    elif hasattr(ida_hexrays, "set_user_cmt"):
                        ida_hexrays.set_user_cmt(cfunc, tl, cmt_text)
                    applied_hx += 1
                cfunc.save_user_cmts()
            except Exception:
                pass
        log(f"[Hex-Rays] Successfully applied {applied_hx} comments to decompiled C code!\n")

    # Export strings to files if export_dir is provided or auto-detected
    if export_dir is None:
        script_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else ""
        search_dirs = [
            os.path.abspath(os.path.join(script_dir, "..", "..", "dumps", "arm64")),
            os.path.abspath(os.path.join(script_dir, "..", "dumps", "arm64")),
            os.path.abspath(os.path.join(script_dir, "dumps", "arm64")),
            os.path.abspath(os.path.join(script_dir, "..", "docs")),
            os.path.abspath("dumps/arm64"),
            os.path.abspath("docs")
        ]
        for cand in search_dirs:
            if os.path.isdir(cand):
                export_dir = cand
                break

    if export_dir and strings_by_offset:
        log(f"\n[Export] Saving decrypted strings to '{export_dir}'...\n")
        export_decrypted_strings(export_dir, base_address, string_array_rva, strings_by_offset, calls_list)

    log("\n" + "=" * 70 + "\n")
    log("  Decryption Summary\n")
    log("=" * 70 + "\n")
    log(f"  Decryptor functions found:   {len(decryptors)}\n")
    log(f"  Total BL call sites:         {total_callers}\n")
    log(f"  Arguments resolved:          {resolved_args} ({resolved_args*100.0/max(1, total_callers):.1f}%)\n")
    log(f"  Strings decrypted (OK):      {decrypted_ok}\n")
    log(f"  Checksum mismatches/errors:  {decrypted_failed}\n")
    log("=" * 70 + "\n")
    log("[Done] String decryption completed successfully!\n")


if __name__ == "__main__":
    main()
