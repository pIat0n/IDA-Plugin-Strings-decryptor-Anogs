import idaapi
import idc
import ida_kernwin
import ida_funcs
import idautils
import ida_xref
import ida_ua
import ida_bytes

TARGETS = ["sub_38D534", "sub_38D548"]
STRING_ARRAY_RVA = 0xCB964
PARTIAL_KEY_RVA = 0x3F08A0

def resolve_ea(spec):
    if spec is None:
        return idc.BADADDR
    if isinstance(spec, int):
        return spec
    try:
        return int(spec, 0)
    except Exception:
        pass
    return idc.get_name_ea_simple(spec)

def is_call_xref(xref_type):
    try:
        return xref_type in (ida_xref.fl_CN, ida_xref.fl_CF)
    except Exception:
        return xref_type in (16, 17)

def get_call_arg_imm(call_ea):
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, call_ea) == 0:
        return None
    ea = idc.prev_head(call_ea)
    movw_val = None
    movt_val = None
    while ea != idc.BADADDR and call_ea - ea < 0x20:
        if ida_ua.decode_insn(insn, ea) == 0:
            break
        mnem = idc.print_insn_mnem(ea).upper()
        if mnem.startswith("MOV") and insn.ops[0].reg == 0:
            if insn.ops[1].type == ida_ua.o_imm:
                val = insn.ops[1].value
                if mnem.startswith("MOVW"):
                    movw_val = val & 0xFFFF
                else:
                    return val
        elif mnem.startswith("MOVT") and insn.ops[0].reg == 0:
            if insn.ops[1].type == ida_ua.o_imm:
                movt_val = insn.ops[1].value & 0xFFFF
        if movw_val is not None and movt_val is not None:
            return (movt_val << 16) | movw_val
        if movw_val is not None and movt_val is None:
            return movw_val
        ea = idc.prev_head(ea)
    return None

def get_byte_at_rva(base, rva):
    try:
        actual_address = base + rva
        byte_data = ida_bytes.get_bytes(actual_address, 1)
        if byte_data is None:
            return None
        return byte_data[0]
    except:
        return None

def decrypt_string(base_address, main_key, xor_key=None, increment_size=None):
    try:
        xor_key = (xor_key or 0) & 0xFF
        delta = (increment_size or 7) & 0xFF
        src_rva = STRING_ARRAY_RVA + main_key
        k0 = get_byte_at_rva(base_address, src_rva + 0)
        if k0 is None:
            return None, "Failed to read k0"
        length_byte = get_byte_at_rva(base_address, src_rva + 1)
        if length_byte is None:
            return None, "Failed to read length"
        length = (length_byte ^ k0) & 0xFF
        if length > 500:
            return None, "Length too large"
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
        return result_storage[:length], "OK" if ok else "CHECKSUM_FAIL"
    except Exception as e:
        return None, str(e)

def bytes_to_string(byte_data):
    if not byte_data:
        return ""
    try:
        data = bytes(byte_data)
        for encoding in ['utf-8', 'cp1251', 'latin-1']:
            try:
                return data.decode(encoding)
            except UnicodeDecodeError:
                continue
        return data.hex()
    except:
        return str(byte_data)

def analyze_decrypt_function(func_ea):
    xor_key = None
    increment = None
    func = ida_funcs.get_func(func_ea)
    if not func:
        return xor_key, increment
    ea = func.start_ea
    insn = ida_ua.insn_t()
    try:
        while ea < func.end_ea:
            if ida_ua.decode_insn(insn, ea) == 0:
                ea = idc.next_head(ea)
                continue
            mnem = idc.print_insn_mnem(ea).upper()
            if mnem == "EOR" or mnem.startswith("EOR."):
                try:
                    if hasattr(insn.ops[2], 'type') and insn.ops[2].type == ida_ua.o_imm:
                        xor_key = insn.ops[2].value
                    elif hasattr(insn.ops[1], 'type') and insn.ops[1].type == ida_ua.o_imm:
                        xor_key = insn.ops[1].value
                except:
                    pass
            elif mnem == "ADDS":
                try:
                    if hasattr(insn.ops[2], 'type') and insn.ops[2].type == ida_ua.o_imm:
                        potential_increment = insn.ops[2].value
                        context_found = False
                        check_start = max(ea - 0x30, func.start_ea)
                        check_end = min(ea + 0x20, func.end_ea)
                        temp_ea = check_start
                        while temp_ea <= check_end:
                            try:
                                temp_mnem = idc.print_insn_mnem(temp_ea).upper()
                                if (temp_mnem.startswith("EOR") or 
                                    temp_mnem == "LDRB" or 
                                    temp_mnem == "STRB" or
                                    temp_mnem == "CMP" or
                                    temp_mnem == "BNE"):
                                    context_found = True
                                    break
                            except:
                                pass
                            temp_ea = idc.next_head(temp_ea)
                        if context_found and potential_increment < 20:
                            increment = potential_increment
                except:
                    pass
            ea = idc.next_head(ea)
    except Exception as e:
        ida_kernwin.msg("[Error] Ошибка при анализе функции 0x%X: %s\n" % (func_ea, str(e)))
    return xor_key, increment

def find_functions_with_targets(target_eas):
    all_funcs = {}
    def record_xrefs(to_ea):
        new_funcs = []
        for xref in idautils.XrefsTo(to_ea, 0):
            if not is_call_xref(xref.type):
                continue
            call_ea = xref.frm
            try:
                if hasattr(idaapi, "is_call_insn") and not idaapi.is_call_insn(call_ea):
                    continue
            except Exception:
                pass
            f = ida_funcs.get_func(call_ea)
            if f:
                func_start = f.start_ea
                func_name = (ida_funcs.get_func_name(func_start)
                             or idc.get_name(func_start)
                             or "sub_%X" % func_start)
            else:
                func_start = call_ea
                func_name = "unknown_%X" % call_ea
            rec = all_funcs.get(func_start)
            if rec is None:
                rec = {"name": func_name, "sites": {}}
                all_funcs[func_start] = rec
                new_funcs.append(func_start)
            rec["sites"].setdefault(to_ea, []).append(call_ea)
        return new_funcs
    frontier = []
    for ea in target_eas:
        frontier += record_xrefs(ea)
        frontier += record_xrefs(ea | 1)
    seen = set(frontier)
    while frontier:
        next_frontier = []
        for fstart in frontier:
            next_frontier += record_xrefs(fstart)
            next_frontier += record_xrefs(fstart | 1)
        next_frontier = [f for f in next_frontier if f not in seen]
        seen.update(next_frontier)
        frontier = next_frontier
    funcs = {}
    for func_start, rec in all_funcs.items():
        if all(t in rec["sites"] for t in target_eas):
            funcs[func_start] = rec
    return funcs

def find_callers(func_ea):
    callers = []
    for xref in idautils.XrefsTo(func_ea, 0):
        if not is_call_xref(xref.type):
            continue
        call_ea = xref.frm
        f = ida_funcs.get_func(call_ea)
        if f:
            caller_name = ida_funcs.get_func_name(f.start_ea) or idc.get_name(f.start_ea) or "sub_%X" % f.start_ea
            caller_id = f.start_ea
        else:
            caller_name = "unknown_%X" % call_ea
            caller_id = call_ea
        arg = get_call_arg_imm(call_ea)
        callers.append((caller_name, caller_id, arg))
    return callers

def main(target_specs=None):
    if target_specs is None:
        target_specs = TARGETS
    target_eas = []
    for spec in target_specs:
        ea = resolve_ea(spec)
        if ea is None or ea == idc.BADADDR:
            ida_kernwin.msg("[FindBothCalls] Не удалось найти адрес для '%s'\n" % spec)
            continue
        target_eas.append(ea)

    funcs = find_functions_with_targets(target_eas)
    if not funcs:
        ida_kernwin.msg("[FindBothCalls] Не найдено функций, где вызываются все цели.\n")
        return

    base_address = idaapi.get_imagebase()

    decoder_well = 0
    decoder_unknown = 0
    caller_well = 0
    caller_unknown = 0

    for func_start, rec in funcs.items():
        func_name = rec["name"]
        xor_key, increment = analyze_decrypt_function(func_start)

        if func_name.startswith("unknown_"):
            decoder_unknown += 1
        else:
            decoder_well += 1

        decrypt_info = []
        decrypt_info.append("xor_key=0x%X" % xor_key if xor_key is not None else "xor_key=None")
        decrypt_info.append("increment=%d" % increment if increment is not None else "increment=None")
        decrypt_params = ", ".join(decrypt_info)

        callers = find_callers(func_start)

        if not callers:
            ida_kernwin.msg("%s @ 0x%X (%s) used in - <no callers>\n"
                            % (func_name, func_start, decrypt_params))
        else:
            caller_strings = []
            for name, ea, arg in callers:
                if name.startswith("unknown_"):
                    caller_unknown += 1
                else:
                    caller_well += 1

                caller_str = "%s (0x%X, arg=%s)" % (
                    name, ea, str(arg) if arg is not None else "?"
                )

                user_comment = None

                if arg is not None:
                    decrypted_bytes, status = decrypt_string(
                        base_address, arg, xor_key, increment
                    )
                    if decrypted_bytes is not None:
                        decrypted_string = bytes_to_string(decrypted_bytes)
                        if xor_key is not None and increment is not None:
                            algo = "v2"
                        elif increment is not None:
                            algo = "v1"
                        else:
                            algo = "v2_default"
                        string_addr = base_address + STRING_ARRAY_RVA + arg
                        user_comment = f'"{decrypted_string}" ({status}, {algo})'
                        caller_str += " -> [0x%X: %s]" % (string_addr, user_comment)
                    else:
                        user_comment = f'decrypt_failed: {status}'
                        caller_str += " -> [decrypt_failed: %s]" % status

                if user_comment:
                    idc.set_cmt(ea, user_comment, 0)
                    try:
                        if ida_hexrays.init_hexrays_plugin():
                            f = ida_funcs.get_func(ea)
                            if f:
                                cfunc = ida_hexrays.decompile(f)
                                tl = ida_hexrays.treeloc_t()
                                tl.ea = ea
                                tl.itp = ida_hexrays.ITP_SEMI
                                ida_hexrays.set_user_cmt(cfunc, tl, user_comment)
                                cfunc.save_user_cmts()
                    except Exception:
                        pass

                caller_strings.append(caller_str)

            callers_str = ", ".join(caller_strings)
            ida_kernwin.msg("%s @ 0x%X (%s) used in - %s\n" %
                            (func_name, func_start, decrypt_params, callers_str))

    ida_kernwin.msg(
        "[FindBothCalls] Дешифраторов: размеченных=%d, неразмеченных=%d | "
        "Вызывателей: размеченных=%d, неразмеченных=%d\n"
        % (decoder_well, decoder_unknown, caller_well, caller_unknown)
    )

if __name__ == "__main__":
    main()