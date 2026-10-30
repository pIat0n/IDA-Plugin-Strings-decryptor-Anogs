#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDA Pro Universal String Decryptor for Tencent Anogs (ACE / Anti-Cheat Expert)
Supports:
  - ARM64 (arm64-v8a) with auto-detection of accessor functions & string table RVA
  - ARM32 (armeabi-v7a) with auto-detection between PUBG Mobile 4.1 & 4.0

Usage in IDA Pro:
  File -> Script file... -> DecryptStringsAuto.py
"""

import os
import sys
import importlib.util
import idaapi
import idc
import ida_kernwin

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()


def is_64bit_binary():
    """Detect if current IDB binary is 64-bit."""
    try:
        if hasattr(idaapi, "get_inf_structure"):
            return idaapi.get_inf_structure().is_64bit()
    except Exception:
        pass
    try:
        import ida_ida
        return ida_ida.inf_is_64bit()
    except Exception:
        pass
    return False


def run_script(script_path):
    """Load and execute an IDA script module by absolute file path."""
    if not os.path.isfile(script_path):
        ida_kernwin.msg(f"[Error] Plugin script not found: {script_path}\n")
        return False
    try:
        spec = importlib.util.spec_from_file_location("anogs_decryptor_mod", script_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if hasattr(mod, "main"):
            mod.main()
        return True
    except Exception as e:
        ida_kernwin.msg(f"[Error] Failed to execute '{os.path.basename(script_path)}': {e}\n")
        import traceback
        traceback.print_exc()
        return False


def main():
    ida_kernwin.msg("\n" + "=" * 70 + "\n")
    ida_kernwin.msg("  [Anogs Decryptor] Universal String Decryption Plugin\n")
    ida_kernwin.msg("  Tencent Anti-Cheat Expert (ACE) / Anogs Strings Deobfuscator\n")
    ida_kernwin.msg("=" * 70 + "\n")

    is_64 = is_64bit_binary()
    proc_name = getattr(idaapi.get_inf_structure(), "procname", "ARM") if hasattr(idaapi, "get_inf_structure") else "ARM"
    base_ea = idaapi.get_imagebase()

    ida_kernwin.msg(f"[*] Target Architecture: {'64-bit' if is_64 else '32-bit'} ({proc_name})\n")
    ida_kernwin.msg(f"[*] Image Base: 0x{base_ea:X}\n\n")

    if is_64:
        ida_kernwin.msg("[*] Routing to ARM64 engine...\n")
        script_file = os.path.join(SCRIPT_DIR, "plugins", "arm64", "DecAnogsArm64Strings.py")
        run_script(script_file)
    else:
        ida_kernwin.msg("[*] Routing to ARM32 engine...\n")
        # Check known target functions to distinguish PUBG 4.1 and 4.0
        ea_41 = idc.get_name_ea_simple("sub_38D534")
        ea_40 = idc.get_name_ea_simple("sub_3AC024")

        if ea_41 != idc.BADADDR:
            ida_kernwin.msg("[*] Auto-detected PUBG Mobile 4.1 targets!\n")
            script_file = os.path.join(SCRIPT_DIR, "plugins", "arm32", "DecPubg4.1Strings.py")
        elif ea_40 != idc.BADADDR:
            ida_kernwin.msg("[*] Auto-detected PUBG Mobile 4.0 targets!\n")
            script_file = os.path.join(SCRIPT_DIR, "plugins", "arm32", "DecPubg4.0Strings.py")
        else:
            # Default to latest 4.1 version
            ida_kernwin.msg("[*] Defaulting to PUBG Mobile 4.1 profile...\n")
            script_file = os.path.join(SCRIPT_DIR, "plugins", "arm32", "DecPubg4.1Strings.py")

        run_script(script_file)


if __name__ == "__main__":
    main()
