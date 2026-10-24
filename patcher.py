import argparse
import sys
from pathlib import Path

try:
    import pefile
except ImportError:
    sys.exit("not found pefile: pip install pefile")

try:
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
except ImportError:
    sys.exit("not found capstone: pip install capstone")

MAGIC_BYTES = b"\x49\x53\x4c\x31"
DASH_BYTE = 0x2D
MAGIC_SEARCH_WINDOW = 12
FORWARD_SCAN_BYTES = 80
MAX_INSNS_FORWARD = 20


def _get_pdata_entries(pe: "pefile.PE") -> list[tuple[int, int, int]]:
    pdata = None
    for section in pe.sections:
        if b".pdata" in section.Name:
            pdata = section
            break
    if pdata is None:
        raise RuntimeError("NF .pdata")

    pdata_bytes = pdata.get_data()
    n_entries = len(pdata_bytes) // 12
    entries = []
    for i in range(n_entries):
        off = i * 12
        begin, end, unwind = pefile.struct.unpack_from("<III", pdata_bytes, off)
        entries.append((begin, end, unwind))
    return entries


def find_containing_function(pe: "pefile.PE", rva: int) -> tuple[int, int] | None:
    for begin, end, _unwind in _get_pdata_entries(pe):
        if begin <= rva < end:
            return begin, end
    return None


def find_validate_function(pe: "pefile.PE") -> int:
    text_section = None
    for section in pe.sections:
        if b".text" in section.Name:
            text_section = section
            break
    if text_section is None:
        raise RuntimeError("NF .text")

    data = text_section.get_data()
    base_rva = text_section.VirtualAddress

    candidates = []
    start = 0
    while True:
        idx = data.find(MAGIC_BYTES, start)
        if idx == -1:
            break
        window = data[idx : idx + 4 + MAGIC_SEARCH_WINDOW]
        if DASH_BYTE in window[4:]:
            candidates.append(base_rva + idx)
        start = idx + 1

    if not candidates:
        raise RuntimeError("NF SING")

    for magic_rva in candidates:
        bounds = find_containing_function(pe, magic_rva)
        if bounds:
            return bounds[0]

    raise RuntimeError("MG CONST OK, NO .PDATA MAP")


def find_call_sites(pe: "pefile.PE", target_rva: int, md: "Cs") -> list[int]:
    image_base = pe.OPTIONAL_HEADER.ImageBase
    text_section = None
    for section in pe.sections:
        if b".text" in section.Name:
            text_section = section
            break
    data = text_section.get_data()
    base_va = image_base + text_section.VirtualAddress

    sites = []
    for insn in md.disasm(data, base_va):
        if insn.mnemonic != "call" or not insn.operands:
            continue
        op = insn.operands[0]
        if op.type == X86_OP_IMM:
            target_va = op.imm
            if target_va - image_base == target_rva:
                sites.append(insn.address + insn.size - image_base)  # RVA возврата
    return sites


def classify_and_patch(pe: "pefile.PE", return_rva: int, md: "Cs") -> str | None:
    image_base = pe.OPTIONAL_HEADER.ImageBase
    window = pe.get_data(return_rva, FORWARD_SCAN_BYTES)
    base_va = image_base + return_rva

    insns = list(md.disasm(window, base_va))[:MAX_INSNS_FORWARD]

    for i, insn in enumerate(insns):
        if insn.mnemonic == "cmp" and len(insn.operands) == 2:
            dst, src = insn.operands
            if dst.type == X86_OP_MEM and src.type == X86_OP_IMM and src.imm == 1:
                for j in range(i + 1, min(i + 3, len(insns))):
                    nxt = insns[j]
                    if nxt.mnemonic.startswith("j") and nxt.mnemonic != "jmp":
                        raw = bytes(insn.bytes)
                        if raw[-1] != 1:
                            continue
                        patch_rva = insn.address - image_base + len(raw) - 1
                        pe.set_bytes_at_rva(patch_rva, bytes([0x02]))
                        print(
                            f"[TYP B] CMP-IMM PATCH @RVA 0x{patch_rva:X}: 01->02 (CMP@0x{insn.address - image_base:X}, {nxt.mnemonic}@0x{nxt.address - image_base:X})"
                        )
                        return "B"

    for insn in insns:
        if insn.mnemonic == "xor" and len(insn.operands) == 2:
            dst, src = insn.operands
            if src.type == X86_OP_IMM and src.imm == 1:
                raw = bytes(insn.bytes)
                for k in range(len(raw) - 2):
                    if (
                        raw[k] == 0x83
                        and (raw[k + 1] & 0xF8) == 0xF0
                        and raw[k + 2] == 0x01
                    ):
                        modrm = raw[k + 1]
                        new_modrm = (modrm & 0xC7) | 0x08
                        patch_rva = insn.address - image_base + k + 1
                        pe.set_bytes_at_rva(patch_rva, bytes([new_modrm]))
                        print(
                            f"[TYP A] XOR->OR PATCH @RVA 0x{patch_rva:X}: {modrm:02X}->{new_modrm:02X} (INSN@0x{insn.address - image_base:X})"
                        )
                        return "A"
    return None


def find_iat_rva(pe: "pefile.PE", dll_name_substr: str, func_name: str) -> int | None:
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return None
    image_base = pe.OPTIONAL_HEADER.ImageBase
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode(errors="ignore").lower()
        if dll_name_substr.lower() not in dll:
            continue
        for imp in entry.imports:
            if imp.name and imp.name.decode(errors="ignore") == func_name:
                return imp.address - image_base  # imp.address = VA слота IAT
    return None


def find_iat_call_sites(pe: "pefile.PE", iat_slot_rva: int, md: "Cs") -> list[int]:
    image_base = pe.OPTIONAL_HEADER.ImageBase
    text_section = None
    for section in pe.sections:
        if b".text" in section.Name:
            text_section = section
            break
    data = text_section.get_data()
    base_va = image_base + text_section.VirtualAddress

    sites = []
    for insn in md.disasm(data, base_va):
        if insn.mnemonic != "call" or not insn.operands:
            continue
        op = insn.operands[0]
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            target_va = insn.address + insn.size + op.mem.disp
            if target_va - image_base == iat_slot_rva:
                sites.append(insn.address - image_base)
    return sites


def patch_constant_dl_before_call(
    pe: "pefile.PE", call_insn_rva: int, md: "Cs"
) -> bool:
    image_base = pe.OPTIONAL_HEADER.ImageBase

    bounds = find_containing_function(pe, call_insn_rva)
    if bounds:
        start_rva, _end_rva = bounds
    else:
        start_rva = max(call_insn_rva - 512, 0)

    window = pe.get_data(start_rva, (call_insn_rva - start_rva) + 16)
    base_va = image_base + start_rva
    insns = [
        i for i in md.disasm(window, base_va) if i.address - image_base < call_insn_rva
    ]

    if not insns:
        return False
    prev = insns[-1]

    if prev.mnemonic == "mov" and len(prev.operands) == 2:
        dst, src = prev.operands
        if dst.type == X86_OP_REG and src.type == X86_OP_IMM:
            reg_name = prev.reg_name(dst.reg)
            if reg_name == "dl" and src.imm != 0:
                raw = bytes(prev.bytes)
                if (
                    raw[0] == 0xB2
                ):  # mov dl, imm8 - опкод B2, immediate - последний байт
                    patch_rva = prev.address - image_base + len(raw) - 1
                    pe.set_bytes_at_rva(patch_rva, bytes([0x00]))
                    print(
                        f"[TYP C] MOV DL PATCH @RVA 0x{patch_rva:X}: {src.imm:#x}->0x0 (ENB=FAL ONLY FOR THIS CALL) (MOV DL@0x{prev.address - image_base:X}, CALL@0x{call_insn_rva:X})"
                    )
                    return True

    print(
        f"[*] DL BEFORE CALL@0x{call_insn_rva:X} NOT CONST ({prev.mnemonic} {prev.op_str}), DYN TOGGLE (HUD CAP), SKIP"
    )
    return False


def patch_display_affinity(pe: "pefile.PE", md: "Cs") -> int:
    iat_rva = find_iat_rva(pe, "user32", "SetWindowDisplayAffinity")
    if iat_rva is None:
        print("[*] SetWindowDisplayAffinity NOT IN user32.dll IMPORTS")
        return 0
    print(f"[+] SetWindowDisplayAffinity F IAT: RVA 0x{iat_rva:X}")

    api_call_sites = find_iat_call_sites(pe, iat_rva, md)
    if not api_call_sites:
        print("[!] IAT SLOT NO CALL [RIP+DISP]")
        return 0

    wrapper_bounds = find_containing_function(pe, api_call_sites[0])
    if not wrapper_bounds:
        print("[!] NO FUNC")
        return 0
    wrapper_rva = wrapper_bounds[0]
    print(f"[+] WRP set_capture_protection(): RVA 0x{wrapper_rva:X}")

    wrapper_return_sites = find_call_sites(pe, wrapper_rva, md)
    if not wrapper_return_sites:
        print("[!] NO WRP CALLS")
        return 0
    print(f"[+] WRP CALLS: {len(wrapper_return_sites)}")

    patched = 0
    for i, ret_rva in enumerate(wrapper_return_sites, 1):
        call_insn_rva = ret_rva - 5
        print(f"[*] WRP CALL #{i} @RVA 0x{call_insn_rva:X}")
        if patch_constant_dl_before_call(pe, call_insn_rva, md):
            patched += 1
    return patched


def main():
    ap = argparse.ArgumentParser(description="Автопатч island.exe: любой ключ -> Pro")
    ap.add_argument("input", help="путь к island.exe")
    ap.add_argument(
        "-o",
        "--output",
        help="путь для сохранения патченой копии (по умолчанию: <input>_patched.exe)",
    )
    args = ap.parse_args()

    in_path = Path(args.input)
    out_path = (
        Path(args.output)
        if args.output
        else in_path.with_name(in_path.stem + "_patched" + in_path.suffix)
    )

    pe = pefile.PE(str(in_path))
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    print("[*] SCAN validate_key() SIG ...")
    validate_rva = find_validate_function(pe)
    print(f"[+] validate_key() -> RVA 0x{validate_rva:X}")

    print("[*] SCAN validate_key() CALLS ...")
    sites = find_call_sites(pe, validate_rva, md)
    if not sites:
        sys.exit("[-] NO CALLS, CODE STRUCTURE CHANGED")
    print(f"[+] CALLS FOUND: {len(sites)}")

    patched = {"A": 0, "B": 0}
    for i, rva in enumerate(sites, 1):
        print(f"[*] CALL SITE #{i} (RET @RVA 0x{rva:X})")
        kind = classify_and_patch(pe, rva, md)
        if kind:
            patched[kind] += 1
        else:
            print("[!] PATTERN NOT MATCH, SKIP (MAYBE WRONG CALL)")

    if patched["A"] == 0 or patched["B"] == 0:
        print(
            f"\n[!] WARN: NOT ALL PATCHES APPLIED (TYP A:{patched['A']}, TYP B:{patched['B']})."
        )
    else:
        print(
            f"\n[+] BOTH LICENSE PATCHES APPLIED (TYP A x{patched['A']}, TYP B x{patched['B']})"
        )

    # affinity_patched = patch_display_affinity(pe, md)
    # if affinity_patched:
    #     print(f"[+] SetWindowDisplayAffinity PATCHED ({affinity_patched} CALLS)")
    # else:
    #     print("[!] SetWindowDisplayAffinity NOT PATCHED")

    pe.write(str(out_path))
    print(f"[+] PATCHED -> {out_path}")


if __name__ == "__main__":
    main()
