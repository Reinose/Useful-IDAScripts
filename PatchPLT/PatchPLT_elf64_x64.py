from ida_bytes import *

import idaapi
import ida_kernwin
import struct

def main():
    u32 = lambda x: struct.unpack("<I", x)[0]
    u64 = lambda x: struct.unpack("<Q", x)[0]

    image_base = idaapi.get_imagebase()

    assert get_bytes(image_base, 4) == b"\x7fELF", "The file looks like non-ELF binary"
    assert get_byte(image_base + 4) == 2, "Only support 64bit ELF binary"
    if get_word(image_base + 0x12) != 0x3e:
        res = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "Only x86-64 machine type has been tested.\nContinue?")
        if res != ida_kernwin.ASKBTN_YES:
            return;


    pht_base = image_base + get_qword(image_base + 0x20)
    pht_entry_size = get_word(image_base + 0x36)
    pht_entry_count = get_word(image_base + 0x38)

    jmprel = None
    for i in range(pht_entry_count):
        current = pht_base + pht_entry_size * i
        if get_dword(current) != 2:
            continue
        dynamic = get_qword(current + 0x10)
        j = 0
        tag = -1
        while tag != 0:
            tag = get_qword(dynamic + 0x10 * j)

            if tag == 0x17:
                jmprel = get_qword(dynamic + 0x10 * j + 0x8)
                break
            j += 1
        else:
            continue
        break
    else:
        ida_kernwin.warning("Cannot find DYNAMIC PHT Entry")
        return;

    got_start_ea = SegByBase(SegByName(".got"))
    got_end_ea = SegEnd(got_start_ea)

    extern_start_ea = SegByBase(SegByName("extern"))
    extern_end_ea = SegEnd(extern_start_ea)

    cur = got_start_ea + 0x18


    fails = []

    # Handle .got for full RELRO
    while cur < got_end_ea:
        plt_offset = u64(get_bytes(cur, 8))

        if get_segm_name(plt_offset) == "extern":
            cur += 0x8
            continue

        gen = FuncItems(plt_offset)
        gen.next()
        extern_idx = GetOperandValue(gen.next(), 0)
        del gen

        func_offset = ida_funcs.get_func(XrefsTo(cur, 0).next().frm).startEA

        real_func_name = GetCommentEx(jmprel + get_struc_size(get_struc_id("Elf64_Rela")) * extern_idx, 0).split()[-1]

        extern_ea = extern_start_ea
        while extern_ea < extern_end_ea:
            if get_name(extern_ea) == real_func_name:
                func_type = get_type(extern_ea)
                break
            extern_ea = NextNotTail(extern_ea)
        if extern_ea == BADADDR:
            fails.append((cur, real_func_name))
            cur += 0x8
            continue

        MakeNameEx(extern_ea, "__imp_" + real_func_name, 0)
        MakeNameEx(plt_offset, real_func_name + "_plt", 0)
        MakeNameEx(cur, real_func_name + "_ptr", 0)
        MakeNameEx(func_offset, real_func_name, 0)
        apply_type(func_offset, get_tinfo(extern_ea))

        cur += 0x8

    got_start_ea = SegByBase(SegByName(".got.plt"))
    got_end_ea = SegEnd(got_start_ea)
    cur = got_start_ea + 0x18

    # Handle .got for full RELRO
    while cur < got_end_ea:
        plt_offset = u64(get_bytes(cur, 8))

        if get_segm_name(plt_offset) == "extern":
            cur += 0x8
            continue

        gen = FuncItems(plt_offset)
        gen.next()
        extern_idx = GetOperandValue(gen.next(), 0)
        del gen

        func_offset = ida_funcs.get_func(XrefsTo(cur, 0).next().frm).startEA

        real_func_name = GetCommentEx(jmprel + get_struc_size(get_struc_id("Elf64_Rela")) * extern_idx, 0).split()[-1]

        print(real_func_name)
        extern_ea = extern_start_ea
        while extern_ea < extern_end_ea:
            if get_name(extern_ea) == real_func_name:
                func_type = get_type(extern_ea)
                break
            extern_ea = NextNotTail(extern_ea)
        if extern_ea == BADADDR:
            fails.append((cur, real_func_name))
            cur += 0x8
            continue

        MakeNameEx(extern_ea, "__imp_" + real_func_name, 0)
        MakeNameEx(plt_offset, real_func_name + "_plt", 0)
        MakeNameEx(cur, real_func_name + "_ptr", 0)
        MakeNameEx(func_offset, real_func_name, 0)
        apply_type(func_offset, get_tinfo(extern_ea))

        cur += 0x8

    print("DONE")
    if fails:
        print("Fails: {}".format(fails))

main()
