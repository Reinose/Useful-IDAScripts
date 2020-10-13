def main():
    import struct

    u32 = lambda x: struct.unpack("<I", x)[0]
    u64 = lambda x: struct.unpack("<Q", x)[0]

    from ida_bytes import get_bytes
    import idaapi
    import ida_kernwin

    image_base = idaapi.get_imagebase()

    assert get_bytes(image_base, 4) == b"\x7fELF", "The file looks like non-ELF binary"
    assert get_bytes(image_base + 4, 1) == b"\x02", "Only support 64bit ELF binary"
    if get_bytes(image_bae + 0x12, 2) != "\x3e\x00":
        res = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "Only x86-64 machine type has been tested.\nContinue?")
        if res != ida_kernwin.ASKBTN_YES:
            return;

    jmprel = None
    cursor = image_base
    while jmprel == None:
        cursor = next_not_tail(cursor)
        assert cursor != BADADDR, "ELF JMPREL Relocation Table not found"
        if LineA(cursor, 0) == "; ELF JMPREL Relocation Table":
            jmprel = cursor

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
