import struct

start = SegStart(0)

jmprel = None

while True:
    start = next_not_tail(start)
    assert(start != BADADDR)
    if LineA(start, 0) == "; ELF JMPREL Relocation Table":
        jmprel = start
    if jmprel != None:
        break

got_start_ea = SegByBase(SegByName(".got"))
got_end_ea = SegEnd(got_start_ea)

extern_start_ea = SegByBase(SegByName("extern"))
extern_end_ea = SegEnd(extern_start_ea)

cur = got_start_ea + 0x18

u64 = lambda x: struct.unpack("<Q", x)[0]
u32 = lambda x: struct.unpack("<I", x)[0]

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
        extern_ea = next_head(extern_ea)
    assert(extern_ea != BADADDR)

    MakeNameEx(extern_ea, "__imp_" + real_func_name, 0)
    MakeNameEx(plt_offset, real_func_name + "_plt", 0)
    MakeNameEx(cur, real_func_name + "_ptr", 0)
    MakeNameEx(func_offset, real_func_name, 0)
    apply_type(func_offset, get_tinfo(extern_ea))

    cur += 0x8
