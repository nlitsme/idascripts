# (C) 2013-2014 Willem Hengeveld <itsme@xs4all.nl>

import idaapy
import idc

def Texts(ea, endea, searchstr, flags):
    """
    Enumerate text search matches

    @param ea:           where to start
    @param endea:        BADADDR, or end address
    @param searchstr:    string or regex
    @param flags:        for instance SEARCH_REGEX

    @return: list of addresses matching searchstr

    Example::
        for ea in Texts(FirstSeg(), BADADDR, "LDR *PC, =", SEARCH_REGEX):
            f = idaapi.get_func(ea)
            if f and f.startEA==ea:
                n= idaapi.get_name(BADADDR, ea)
                if not n.startswith("sub_"):
                    MakeName(ea, "j_%s" %n)
    """
    ea= idaapi.find_text(ea, 0, 0, searchstr, idaapi.SEARCH_DOWN|flags)
    while ea!=idaapi.BADADDR and ea<endea:
        yield ea
        ea= idaapi.find_text(idaapi.next_head(ea, endea), 0, 0, searchstr, idaapi.SEARCH_DOWN|flags)

def NonFuncs(ea, endea):
    """
    Enumerate code which is not in a function

    @param ea:    where to start
    @param endea: BADADDR, or end address

    @return: list of addresses containing code, but not in a function

    Example::
        for ea in NonFuncs(FirstSeg(), BADADDR):
            if not MakeFunction(ea):
                Jump(ea)
                break
            Wait()
    """
    while ea!=idaapi.BADADDR and ea<endea:
        nextcode= idaapi.find_code(ea, idaapi.SEARCH_NEXT|idaapi.SEARCH_DOWN)
        thischunk= idaapi.get_fchunk(ea)
        nextchunk= idaapi.get_next_fchunk(ea)
        if thischunk:
            ea= thischunk.endEA
        elif idaapi.isCode(idaapi.getFlags(ea)):
            yield ea
            ea= idaapi.next_head(ea, endea)
        elif nextcode<nextchunk.startEA:
            yield nextcode
            ea= nextcode
        else:
            ea= nextchunk.endEA

def Undefs(ea, endea):
    """
    Enumerate undefined bytes

    @param ea:     where to start
    @param endea:  BADADDR, or end address

    @return: list of addresses of undefined bytes

    Example::
        for ea in Undefs(FirstSeg(), BADADDR):
            if isCode(GetFlags(PrevHead(ea))) and (ea%4)!=0 and iszero(ea, 4-(ea%4)):
                MakeAlign(ea, 4-(ea%4), 2)

        will add alignment directives after code
    """
    ea= idaapi.find_unknown(ea, idaapi.SEARCH_DOWN)
    while ea!=idaapi.BADADDR and ea<endea:
        yield ea
        ea= idaapi.find_unknown(ea, idaapi.SEARCH_DOWN|idaapi.SEARCH_NEXT)

def Binaries(ea, endea, searchstr):
    """
    Enumerate binary search matches

    @param ea:
    @param endea:
    @param searchstr:

    @return: list of addresses matching searchstr

    Example::
        # this will name all syscall stubs in an android binary

        # assume a enum exists with all syscall numbers
        sysenum= GetEnum("enum_syscalls")
        for ea in Binaries(FirstSeg(), BADADDR, "00 00 00 ef"):
           insn= DecodePreviousInstruction(ea)
           if insn.itype==idaapi.ARM_mov and insn.Op1.is_reg(7) and insn.Op2.type==o_imm:
               OpEnumEx(insn.ea, 1, sysenum, 0)
               if Dword(insn.ea-4)==0xe92d0090 and Dword(insn.ea+8)==0xe8bd0090:
                    syscall= GetConstName(GetConst(sysenum, insn.Op2.value, 0))
                    if syscall:
                        MakeName(insn.ea-4, "syscall_%s" % syscall[4:])
                    else:
                        print "unknown syscall number: %08x" % insn.Op2.value

    """
    ea= idaapi.find_binary(ea, +endea, searchstr, 16, idaapi.SEARCH_DOWN)
    while ea!=idaapi.BADADDR and ea<endea:
        yield ea
        ea= idaapi.find_binary(ea, +endea, searchstr, 16, idaapi.SEARCH_DOWN|idaapi.SEARCH_NEXT)

def ArrayItems(ea):
    """
    Enumerate array items

    @param ea:    address of the array you want the items enumerated

    @return: list of each item in the array.

    Example::
        # assuming the cursor is on an array of structs
        # where the first struct item points to a name,
        # this will name the other items in the struct

        for ea in ArrayItems(ScreenEA()):
           pname= GetString(Dword(ea))
           MakeName(Dword(ea+4)&~1, "task_%s" % pname)
           MakeName(Dword(ea+8), "taskinfo_%s" % pame)
           MakeName(Dword(ea+12), "stack_%s" % pame)

    """
    ti = idaapi.opinfo_t()
    f= idc.GetFlags(ea)
    if not idaapi.get_opinfo(ea, 0, f, ti):
        print "could not get opinfo"
        return
    s= idc.ItemSize(ea)
    ss= 0
    if idc.isStruct(f):
        ss= idaapi.get_struc_size(ti.tid)
    else:
        ss= s

    n= s/ss
    for i in range(n):
        yield ea+i*ss



