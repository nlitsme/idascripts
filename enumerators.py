# (C) 2013-2014 Willem Hengeveld <itsme@xs4all.nl>

import idaapi
import idc
import types


""" utilities for parsing arguments """

def getrange(args):
    selection, selfirst, sellast = idaapi.read_selection()

    argfirst = args[0] if len(args)>0 and type(args[0])==types.IntType else None
    arglast  = args[1] if len(args)>1 and type(args[1])==types.IntType else None
    """
        afirst  alast    sel 
          None   None     0    ->  here, BADADDR
          None   None     1    ->    selection
          None    +       0    ->  here, BADADDR
          None    +       1    ->    selection
           +     None     0    ->  afirst, BADADDR
           +     None     1    ->  afirst, BADADDR
           +      +       0    ->  afirst, alast
           +      +       1    ->  afirst, alast
    """
    if argfirst is None:
        if selection:
            return (selfirst, sellast)
        else:
            return (here(), BADADDR)
    if arglast is None:
        return (argfirst, BADADDR)
    else:
        return (argfirst, arglast)

def getstringpos(args):
    for i in range(len(args)):
        if type(args[i])==types.StringType:
            return i
    return -1


""" enumerator functions """


def Texts(*args):
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

    Will search for functions containing only  "LDR PC, =xxxxx",
    and rename them as j_XXXXX.
    """
    (first, last)= getrange(args)
    i= getstringpos(args)
    if i<0:
        raise Exception("missing searchstring")

    searchstr= args[i]
    flags = args[i+1] if i+1<len(args) else 0

    ea= idaapi.find_text(first, 0, 0, searchstr, idaapi.SEARCH_DOWN|flags)
    while ea!=idaapi.BADADDR and ea<last:
        yield ea
        ea= idaapi.find_text(idaapi.next_head(ea, last), 0, 0, searchstr, idaapi.SEARCH_DOWN|flags)

def NonFuncs(*args):
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

    Will try to change non-function code to function
    until MakeFunction fails
    """

    (first, last)= getrange(args)

    ea = first
    while ea!=idaapi.BADADDR and ea<last:
        nextcode= idaapi.find_code(ea, idaapi.SEARCH_NEXT|idaapi.SEARCH_DOWN)
        thischunk= idaapi.get_fchunk(ea)
        nextchunk= idaapi.get_next_fchunk(ea)
        if thischunk:
            ea= thischunk.endEA
        elif idaapi.isCode(idaapi.getFlags(ea)):
            yield ea
            ea= idaapi.next_head(ea, last)
        elif nextchunk is None:
            return
        elif nextcode<nextchunk.startEA:
            yield nextcode
            ea= nextcode
        else:
            ea= nextchunk.endEA

def Undefs(*args):
    """
    Enumerate undefined bytes

    @param ea:     where to start
    @param endea:  BADADDR, or end address

    @return: list of addresses of undefined bytes

    Example::

        for ea in Undefs(FirstSeg(), BADADDR):
            if isCode(GetFlags(PrevHead(ea))) and (ea%4)!=0 and iszero(ea, 4-(ea%4)):
                MakeAlign(ea, 4-(ea%4), 2)

    Will add alignment directives after code.
    """
    (first, last)= getrange(args)

    ea= idaapi.find_unknown(first, idaapi.SEARCH_DOWN)
    while ea!=idaapi.BADADDR and ea<last:
        yield ea
        ea= idaapi.find_unknown(ea, idaapi.SEARCH_DOWN|idaapi.SEARCH_NEXT)

def Binaries(*args):
    """
    Enumerate binary search matches

    @param ea:
    @param endea:
    @param searchstr:

    @return: list of addresses matching searchstr

    Example::

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

    This will name all syscall stubs in an android binary.
    Assumes a enum exists with all syscall numbers

    """
    (first, last)= getrange(args)
    i= getstringpos(args)
    if i<0:
        raise Exception("missing searchstring")
    searchstr= args[i]

    ea= idaapi.find_binary(first, last, searchstr, 16, idaapi.SEARCH_DOWN)
    while ea!=idaapi.BADADDR and ea<last:
        yield ea
        ea= idaapi.find_binary(ea, last, searchstr, 16, idaapi.SEARCH_DOWN|idaapi.SEARCH_NEXT)

def ArrayItems(*args):
    """
    Enumerate array items

    @param ea:    address of the array you want the items enumerated, defaults to here()

    @return: list of each item in the array.

    Example::

        for ea in ArrayItems():
           pname= GetString(Dword(ea))
           MakeName(Dword(ea+4)&~1, "task_%s" % pname)
           MakeName(Dword(ea+8), "taskinfo_%s" % pame)
           MakeName(Dword(ea+12), "stack_%s" % pame)


    Assuming the cursor is on an array of structs, in which the
    first struct item points to a name, this will name the other
    items in the struct.
    """
    ea = args[0] if len(args)>0 else here()

    s= idc.ItemSize(ea)
    ss= idaapi.get_data_elsize(ea, idc.GetFlags(ea))

    n= s/ss

    for i in range(n):
        yield ea+i*ss



