# (C) 2013-2014 Willem Hengeveld <itsme@xs4all.nl>

import idaapi
import idc
import types
import ida_bytes

"""
 
Enumeration utilities for idapython

 * Texts      - like Alt-T / ctrl-t
 * Code       - like Alt-C
 * NonFuncs   - like Alt-U
 * Undefs     - like Ctrl-U
 * Binaries   - like Alt-B / ctrl-b
 * ArrayItems
 * Addrs
 * NotTails   - like cursor down
 * BytesThat  
 * Heads
 * Funcs
 * FChunks
 * Names      - todo: iterate over all names in the given range

the range which will be operated upon can be specified in several ways:

 * pass an area_t subclass ( as returned by idaapi.getseg, get_fchunk, get_func )
 * no arguments, take selection when available
 * no arguments: from here until the end
 * one address: from addr until the end
 * two addresses: from first until last address


      for ea in Undefs():
          if isstring(PrevItem(ea)) and lookslikestring(ea):
               MakeString(ea)

todo:
    Data      - ctrl-d
    Explored  - ctrl-a
    Immediates- alt-I  / ctrl-i
    Voids     - ctrl-v
    Errors    - ctrl-y
    Enums
    EnumMembers
    Structs
    StructMembers

    make this easier:

for ea in map(lambda x:x[0], filter(lambda x:x[1].startswith("ifenums_"), Names())): OpOff(ea,0,0)


"""

BADADDR         = idaapi.BADADDR

""" utilities for parsing arguments """

def getrange(args):
    """
    Determines a address range.

    @param  args:  the argument list passed to the caller

    @return: a pair of addresses

    args can contain one of the following:

    1) a tuple containing (first, last)
    2) an area_t, containing  (start_ea, end_ea)
    3) nothing
       * if the user made a selection ( using Alt-L ), that selection is returned
       * otherwise from the cursor line until endoffile
    4) one address: from address until the end of file
    5) two addresses: the range between those addresses

    The range is specified as (first,last)
    meaning all addresses satisfying  first <= addr < last

    """
    selection, selfirst, sellast = idaapi.read_selection()

    if isinstance(args, idaapi.area_t):
        return (args.start_ea, args.end_ea)
    if len(args) and type(args[0])==types.TupleType:
        return args[0]
    if len(args) and isinstance(args[0], idaapi.area_t):
        return (args[0].start_ea, args[0].end_ea)

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
            return (idc.here(), BADADDR)
    if arglast is None:
        return (argfirst, BADADDR)
    else:
        return (argfirst, arglast)

def getstringpos(args):
    for i in xrange(len(args)):
        if type(args[i])==types.StringType:
            return i
    return -1

def getcallablepos(args):
    for i in xrange(len(args)):
        if type(args[i])==types.FunctionType:
            return i
    return -1


""" enumerator functions """


def Texts(*args):
    """
    Enumerate text search matches

    @param <range>: see getrange
    @param searchstr:    string or regex
    @param flags:        for instance SEARCH_REGEX

    @return: list of addresses matching searchstr

    Example::

        for ea in Texts((FirstSeg(), BADADDR), "LDR *PC, =", SEARCH_REGEX):
            f = idaapi.get_func(ea)
            if f and f.start_ea==ea:
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

    ea= idaapi.find_text(first, idaapi.SEARCH_DOWN|flags, 0, 0, searchstr)
    while ea!=idaapi.BADADDR and ea<last:
        yield ea
        ea= idaapi.find_text(idaapi.next_head(ea, last), idaapi.SEARCH_DOWN|flags, 0, 0, searchstr)

def NonFuncs(*args):
    """
    Enumerate code which is not in a function

    @param <range>: see getrange

    @return: list of addresses containing code, but not in a function

    Example::

        for ea in NonFuncs((FirstSeg(), BADADDR)):
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
            ea= thischunk.end_ea
        elif idaapi.is_code(idaapi.get_full_flags(ea)):
            yield ea
            ea= idaapi.next_head(ea, last)
        elif nextchunk is None:
            return
        elif nextcode<nextchunk.start_ea:
            yield nextcode
            ea= nextcode
        else:
            ea= nextchunk.end_ea

def Undefs(*args):
    """
    Enumerate undefined bytes

    @param <range>: see getrange

    @return: list of addresses of undefined bytes

    Example::

        for ea in Undefs((FirstSeg(), BADADDR)):
            if isCode(GetFlags(PrevHead(ea))) and (ea%4)!=0 and iszero(ea, 4-(ea%4)):
                MakeAlign(ea, 4-(ea%4), 2)

    Will add alignment directives after code.
    """
    (first, last)= getrange(args)

    ea= first
    # explicitly testing first byte, since find_unknown
    # implicitly sets SEARCH_NEXT flag
    if ea<last and not ida_bytes.is_unknown(idaapi.get_full_flags(ea)):
        ea= idaapi.find_unknown(ea, idaapi.SEARCH_DOWN)
    while ea!=idaapi.BADADDR and ea<last:
        yield ea
        ea= idaapi.find_unknown(ea, idaapi.SEARCH_DOWN)

def Code(*args):
    """
    Enumerate code bytes

    @param <range>: see getrange

    @return: list of addresses of code bytes

    Example::

        for ea in Code():
            MakeUnkn(ea, DOUNK_EXPAND)
            Wait()

    Will delete all code in the selected area.


        len(list(MakeUnkn(ea, DOUNK_EXPAND) and Wait() for ea in enumerators.Code(idaapi.getseg(here()))))

    will delete all code in the current segment, and can be pasted in the command area of ida

    """
    (first, last)= getrange(args)

    ea= first
    # explicitly testing first byte, since find_code
    # implicitly sets SEARCH_NEXT flag
    if ea<last and not idaapi.is_code(idaapi.get_full_flags(ea)):
        ea= idaapi.find_code(ea, idaapi.SEARCH_DOWN)
    while ea!=idaapi.BADADDR and ea<last:
        yield ea
        ea= idaapi.find_code(ea, idaapi.SEARCH_DOWN)


def Binaries(*args):
    """
    Enumerate binary search matches

    @param <range>: see getrange
    @param searchstr:
    @param flags:        for instance SEARCH_CASE

    @return: list of addresses matching searchstr

    Example::

        sysenum= GetEnum("enum_syscalls")
        for ea in Binaries((FirstSeg(), BADADDR), "00 00 00 ef"):
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
    flags = args[i+1] if i+1<len(args) else 0

    ea= idaapi.find_binary(first, last, searchstr, 16, idaapi.SEARCH_DOWN|flags)
    while ea!=idaapi.BADADDR and ea<last:
        yield ea
        ea= idaapi.find_binary(ea, last, searchstr, 16, idaapi.SEARCH_DOWN|idaapi.SEARCH_NEXT|flags)

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
    ea = args[0] if len(args)>0 else idc.here()

    s= idc.ItemSize(ea)
    ss= idaapi.get_data_elsize(ea, idaapi.get_full_flags(ea))

    n= s/ss

    for i in xrange(n):
        yield ea+i*ss

def Addrs(*args):
    """
    Enumerate all addresses

    @param <range>: see getrange

    @return: list of all addresses in range

    """
    (first, last)= getrange(args)

    # note: problem when using range(...) for ea>=2^31
    # TODO: problem when last == BADADDR
    ea = first
    while ea!=BADADDR and ea<last:
        yield ea
        ea = idc.NextAddr(ea)

def BytesThat(*args):
    """
    Enumerate array items

    @param <range>: see getrange
    @param callable: function which tests the flags

    @return: list of all addresses where callable(GetFlags(ea)) is True

    """
    (first, last)= getrange(args)
    i= getcallablepos(args)
    if i<0:
        raise Exception("missing callable")

    callable= args[i]

    ea= first
    if ea<last and not callable(idaapi.get_full_flags(ea)):
        ea= idaapi.nextthat(ea, last, callable)
    while ea!=BADADDR and ea<last:
        yield ea
        ea= idaapi.nextthat(ea, last, callable)

def Heads(*args):
    """
    Enumerate array items

    @param <range>: see getrange

    @return: list of all heads

    """
    (first, last)= getrange(args)

    ea= first
    if ea<last and not idaapi.is_head(idaapi.get_full_flags(ea)):
        ea= idaapi.next_head(ea, last)
    while ea!=BADADDR and ea<last:
        yield ea
        ea= idaapi.next_head(ea, last)

def NotTails(*args):
    """
    Enumerate array items

    @param <range>: see getrange

    @return: list of all not-tails

    Note that NotTails includes all Heads plus all undefined bytes

    """
    (first, last)= getrange(args)

    ea= first
    if ea<last and idaapi.is_tail(idaapi.get_full_flags(ea)):
        ea= idaapi.next_not_tail(ea)
    while ea!=BADADDR and ea<last:
        yield ea
        ea= idaapi.next_not_tail(ea)

def Funcs(*args):
    """
    Enumerate array items

    @param <range>: see getrange

    @return: list of all function starts

    """
    (first, last)= getrange(args)
    # find first function head chunk in the range
    chunk = idaapi.get_fchunk(first)
    if not chunk:
        chunk = idaapi.get_next_fchunk(first)
    while chunk and chunk.start_ea < last and (chunk.flags & idaapi.FUNC_TAIL) != 0:
        chunk = idaapi.get_next_fchunk(chunk.start_ea)
    func = chunk

    while func and func.start_ea < last:
        yield func.start_ea
        func = idaapi.get_next_func(func.start_ea)


def FChunks(*args):
    """
    Enumerate array items

    @param <range>: see getrange

    @return: list of all function chunks in an address range.

    For the list of all chunks in a function use idautils.Chunks

    """
    (first, last)= getrange(args)
    chunk = idaapi.get_fchunk(first)
    if not chunk:
        chunk = idaapi.get_next_fchunk(first)
    while chunk and chunk.start_ea < last:
        yield chunk.start_ea
        chunk = idaapi.get_next_fchunk(chunk.start_ea)

def findend(ea):
    ea0 = ea
    while True:
        ea = idc.NextAddr(ea)
        if XrefsTo(ea):
            break
        if idaapi.get_full_flags(ea)&idc.FF_ANYNAME:
            break
    return ea-ea0
    
