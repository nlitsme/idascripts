idascripts
==========

IDApro idc and idapython script collection 


enumerators.py
--------------

Contains several iterators:

| Texts       | search text ( or regex ) in the disassembly, like Alt-T
| NonFuncs    | search non function code ( like Alt-U )
| Undefs      | search unexplored items ( like Ctrl-U )
| Binaries    | search binary patterns ( like Alt-B )
| ArrayItems  | return addresses for each item in an array

The range which is to be searched can be specified in several ways:

| Texts(start [, "text"] )      | search from start until the end of the file
| Texts(start, end [, "text"] ) | search between start and end
| Texts(["text"])               | search the selected area, or
|                               | search from the cursor to the end of the file

