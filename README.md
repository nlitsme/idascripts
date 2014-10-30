idascripts
==========

IDApro idc and idapython script collection 


enumerators.py
--------------

Contains several iterators:

|             |                                                          |
| ----------- | -------------------------------------------------------- |
| Texts       | search text ( or regex ) in the disassembly, like Alt-T  |
| NonFuncs    | search non function code ( like Alt-U )                  |
| Undefs      | search unexplored items ( like Ctrl-U )                  |
| Binaries    | search binary patterns ( like Alt-B )                    |
| ArrayItems  | return addresses for each item in an array               |
| Addrs       | all addresses in range                                   |
| BytesThat   | bytes matching a filter                                  |
| Heads       | all heads in range                                       |
| NotTails    | Heads + undefined bytes                                  |
| Funcs       | enumerate all function starts                            |
| FChunks     | enumerate all function chunks                            |

The range which is to be searched can be specified in several ways:

|                               |                                                |
| ----------------------------- | ---------------------------------------------- |
| Texts(start [, "text"] )      | search from start until the end of the file    |
| Texts(start, end [, "text"] ) | search between start and end                   |
| Texts(["text"])               | search the selected area, or                   |
|                               | search from the cursor to the end of the file  |

