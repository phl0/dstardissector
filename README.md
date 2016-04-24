# dstardissector

A Wireshark dissector written in Lua to disassemble D-Star packets beeing exchanged between reflectors.

# Installation

You can directly load this dissector on the command line using:

$ wireshark -X lua_script:dstardissector.lua 

or you can let Wireshark automatically load this file on every start by editing /usr/share/wireshark/init.lua and adding a line like this:
dofile(DATA_DIR.."dstardissector.lua") 

to the end of the file. DATA_DIR represents /usr/share/wireshark so you need to put the dstardissector.lua file into this directory.


