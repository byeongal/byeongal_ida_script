from idc import *
from idautils import *
from idaapi import *

import json

autoWait()

static_report_dict = dict()

# Basic Properties
static_report_dict['MD5'] = retrieve_input_file_md5()
static_report_dict['SHA256'] = retrieve_input_file_sha256()
static_report_dict['CRC32'] = retrieve_input_file_crc32()
static_report_dict['FILE_SIZE'] = retrieve_input_file_size()

# Opcode and Asm
static_report_dict['opcode'] = []
static_report_dict['asm'] = []
static_report_dict['segments'] = []
for seg_ea in Segments() :
    seg_name, seg_start, seg_end = idc.SegName(seg_ea), idc.SegStart(seg_ea), idc.SegEnd(seg_ea)
    static_report_dict['segments'].append([seg_name, seg_start, seg_end])
    for func_ea in Functions(seg_ea, SegEnd(seg_ea)):
        f = get_func(func_ea)
        flags = GetFunctionFlags(func_ea)
        #if flags & FUNC_LIB or flags & FUNC_THUNK :
        #    continue
        func_opcode = []
        func_asm = []
        for block in FlowChart(f):
            block_opcode = []
            block_asm = []
            for head in Heads(block.startEA, block.endEA):
                text = generate_disasm_line(head, 0)
                if text :
                    block_asm.append(tag_remove(text))
                if isCode(GetFlags(head)) :
                    block_opcode.append('%02x' %(Byte(head)))
            func_opcode.append(block_opcode)
            func_asm.append(block_asm)
        static_report_dict['opcode'].append(func_opcode)
        static_report_dict['asm'].append(func_asm)

# String
static_report_dict['string'] = []
sc = Strings()

for s in sc:
    static_report_dict['string'].append(str(s))

# Imports
static_report_dict['import'] = {}
for i in range(get_import_module_qty()):
    dllname = get_import_module_name(i)
    if not dllname:
        continue
    if not dllname in static_report_dict['import'] :
        static_report_dict['import'][dllname] = []
    entries = []
    def cb(ea, name, ordinal):
        if name :
            entries.append((ea, name, ordinal))
        return True  # continue enumeration

    enum_import_names(i, cb)

    for ea, name, ordinal in entries :
        static_report_dict['import'][dllname].append(name)

# Export
static_report_dict['export'] = [ each[-1] for each in list(Entries()) ]

with open(static_report_dict['MD5'] + '.json', 'w') as f :
    json.dump(static_report_dict, f)

Exit(0)
