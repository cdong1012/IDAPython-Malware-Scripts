import json
import idaapi
import idc
import idautils
from fnvhash import fnv1a_32

# task 1: set up json
def setup(json_file):
    global export_hashes
    exports_json = json.loads(open(json_file, 'rb').read())
    exports_list = exports_json['exports']
    for export in exports_list:
        api_hash = hashing(export)
        export_hashes[api_hash] = export
    
def hashing(API_name):
    return fnv1a_32(API_name.lower().encode())


def resolve_all_APIs(resolve_ea):
    if resolve_ea is None:
        print('resolve fails..')
        return

    for ref in idautils.CodeRefsTo(resolve_ea, 1):
        # only 1 ref

        curr_ea = ref
        
        next_instruction_ea = idc.next_head(curr_ea)
        if 'ebx' not in idc.GetDisasm(next_instruction_ea):
            hash_val = idc.get_operand_value(next_instruction_ea, 1)
            if hash_val in export_hashes: 
                #idc.set_cmt(ref, export_hashes[hash_val], 0)
                parent_func_addr = idaapi.get_func(ref).start_ea
                print(hex(ref) + ' : ' + export_hashes[hash_val] + ' ' + hex(parent_func_addr))
                idc.set_name(parent_func_addr, "resolve_" + export_hashes[hash_val], idaapi.SN_FORCE)
                
                # set the parent's parent function name
                
                for parentRef in idautils.CodeRefsTo(parent_func_addr, 1):
                    wrapper_parent_func_addr = idaapi.get_func(parentRef).start_ea
                    idc.set_name(wrapper_parent_func_addr, "get_" + export_hashes[hash_val], idaapi.SN_FORCE)
                    for wrapperParentRef in idautils.CodeRefsTo(wrapper_parent_func_addr, 1):
                        idc.set_name(wrapperParentRef, "w_get_" + export_hashes[hash_val], idaapi.SN_FORCE)

export_hashes = {}
setup('C:\\Users\\IEUser\\Desktop\\lockbit\\IDAPython-Malware-Scripts-master\\Lockbit\\exports.json')

# dictionary{key = func_ea, value = API name}
func_hash_dict = {}

resolve_all_APIs(0x406149)
