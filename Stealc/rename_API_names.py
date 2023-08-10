import idc

start_Addrs = 0x0041267C
end_Addrs = 0x0041297B
ea = start_Addrs
api_list = []


while start_Addrs <= end_Addrs:

    # Get var_API name 
    if (idc.print_insn_mnem(ea) == "mov") and (idc.get_operand_type(ea, 0) ==idc.o_reg ) and (idc.get_operand_type(ea, 1) == idc.o_mem):
        addr_push = ea
        # print(hex(addr_push))
        op_value = idc.get_operand_value(ea, 1)
        name = idc.get_name(op_value)
        # print(name)
        if name.startswith("var_"):
            temp = name
            # print(name)
    
    # Assign the API name
    if (idc.print_insn_mnem(ea) == "mov") and (idc.get_operand_type(ea, 0) == idc.o_mem) and (idc.print_operand(ea, 1) == "eax"):
        addr = idc.get_operand_value(ea, 0)
        idc.set_name(addr,temp[4:])

    ea = idc.next_head(ea, end_Addrs)

