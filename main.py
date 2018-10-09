from pefile import *
from capstone import *
import os
import re

# 使用capstone库获得文件头中的信息
# 存储函数的开始地址
fun_list = []
# 存储函数
functions = []
# 存储函数的调用关系
function_graph = []
# 存储局部变量
local_var = {}
# 函数内部的for、if、switch的调用情况
internal_function = []
# 存储jcc指令集
jcc_instruction = ['jne', 'jz', 'je', 'jnz', 'js', 'jns', 'jp', 'jpe', 'jnp', 'jpo', 'jo', 'jno', 'jc', 'jb', 'jnae',
                   'jnc', 'jnb', 'jae', 'jbe', 'jna', 'jnbe', 'ja', 'jl', 'jnge', 'jnl', 'jge', 'jle', 'jng', 'jnle',
                   'jg']
# for跳转指令的位置
for_instruction = []
# 用于判断不会困在FOR循环里面的list
break_for = []
# main函数的入口地址
main_address = ""
# 存储switch结构
switch_ins = []
#switch跳转表的内存范围
switch_table = []

# 完成预处理工作
def get_bin_file(filename):
    with open(filename, 'rb') as f:
        buffer = f.read()
    p = re.compile(r'0x[0-9a-fA-F]+')
    pe = PE(filename)
    sections = pe.sections

    # 获取文件头中的信息
    OPTIONAL_HEADER = pe.OPTIONAL_HEADER
    image_base = OPTIONAL_HEADER.ImageBase
    entry_point = OPTIONAL_HEADER.AddressOfEntryPoint
    fun_list.append(hex(image_base + entry_point))
    main_address = hex(image_base + entry_point)
    entry_main = hex(image_base + entry_point)
    # 获取导入函数表
    imported_fun = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for dll in pe.DIRECTORY_ENTRY_IMPORT:
            for symbol in dll.imports:
                imported_fun[hex(symbol.address)] = {'name': symbol.name.decode(), 'dll': dll.dll}

    # 获取.text节的数据
    for i in range(0, len(sections)):
        # entry_point必定处于代码段内
        if sections[i].VirtualAddress <= entry_point <= sections[i].VirtualAddress + sections[i].Misc_VirtualSize:
            text = sections[i]

    text_va = text.VirtualAddress
    text_vs = text.Misc_VirtualSize
    text_data = text.get_data()[:text_vs]

    # 获取.data节的数据
    data = sections[2]
    data_va = data.VirtualAddress
    data_vs = data.Misc_VirtualSize
    data_data = data.get_data()[:data_vs]

    return entry_main, p, image_base, imported_fun, text_va, text_vs, text_data, data_va, data_vs, data_data, main_address


# 获取的外部函数
def get_dll(p, assembles, imported_fun):
    print(imported_fun)
    index = 0
    dll_address = []
    dll_function = []
    for address, size, mnemonic, op_str in assembles:
        if mnemonic == 'jmp' or mnemonic == 'call':
            if p.findall(op_str) != []:
                func_address = p.findall(op_str)[0]
                if func_address in imported_fun:
                    assembles[index][3] = imported_fun[func_address]['name']
                    dll_address.append(hex(address))
                    dll_function.append(imported_fun[func_address]['name'])
        index += 1
    index = 0
    for address, size, mnemonic, op_str in assembles:
        if op_str in dll_address:
            assembles[index][3] = dll_function[dll_address.index(op_str)]
        index += 1
    index = 0
    for address, size, mnemonic, op_str in assembles:
        if mnemonic == 'call' and op_str.find("0x") >= 0 and op_str not in fun_list:
            fun_list.append(op_str)

    fun_list.sort()
    return assembles


# 获取全局变量
def get_global_var(p, assembles, data_va, data_vs, data_data, image_base):
    global_var = []
    index = 0
    for address, size, mnemonic, op_str in assembles:
        # MOVSX是按有符号数扩展，MOVZX是按无符号数扩展
        if (mnemonic == 'mov' or mnemonic == 'movsx' or mnemonic == 'movzx') and op_str.find('ptr') > 0:
            target = p.findall((op_str.split('[')[1]).split(']')[0])
            if len(target):
                target = int(target[0], 16) - image_base
                if data_va <= target < data_va + data_vs:
                    # 查看是int类型数据或是char数据
                    if op_str.split(' ')[1] == 'dword':
                        global_var.append(["int" + str(index), get_int_from_string(target, data_va, data_data)])
                    else:
                        global_var.append(["char" + str(index), translate_str(target, data_va, data_data)])
    return global_var


# 返回地址处存取的整形数据
def get_int_from_string(va, rdata_va, rdata_data):
    int_var = 0
    for i in range(1, 5):
        ch = rdata_data[va - rdata_va]
        if ch % 10 != ch:
            int_var += (ch - ch % 10) ** ((16) ** (i))
            int_var += (ch % 10) ** ((16) ** (i - 1))
        if ch % 10 == ch and ch != 0:
            int_var += (ch % 10) ** ((16) ** (i - 1))
        va += 1
    return int_var


# 获得程序中的字符串变量
def get_string(p, assembles, data_va, data_vs, data_data, image_base):
    index = 0
    for address, size, mnemonic, op_str in assembles:
        if mnemonic == 'push':
            # 该指令在程序中的地址
            target = p.findall(op_str)
            if len(target):
                # 得到它在程序里的偏移地址
                target = int(target[0], 16) - image_base
                # rdata的地址范围
                if data_va <= target < data_va + data_vs:
                    string = translate_str(target, data_va, data_data)
                    # 如果成功获取（获取失败的话字符串长度为0）
                    if len(string):
                        assembles[index][3] += "(\"" + string + "\")"
        index += 1
        # print("0x%x:\t%s \t%s" % (address, mnemonic, op_str))
    return assembles


# 返回地址处所存储的字符串
def translate_str(va, rdata_va, rdata_data):
    str = ''
    while True:
        ch = rdata_data[va - rdata_va]
        if ch not in range(32, 128):
            if ch == 0:
                return str
            else:
                return ''
        str += chr(ch)
        va += 1
    return str


# 得到函数的调用关系
def get_function(p, assembles):
    translate_MessageBox(assembles)
    print("\n===============================相关函数调用关系======================================\n")
    for address, size, mnemonic, op_str in assembles:
        if mnemonic == 'call':
            # print("函数调用关系:0x%x -> %s" % (address, op_str))
            for i in range(0, len(fun_list) - 1):
                # print("%d <= %d <= %d"%(int(fun_list[i],16),address,int(fun_list[i+1],16)))
                if int(fun_list[i], 16) <= address <= int(fun_list[i + 1], 16):
                    function_graph.append([fun_list[i], op_str])
                    print("%s -> %s " % (fun_list[i], op_str))
                    break
                if address > int(fun_list[3], 16):
                    function_graph.append([fun_list[3], op_str])
                    print("%s -> %s" % (fun_list[i], op_str))
                    break
    index = 0
    fun_index = 0
    functions = [[] for i in range(0, len(fun_list))]
    ini_assembles = assembles
    print("\n\n==========================函数体详细信息=============================\n")
    for i in range(0, len(fun_list)):
        print("==========================%s================================" % fun_list[i])
        for address, size, mnemonic, op_str in assembles:
            if mnemonic != 'int3':
                print("0x%x:\t%s \t%s" % (address, mnemonic, op_str))
                functions[fun_index].append([address, mnemonic, op_str])
            index += 1
            if mnemonic == 'ret':
                assembles = ini_assembles[index:]
                fun_index += 1
                break
    print(fun_list)
    return functions, function_graph

def get_real_function():
    length = len(functions)
    del_list = []
    for i in range(0,length):
        if functions[i][-1][1] != 'ret':
            del_list.append(i)
    for i in del_list:
        del functions[i]


# 将MessageBox的函数调用关系给出
def translate_MessageBox(assembles):
    index = 0
    messagebox_para_value = []
    for address, size, mnemonic, op_str in assembles:
        if op_str == 'MessageBoxA':
            index_temp = index
            while True:
                index_temp -= 1
                if assembles[index_temp][2] == 'push' and assembles[index_temp][3].find("\"") < 0:
                    messagebox_para_value.append(assembles[index_temp][3])
                if assembles[index_temp][2] == 'push' and assembles[index_temp][3].find("\"") > 0:
                    string_temp = assembles[index_temp][3].split('\"')[1]
                    messagebox_para_value.append(string_temp.split('\"')[0])
                if assembles[index_temp][2] != 'push':
                    break
            assembles[index][3] += "("
            for i in range(0, len(messagebox_para_value)):
                assembles[index][3] += messagebox_para_value[i]
                assembles[index][3] += ","
            assembles[index][3] += ")"
            messagebox_para_value = []
        index += 1
        # print(op_str.split("(")[1].split(")")[0])


# 打印函数的参数
def get_function_para(assembles):
    print("\n========================================函数参数个数===================================================")
    print(len(functions))
    for i in range(0, len(functions)):
        print(functions[i][-1][2])
        print(functions[i][-1][1])
        if functions[i][-1][2] == '' and functions[i][-1][1] == 'ret':
            for ii in range(0, len(function_graph)):
                if hex(functions[i][0][0]) == function_graph[ii][1]:
                    print("函数%s的参数个数为" % hex(functions[i][0][0]), end='')
                    for ii in range(0, len(assembles)):
                        if assembles[ii][2] == 'call' and assembles[ii + 1][2] == 'add' and assembles[ii][3] == hex(
                                functions[i][0][0]):
                            print(int(assembles[ii + 1][3].split(' ')[1], 16) / 4)
                        if assembles[ii][2] == 'call' and assembles[ii + 1][2] != 'add' and assembles[ii][3] == hex(
                                functions[i][0][0]):
                            print(int(assembles[ii + 1][3].split(' ')[0], 16) / 4)
        elif functions[i][-1][1] == 'ret':
            print("函数%s的参数个数为" % hex(functions[i][0][0]), end='')
            print(int(functions[i][-1][2]) / 4)


# 获取局部变量
def get_local_var():
    print("\n=================================================函数的局部变量================================================")
    for func in functions:
        int_index = 0
        char_index = 0
        temp_local_var = {}
        index_functions = 0
        print("0x%x函数的局部变量:" % func[0][0])
        for address, mnemonic, op_str in func:
            index_func = 0
            if 'ebp -' in op_str:
                temp = op_str.split(' ')
                variable_address = temp[4][:-2]
                if variable_address not in temp_local_var and variable_address != '':
                    variable_type = temp[0]
                    if variable_type == 'dword':
                        temp_local_var[variable_address] = 'int' + str(int_index)
                        functions[index_functions][index_func][2] = 'int' + str(int_index)
                        int_index += 1
                    elif variable_type == 'byte':
                        temp_local_var[variable_address] = 'c' + str(char_index)
                        functions[index_functions][index_func][2] = 'char' + str(char_index)
                        char_index += 1
                    print(temp_local_var[variable_address])
            index_func += 1
        index_functions += 1
        local_var[func[0][0]] = temp_local_var
        print("\n\n")


#分析if、for、switch的逻辑情况
def new_analyze_if(funs, funs_number, start_flag, text_data, text_va, image_base):
    index = 0
    jump_address = ''
    add_index = 0
    re_start_if = ''
    temp_re_start_if = ''
    # 用来判断是否是嵌套if的情况
    if_flag = 0
    # 用来判断if是否在这段里面已经出现过
    if_exist = 0
    # 用来判读switch是否存在
    switch_flag = 0
    for address, mnemonic, op_str in funs:
        if index > 2:
            if mnemonic == 'cmp' and funs[index - 2][1] == 'sub' and is_switch_jmp(hex(address)):
                switch_ins.append([hex(funs[0][0]), hex(address)])
                find_switch(funs[index:], text_data, text_va, image_base)
                switch_flag = 1
                switch_start_address = address
        if index < len(funs) - 1 and index >= 0 and is_switch_jmp(hex(address)) and op_str.find('edx') < 0:
            if mnemonic == 'cmp' and funs[index + 1][1] in jcc_instruction and is_already_exist(hex(funs[0][0]),
                                                                                                hex(address),
                                                                                                funs_number) and is_already_exist(
                hex(address), funs[index + 1][2],
                funs_number) and is_already_exist(hex(address), hex(funs[index + 2][0]),
                                                  funs_number):
                if start_flag == 1:
                    internal_function[funs_number].append([hex(funs[0][0]), hex(address)])
                    start_flag = 0
                elif start_flag != 1 and is_if_start(hex(funs[0][0]), funs_number) and hex(funs[0][0]) != hex(address):

                    re_start_if = hex(address)
                    temp_re_start_if = re_start_if
                    internal_function[funs_number].append([hex(funs[0][0]), hex(address)])
                if if_flag != 0 and jump_address < hex(address):
                    internal_function[funs_number].append([hex(jump_address), hex(address)])
                elif if_flag != 0 and hex(temp_if) < hex(address):
                    internal_function[funs_number].append([hex(temp_if), hex(address)])

                internal_function[funs_number].append([hex(address), funs[index + 1][2]])
                internal_function[funs_number].append([hex(address), hex(funs[index + 2][0])])
                jump_address = funs[index + 1][2]
                temp_else = funs[index + 1][2]
                temp_if = funs[index + 2][0]
                if_flag += 1
                if_exist += 1
                new_start = search_address(funs[index + 1][2], funs)
                re_start_if, add_index = new_analyze_if(funs[new_start:], funs_number, start_flag, text_data, text_va,
                                                        image_base)
                if re_start_if == "":
                    re_start_if = temp_re_start_if
            if hex(address) == jump_address and funs[index - 1][1] != 'jmp' and is_already_exist(hex(temp_if),
                                                                                                 hex(address),
                                                                                                 funs_number):
                internal_function[funs_number].append([hex(temp_if), hex(address)])
                if_flag -= 1
            if index < len(funs) - 2:
                if hex(funs[index + 1][0]) == jump_address and mnemonic == 'jmp' and is_already_exist(temp_if, op_str,
                                                                                                      funs_number):
                    internal_function[funs_number].append([hex(temp_if), op_str])
                    if op_str > jump_address:
                        internal_function[funs_number].append([jump_address, op_str])
                    if re_start_if != '':
                        if int(op_str, 16) < int(re_start_if, 16):
                            internal_function[funs_number].append([op_str, re_start_if])
                    if_flag -= 1
            if mnemonic == 'jmp' and funs[index + 1][1] not in jcc_instruction and if_exist == 0:
                break
            if mnemonic == 'jmp' and internal_function[funs_number][-1][1] not in break_for and \
                            internal_function[funs_number][-1][1] != op_str and funs[index + 1][
                1] not in jcc_instruction and if_exist != 0 and internal_function[funs_number][-1][1] < hex(
                address) and is_already_exist(internal_function[funs_number][-1][1], op_str, funs_number):
                break_for.append(internal_function[funs_number][-1][1])
                internal_function[funs_number].append([internal_function[funs_number][-1][1], op_str])
        index += 1
        if index + add_index == len(funs) + 1:
            break

    return re_start_if, index


# 寻找switch表
def find_switch(funs, text_data, text_va, image_base):
    end_adress = funs[1][2]
    basis_address = (funs[3][2].split(" ")[4]).split(']')[0]
    max = int(funs[0][2].split(' ')[5]) + 1
    target = int(basis_address, 16) - image_base
    switch_table.append([hex(int(basis_address,16)-3),hex(int(basis_address,16)+4*max+6)])
    for i in range(0, max):
        case_address = get_switch_table(text_data, target + i * 4, text_va)
        if traverse_switch(case_address, end_adress):
            switch_ins.append([hex(funs[0][0]), case_address])
            switch_ins.append([case_address, end_adress])


# 查找该函数是否存在switch中
def traverse_switch(start, end):
    for address1, address2 in switch_ins:
        if address1 == start and address2 == end:
            return False
    return True


# 得到跳转表中的位置
def get_switch_table(text_data, va, text_va):
    str = ''
    index = 3
    for i in range(0, 4):
        if text_data[va - text_va + index] != '':
            ch = (hex(text_data[va - text_va + index])).split('x')[1]
            if len(ch) == 1 and ch != '0':
                ch = '0' + ch
            if ch != '0':
                str += ch
            index -= 1
    str = '0x' + str
    return str


# 查看当前跳转指令是否存在switch表中
def is_switch_jmp(target):
    for address1, address2 in switch_ins:
        if address1 == target:
            return False
    return True

# 将switch合并进去
def joint_switch(funs_number):
    index = 0
    for address1,address2 in internal_function[funs_number]:
        if address1 == switch_ins[0][0]:
            del internal_function[funs_number][index]
        index += 1
    for i in range(0,len(switch_ins)):
        internal_function[funs_number].append(switch_ins[i])



# 查找地址在函数中的位置,针对参数为3 个的数值
def search_address(target, funs):
    index = 0
    for address, mnemonic, op_str in funs:
        if hex(address) == target:
            return index
        index += 1


# 查看函数是否已经存在
def is_already_exist(address1, address2, funsnumber):
    for a, b in internal_function[funsnumber]:
        if a == address1 and b == address2:
            return False
    return True


# 查看函数是否已经在末尾
def add_if_end():
    for i in range(0, len(internal_function)):
        for address1, address2 in internal_function[i]:
            if is_if_start(address2, i) and address2 != 'end':
                if address2 > main_address:
                    internal_function[i].append([address2, "end"])
                elif address2 < main_address and address2 != hex(functions[i][-1][0]):
                    internal_function[i].append([address2, hex(functions[i][-1][0])])


# 寻找for循环的位置
def find_for():
    index = 0
    for i in range(0, len(functions)):
        for address, mnemonic, op_str in functions[i]:
            if mnemonic == 'jmp' and hex(address) > op_str:
                for_instruction.append(op_str)
    for i in range(0, len(internal_function)):
        index = 0
        for start_address, end_adress in internal_function[i]:
            if start_address in for_instruction:
                del internal_function[i][index]
                ass_new_start = search_address(start_address, functions[i])
                ass = functions[i][ass_new_start:]
                for address, mnemonic, op_str in ass:
                    if mnemonic == 'cmp':
                        internal_function[i].append([start_address, hex(address)])
                        break
            # 添加main的入口
            if start_address == main_address:
                internal_function[i][index][0] = "main"
            index += 1


# 如果for循环处于末尾，添加end
# def add_for_end():
#     for i in range(0,len(internal_function)):
#         for address1,address2 in internal_function[i]:
#             if address1 > address2:


# 查看地址是否已经存在开头
def is_if_start(start, funsnumber):
    for a, b in internal_function[funsnumber]:
        if start == a:
            return False
    return True


if __name__ == '__main__':
    # entry_main为main函数入口
    entry_main, p, image_base, imported_fun, text_va, text_vs, text_data, data_va, data_vs, data_data, main_address = get_bin_file(
        'main.exe')
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    assembles = list([address, size, mnemonic, op_str]
                     for address, size, mnemonic, op_str in md.disasm_lite(text_data, image_base + text_va))
    for address, size, mnemonic, op_str in assembles:
        print("0x%x:\t%s \t%s" % (address, mnemonic, op_str))
    # 获取外部函数
    assembles = get_dll(p, assembles, imported_fun)
    # 获取字符串
    assembles = get_string(p, assembles, data_va, data_vs, data_data, image_base)
    # 获取函数的调用关系
    functions, function_graph = get_function(p, assembles)
    get_real_function()
    # 获取函数的参数
    get_function_para(assembles)
    # 获取全局变量
    globals_var = get_global_var(p, assembles, data_va, data_vs, data_data, image_base)
    print(
        "\n==============================================全局变量=============================================================\n")
    for type, value in globals_var:
        print("%s:%s" % (type, value))
    # 获取局部变量
    get_local_var()
    # 打印反汇编代码
    print("=================================================反汇编代码===========================================\n")
    for address, size, mnemonic, op_str in assembles:
        print("0x%x:\t%s \t%s" % (address, mnemonic, op_str))
    # 分块寻找if\for
    internal_function = [[] for i in range(0, len(functions))]
    for i in range(0, len(functions)):
        a, b = new_analyze_if(functions[i], i, 1, text_data, text_va, image_base)
        if internal_function[i] != [] and switch_ins != []:
            joint_switch(i)
            switch_ins = []
    # 添加函数的结尾符号
    add_if_end()
    # 链接for循环
    find_for()
    # 函数添加结尾
    for i in range(0, len(internal_function)):
        if internal_function[i] == []:
            internal_function[i].append([hex(functions[i][0][0]), hex(functions[i][-1][0])])
    # 打印函数内部具体执行流程
    print("\n==================================================函数内部执行流程图=====================================\n")
    for i in range(0, len(internal_function)):
        index = 0
        for address1, address2 in internal_function[i] :
            if [address1,address2] not in switch_table:
                print("\"%s\" -> \"%s\" ;" % (address1, address2))
            index += 1
    # 打印函数调用关系
    print("\n===============================================函数调用关系==========================================\n")
    for start, end in function_graph:
        if end not in switch_table:
            print("\"%s\" -> \"%s\" ;" % (start, end))

