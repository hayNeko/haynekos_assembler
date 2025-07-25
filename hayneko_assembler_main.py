import json
import re
import itertools
import sys

ISA_CONFIG: dict = {}

class HaynekoAssembler:
    def __init__(self, isa_file):
        with open(isa_file, 'r') as f:
            self.isa = json.load(f)
            global ISA_CONFIG
            ISA_CONFIG = self.isa
        
        # 构建指令集字典
        self.instructions = self.isa['instructions_set']
        
        # 构建寄存器映射 (名称 -> 4位编码)
        self.reg_map = {}
        for reg_id, reg_info in self.isa['architecture']['registers'].items():
            # 跳过没有编码的寄存器（如 rip）
            if 'code' not in reg_info:
                continue
                
            code = reg_info['code']
            # 添加主寄存器名称
            self.reg_map[reg_id] = code
            
            # 添加别名
            if 'name' in reg_info and reg_info['name']:
                for alias in reg_info['name'].split(','):
                    alias = alias.strip().lower()
                    if alias:
                        self.reg_map[alias] = code
        
        # 特殊寄存器处理
        self.reg_map['x0'] = '0000'
        self.reg_map['rax'] = '0001'
        self.reg_map['rcx'] = '0011'
        self.reg_map['rdx'] = '0100'
        self.reg_map['rsp'] = '0101'  # r5h
        self.reg_map['rirp'] = '0101'  # r5l
        self.reg_map['ram'] = '0110'
        self.reg_map['rbm'] = '0111'
        
        # 确保所有 r0-r15 寄存器都存在
        for i in range(16):
            reg_name = f'r{i}'
            if reg_name not in self.reg_map:
                # 使用二进制编码直接创建寄存器映射
                bin_code = bin(i)[2:].zfill(4)
                self.reg_map[reg_name] = bin_code
        
        # 指令地址长度
        self.addr_len = self.isa['architecture']['instruction_address_length']
        self.bit_width = self.isa['architecture']['bit_width']
    
    def assemble_instruction(self, mnemonic, operands) -> int:
        """将汇编指令转换为机器码"""
        mnemonic = mnemonic.lower()
        
        if mnemonic not in self.instructions:
            raise ValueError(f"Unknown instruction: {mnemonic}")
        
        instr = self.instructions[mnemonic]
        code_template = instr['code'].replace(' ', '')
        
        # 检查操作数数量
        if len(operands) != instr['operands']:
            raise ValueError(
                f"Operand count mismatch for {mnemonic}: "
                f"expected {instr['operands']}, got {len(operands)}"
            )
        
        # 将模板分组（连续的相同字符）
        groups = []
        for char, group in itertools.groupby(code_template):
            groups.append((''.join(group), char))
        
        # 解析操作数
        machine_code = ''
        op_index = 0
        
        for group, char in groups:
            if char in '01':  # 固定位
                machine_code += group
            elif char == '-':  # 任意位
                machine_code += '0' * len(group)
            else:  # 占位符
                if op_index >= len(operands):
                    raise ValueError(f"Not enough operands for {mnemonic}")
                
                op = operands[op_index].lower()
                op_index += 1
                
                # 根据占位符类型解析操作数
                if char in ['d', 'r', 's']:  # 寄存器
                    if op not in self.reg_map:
                        # 尝试添加 rX 格式的寄存器
                        if re.match(r'r\d+$', op):
                            reg_num = int(op[1:])
                            if 0 <= reg_num <= 15:
                                bin_code = bin(reg_num)[2:].zfill(4)
                                self.reg_map[op] = bin_code
                            else:
                                raise ValueError(f"Invalid register number: {op}")
                        else:
                            raise ValueError(f"Invalid register: {op}")
                    
                    reg_code = self.reg_map[op]
                    
                    # 对于2位寄存器字段的特殊处理（addi, subi等）
                    if len(group) == 2:
                        # 只允许寄存器 r8-r11 (1000-1011)
                        reg_num = int(reg_code, 2)
                        if reg_num < 8 or reg_num > 11:
                            raise ValueError(
                                f"Register {op} (r{reg_num}) is not in range r8-r11 "
                                f"for {mnemonic} instruction"
                            )
                        # 转换为2位编码：r8=00, r9=01, r10=10, r11=11
                        reg_code_2bit = bin(reg_num - 8)[2:].zfill(2)
                        machine_code += reg_code_2bit
                    else:
                        # 确保寄存器编码长度与模板匹配
                        if len(reg_code) != len(group):
                            raise ValueError(
                                f"Register field length mismatch: expected {len(group)} bits, "
                                f"got {len(reg_code)} bits for {op}"
                            )
                        machine_code += reg_code
                
                elif char == 'i':  # 立即数
                    bits = len(group)
                    imm_str = self.parse_immediate(op, bits)
                    machine_code += imm_str
                
                elif char == 'a':  # 地址
                    bits = len(group)
                    addr_str = self.parse_immediate(op, bits)
                    machine_code += addr_str
                
                elif char == 'p':  # 端口
                    bits = len(group)
                    port_str = self.parse_immediate(op, bits)
                    machine_code += port_str
        
        # 检查是否所有操作数都已使用
        if op_index < len(operands):
            raise ValueError(f"Too many operands for {mnemonic}")
        
        # 转换为16位整数
        return int(machine_code, 2)
    
    def parse_immediate(self, value, bits):
        """解析立即数值并转换为指定位数的二进制字符串"""
        # 处理字符值
        if value.startswith("'") and value.endswith("'"):
            char = value[1:-1]
            if len(char) == 1:
                num = ord(char)
            else:
                raise ValueError(f"Invalid character literal: {value}")
        else:
            try:
                # 支持不同进制表示法
                if value.startswith('0x'):
                    num = int(value[2:], 16)
                elif value.startswith('0b'):
                    num = int(value[2:], 2)
                else:
                    num = int(value)
            except ValueError:
                raise ValueError(f"Invalid immediate value: {value}")
        
        # 检查范围
        max_val = (1 << bits) - 1
        if num < 0 or num > max_val:
            raise ValueError(
                f"Immediate value out of range ({0}-{max_val}): {num}"
            )
        
        # 转换为二进制字符串并填充指定位数
        return bin(num)[2:].zfill(bits)
    
    def get_register_code(self, reg_name):
        """获取寄存器编码（4位二进制字符串）"""
        reg_name = reg_name.lower()
        if reg_name not in self.reg_map:
            # 尝试添加 rX 格式的寄存器
            if re.match(r'r\d+$', reg_name):
                reg_num = int(reg_name[1:])
                if 0 <= reg_num <= 15:
                    bin_code = bin(reg_num)[2:].zfill(4)
                    self.reg_map[reg_name] = bin_code
                else:
                    raise ValueError(f"Invalid register number: {reg_name}")
            else:
                raise ValueError(f"Unknown register: {reg_name}")
        
        return self.reg_map[reg_name]
    
    def get_lines_without_comments(self, lines: list) -> list:
        """正确移除注释并保留行结构"""
        cleaned: list = []
        # 从ISA配置中获取注释字符
        comment_chars = self.isa["architecture"].get("comment_char", [";", "#", "//"])
        
        for line in lines:
            # 移除行尾换行符
            line = line.rstrip()
            # 查找第一个注释字符
            for char in comment_chars:
                if char in line:
                    # 找到第一个注释字符，移除其后的所有内容
                    line = line.split(char)[0]
                    break
            # 移除首尾空白
            line = line.strip()
            if line:
                cleaned.append(line)
        return cleaned
    
    def assemble(self, lines: list) -> list:
        """汇编主函数，支持标签和指令替换"""
        # 移除注释和空白行
        cleaned = self.get_lines_without_comments(lines)
        
        # 第一遍扫描：构建标签表
        label_map = {}
        address = 0  # 当前指令地址
        label_lines = []  # 记录带标签的行
        
        for line in cleaned:
            # 检查标签定义（以冒号结尾）
            if ':' in line:
                parts = line.split(':', 1)  # 只分割第一个冒号
                label = parts[0].strip()
                instruction = parts[1].strip()
                
                # 记录标签地址
                if label:
                    if label in label_map:
                        raise ValueError(f"Duplicate label: {label}")
                    label_map[label] = address
                
                # 如果有指令，则地址递增
                if instruction:
                    label_lines.append(instruction)
                    address += 1
                else:
                    label_lines.append('')
            else:
                # 普通指令行
                label_lines.append(line)
                address += 1
        
        # 第二遍扫描：生成机器码
        machine_codes = []
        for line in label_lines:
            if not line:
                continue  # 跳过空行
                
            # 分割指令和操作数
            parts = re.split(r'[,\s]+', line)
            parts = [p.strip() for p in parts if p.strip()]
            
            if not parts:
                continue
                
            mnemonic = parts[0].lower()
            operands = parts[1:]
            
            # 替换标签为地址值
            for i in range(len(operands)):
                if operands[i] in label_map:
                    operands[i] = str(label_map[operands[i]])
            
            # 汇编指令
            try:
                machine_code = self.assemble_instruction(mnemonic, operands)
                machine_codes.append(machine_code)
            except Exception as e:
                raise ValueError(f"Assembly error at line: {line}\nError: {str(e)}")
        
        return machine_codes


def main(read_path: str, write_path: str) -> None:
    """
    主函数，用于将汇编代码转换为机器码并写入文件。
    :param read_path: 汇编代码文件路径
    :param write_path: 机器码文件路径
    """
    assembler = HaynekoAssembler("isa.json")
    
    try:
        with open(read_path, 'r') as f:
            lines = f.readlines()
        
        # 汇编代码
        machine_codes = assembler.assemble(lines)
        
        # 写入二进制文件
        with open(write_path, 'w') as f:
            for code in machine_codes:
                # 转换为16位二进制字符串
                bin_str = bin(code)[2:].zfill(16)
                f.write(bin_str + '\n')
        
        print(f"Successfully assembled {len(machine_codes)} instructions to {write_path}")
        
    except Exception as e:
        print(f"Assembly failed: {str(e)}")
        sys.exit(1)

def start_with_cmd() -> None:
    """
    用于命令行启动。
    """
    if len(sys.argv) != 3:
        print("Usage: python hayneko_assembler.py <input.asm> <output.bin>")
        sys.exit(1)
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    main(input_file, output_file)

if __name__ == "__main__":
    main("py_cpu_sim/a_input.asm", "py_cpu_sim/a_output.bin")