#!/usr/bin/env python3

import re
from pathlib import Path

def parse_opcode_line(line):
    """Parse a line from opcodes.txt and extract the opcode number, name, and parameters"""
    # Match the pattern: (number, Name, param1, param2, ...)
    match = re.match(r'^\s*\((\d+),\s*([^,]+)(?:,\s*(.*))?\)\s*,?$', line.strip())
    if not match:
        return None
    
    opcode_num = int(match.group(1))
    opcode_name = match.group(2).strip()
    
    # Handle parameters
    params_str = match.group(3) if match.group(3) else ""
    params = []
    
    if params_str:
        # Use a custom parser that handles the specific format of opcodes.txt
        # The format is: param1: Type1, param2: Type2, param3: Type3(param4)
        # We need to handle both simple and complex types
        
        # Split by commas, but be careful with complex types that contain parentheses
        i = 0
        current_param = ""
        paren_level = 0
        
        while i < len(params_str):
            char = params_str[i]
            
            if char == '(':
                paren_level += 1
                current_param += char
            elif char == ')':
                paren_level -= 1
                current_param += char
            elif char == ',' and paren_level == 0:
                # This comma separates parameters
                if current_param.strip():
                    params.append(current_param.strip())
                current_param = ""
            else:
                current_param += char
            
            i += 1
        
        # Add the last parameter
        if current_param.strip():
            params.append(current_param.strip())
    
    return opcode_num, opcode_name, params

def convert_param_to_slaspec(param):
    """Convert a parameter from opcodes.txt format to slaspec format"""
    # Handle different parameter patterns
    if ':' in param:
        # Simple pattern: r0: Reg8 -> r0_Reg8
        # Remove any spaces around the colon first, then replace with underscore
        cleaned_param = param.replace(' : ', ':').replace(' :', ':').replace(': ', ':')
        return cleaned_param.replace(':', '_')
    else:
        # Already in correct format or simple parameter
        return param

def generate_slaspec_entry(opcode_num, opcode_name, params):
    """Generate a slaspec entry for the given opcode"""
    # Convert opcode number to hex
    hex_num = f"0x{opcode_num:x}"
    
    # Convert parameters to slaspec format
    slaspec_params = [convert_param_to_slaspec(param) for param in params]
    
    # Build the instruction definition
    if params:
        param_list = ",".join(slaspec_params)
        is_clause = " & op; " + "; ".join(slaspec_params)
        entry = f":{opcode_name} {param_list} is op={hex_num} {is_clause} {{\n}}"
    else:
        entry = f":{opcode_name} is op={hex_num} & op {{\n}}"
    
    return entry

def main():
    # Read opcodes.txt
    opcodes_path = Path(__file__).resolve().parent / 'opcodes.txt'
    with opcodes_path.open('r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Process each line
    for line in lines:
        if line.strip() and not line.strip().startswith('#'):
            result = parse_opcode_line(line)
            if result:
                opcode_num, opcode_name, params = result
                slaspec_entry = generate_slaspec_entry(opcode_num, opcode_name, params)
                print(slaspec_entry)

if __name__ == "__main__":
    main()
