import re
import random
import string
import argparse

def generate_random_name():
    return ''.join(random.choices(string.ascii_letters, k=16))

def parse_shellcode(file_path):
    with open(file_path, "r") as f:
        data = f.read()
    
    # Extract hex bytes from shellcode definition
    matches = re.findall(r'\\x([0-9a-fA-F]{2})', data)
    shellcode = ''.join(matches)
    
    return shellcode

def format_shellcode(shellcode):
    segments = [shellcode[i:i+16] for i in range(0, len(shellcode), 16)]
    formatted_lines = []
    var_names = []
    total_size = 0
    
    for segment in segments:
        while len(segment) < 16:
            segment += "90"  # Pad with NOPs if not a full 8-byte segment
        total_size += len(segment) // 2  # Convert hex length to byte count
        var_name = generate_random_name()
        var_names.append(var_name)
        formatted_lines.append(f"PVOID {var_name} = EncodePointer((PVOID)0x{segment});")
    
    return formatted_lines, var_names, total_size

def main():
    parser = argparse.ArgumentParser(description="Parse and format shellcode from an input file.")
    parser.add_argument("input_file", help="Path to the input shellcode file")
    args = parser.parse_args()
    
    shellcode = parse_shellcode(args.input_file)
    formatted_shellcode, var_names, total_size = format_shellcode(shellcode)
    
    print(f"Total shellcode size (including padding): {total_size} bytes")
    
    for line in formatted_shellcode:
        print(line)
    
    print("\nstd::vector<PVOID> encodedSegments = {")
    print("    " + ", ".join(var_names) + ",")
    print("};")

if __name__ == "__main__":
    main()
