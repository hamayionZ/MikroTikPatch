import os, lzma, struct, re, argparse

# MikroTik v7 Official Keys (Hex)
MIKRO_NPK_PUB = "c33b9347898862f18390885141e6b3531b402868c78c3c4343166443685e1327"
MIKRO_LIC_PUB = "4a595133644d6736523959326e5535354d6d4a4d6b6e4d50516b32693836374a"

def force_patch(data, old_hex, new_hex, name):
    old_bytes = bytes.fromhex(old_hex)
    new_bytes = bytes.fromhex(new_hex)
    if old_bytes in data:
        print(f"[+] Found {name}! Patching...")
        return data.replace(old_bytes, new_bytes)
    
    # Try shuffled/chunked search if raw fails
    key_map = [28,19,25,16,14,3,24,15,22,8,6,17,11,7,9,23,18,13,10,0,26,21,2,5,20,30,31,4,27,29,1,12]
    old_shf = bytes([old_bytes[i] for i in key_map])
    new_shf = bytes([new_bytes[i] for i in key_map])
    if old_shf in data:
        print(f"[+] Found {name} (Shuffled)! Patching...")
        return data.replace(old_shf, new_shf)
    
    print(f"[-] Could not find {name} in this binary.")
    return data

def patch_kernel_logic(file_path):
    with open(file_path, 'rb') as f: data = f.read()
    
    custom_npk_pub = os.getenv('CUSTOM_NPK_SIGN_PUBLIC_KEY', 'a1'*32)
    custom_lic_pub = os.getenv('CUSTOM_LICENSE_PUBLIC_KEY', 'b2'*32)

    # 1. Patch RAW Kernel
    data = force_patch(data, MIKRO_NPK_PUB, custom_npk_pub, "NPK Public Key")
    data = force_patch(data, MIKRO_LIC_PUB, custom_lic_pub, "License Public Key")

    # 2. Patch vmlinux inside bzImage (if x86)
    if b'\xFD7zXZ' in data:
        print("[*] Compressed data found, attempting decompression...")
        try:
            parts = data.split(b'\xFD7zXZ')
            for i in range(1, len(parts)):
                try:
                    decompressed = lzma.decompress(b'\xFD7zXZ' + parts[i][:100000000])
                    patched_vmlinux = force_patch(decompressed, MIKRO_NPK_PUB, custom_npk_pub, "Internal vmlinux")
                    if patched_vmlinux != decompressed:
                        recompressed = lzma.compress(patched_vmlinux, check=lzma.CHECK_CRC32)
                        # Re-assemble (caution: size must be similar or padded)
                        print("[+] Re-injecting patched vmlinux...")
                        # Simple replacement logic for demo, usually needs careful padding
                        data = data.replace(b'\xFD7zXZ' + parts[i][:len(recompressed)], recompressed)
                except: continue
        except: pass

    with open(file_path, 'wb') as f: f.write(data)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('command')
    parser.add_argument('input')
    args = parser.parse_args()

    if args.command == 'kernel':
        patch_kernel_logic(args.input)
    elif args.command == 'npk':
        # NPK signing logic (use original npk.py logic here)
        print("[*] NPK Patching called...")
