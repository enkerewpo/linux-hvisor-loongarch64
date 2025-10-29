#!/usr/bin/env python3
"""
Enhanced vmlinux.efi Binary Structure Analyzer
Detailed analysis of vmlinux.efi including relocation tables and binary content
"""

import struct
import sys
import os
from typing import Dict, List, Tuple, Optional

class ELFAnalyzer:
    """Enhanced ELF file analyzer with relocation support"""
    
    def __init__(self, data: bytes, offset: int = 0):
        self.data = data
        self.offset = offset
        self.elf_header = None
        self.sections = []
        self.relocations = []
        self._parse_elf_header()
        self._parse_sections()
        self._parse_relocations()
    
    def _parse_elf_header(self):
        """Parse ELF header"""
        if self.offset + 64 > len(self.data):
            raise ValueError("Not enough data for ELF header")
        
        header_data = self.data[self.offset:self.offset+64]
        
        if header_data[0:4] != b'\x7fELF':
            raise ValueError("Invalid ELF magic")
        
        self.elf_header = {
            'magic': header_data[0:4],
            'class': header_data[4],
            'data': header_data[5],
            'version': header_data[6],
            'os_abi': header_data[7],
            'abi_version': header_data[8],
            'type': struct.unpack('<H', header_data[16:18])[0],
            'machine': struct.unpack('<H', header_data[18:20])[0],
            'version': struct.unpack('<I', header_data[20:24])[0],
            'entry': struct.unpack('<Q', header_data[24:32])[0],
            'phoff': struct.unpack('<Q', header_data[32:40])[0],
            'shoff': struct.unpack('<Q', header_data[40:48])[0],
            'flags': struct.unpack('<I', header_data[48:52])[0],
            'ehsize': struct.unpack('<H', header_data[52:54])[0],
            'phentsize': struct.unpack('<H', header_data[54:56])[0],
            'phnum': struct.unpack('<H', header_data[56:58])[0],
            'shentsize': struct.unpack('<H', header_data[58:60])[0],
            'shnum': struct.unpack('<H', header_data[60:62])[0],
            'shstrndx': struct.unpack('<H', header_data[62:64])[0]
        }
    
    def _parse_sections(self):
        """Parse section headers"""
        if not self.elf_header:
            return
        
        shoff = self.elf_header['shoff']
        shentsize = self.elf_header['shentsize']
        shnum = self.elf_header['shnum']
        shstrndx = self.elf_header['shstrndx']
        
        # Read string table
        strtab_offset = shoff + shstrndx * shentsize
        strtab_header = self.data[self.offset + strtab_offset:self.offset + strtab_offset + shentsize]
        strtab_addr = struct.unpack('<Q', strtab_header[16:24])[0]
        strtab_size = struct.unpack('<Q', strtab_header[32:40])[0]
        strtab_offset = struct.unpack('<Q', strtab_header[24:32])[0]
        
        strtab_data = self.data[self.offset + strtab_offset:self.offset + strtab_offset + strtab_size]
        
        # Parse all section headers
        for i in range(shnum):
            sh_offset = shoff + i * shentsize
            sh_data = self.data[self.offset + sh_offset:self.offset + sh_offset + shentsize]
            
            sh_name_idx = struct.unpack('<I', sh_data[0:4])[0]
            sh_type = struct.unpack('<I', sh_data[4:8])[0]
            sh_flags = struct.unpack('<Q', sh_data[8:16])[0]
            sh_addr = struct.unpack('<Q', sh_data[16:24])[0]
            sh_offset = struct.unpack('<Q', sh_data[24:32])[0]
            sh_size = struct.unpack('<Q', sh_data[32:40])[0]
            sh_link = struct.unpack('<I', sh_data[40:44])[0]
            sh_info = struct.unpack('<I', sh_data[44:48])[0]
            sh_addralign = struct.unpack('<Q', sh_data[48:56])[0]
            sh_entsize = struct.unpack('<Q', sh_data[56:64])[0]
            
            # Get section name
            if sh_name_idx < len(strtab_data):
                name_end = strtab_data.find(b'\x00', sh_name_idx)
                if name_end == -1:
                    name_end = len(strtab_data)
                sh_name = strtab_data[sh_name_idx:name_end].decode('ascii', errors='ignore')
            else:
                sh_name = f"section_{i}"
            
            section = {
                'name': sh_name,
                'type': sh_type,
                'flags': sh_flags,
                'addr': sh_addr,
                'offset': sh_offset,
                'size': sh_size,
                'link': sh_link,
                'info': sh_info,
                'addralign': sh_addralign,
                'entsize': sh_entsize
            }
            self.sections.append(section)
    
    def _parse_relocations(self):
        """Parse relocation tables"""
        # Find .rela.dyn section
        rela_section = self.get_section_by_name('.rela.dyn')
        if not rela_section:
            return
        
        rela_offset = rela_section['offset']
        rela_size = rela_section['size']
        rela_entsize = rela_section['entsize'] or 24  # Default size for RELA entries
        
        num_relocs = rela_size // rela_entsize
        
        for i in range(num_relocs):
            rel_offset = rela_offset + i * rela_entsize
            if rel_offset + rela_entsize > len(self.data):
                break
            
            rel_data = self.data[self.offset + rel_offset:self.offset + rel_offset + rela_entsize]
            
            r_offset = struct.unpack('<Q', rel_data[0:8])[0]
            r_info = struct.unpack('<Q', rel_data[8:16])[0]
            r_addend = struct.unpack('<q', rel_data[16:24])[0]
            
            rel_type = r_info & 0xffffffff
            sym_index = r_info >> 32
            
            relocation = {
                'offset': r_offset,
                'type': rel_type,
                'sym_index': sym_index,
                'addend': r_addend
            }
            self.relocations.append(relocation)
    
    def get_section_by_name(self, name: str) -> Optional[Dict]:
        """Get section by name"""
        for section in self.sections:
            if section['name'] == name:
                return section
        return None
    
    def print_info(self):
        """Print ELF information"""
        if not self.elf_header:
            return
        
        print(f"ELF Header:")
        print(f"  Magic: {self.elf_header['magic'].hex()}")
        print(f"  Class: {self.elf_header['class']} ({'32-bit' if self.elf_header['class'] == 1 else '64-bit'})")
        print(f"  Data: {self.elf_header['data']} ({'little-endian' if self.elf_header['data'] == 1 else 'big-endian'})")
        
        type_names = {1: 'ET_REL', 2: 'ET_EXEC', 3: 'ET_DYN', 4: 'ET_CORE'}
        print(f"  Type: {self.elf_header['type']} ({type_names.get(self.elf_header['type'], 'Unknown')})")
        
        machine_names = {0x102: 'LoongArch', 0x3e: 'x86-64', 0x28: 'ARM64'}
        print(f"  Machine: 0x{self.elf_header['machine']:x} ({machine_names.get(self.elf_header['machine'], 'Unknown')})")
        print(f"  Entry point: 0x{self.elf_header['entry']:x}")
        print(f"  Section headers: {self.elf_header['shnum']} entries")
        print()
        
        print("Sections:")
        for i, section in enumerate(self.sections):
            type_names = {0: 'NULL', 1: 'PROGBITS', 3: 'STRTAB', 5: 'HASH', 6: 'DYNAMIC', 7: 'NOTE', 11: 'DYNSYM'}
            type_name = type_names.get(section['type'], f'0x{section["type"]:x}')
            print(f"  [{i:2d}] {section['name']:<20} {type_name:<10} addr=0x{section['addr']:016x} offset=0x{section['offset']:08x} size=0x{section['size']:08x}")
        print()
        
        # Print relocation information
        if self.relocations:
            print(f"Relocations ({len(self.relocations)} entries):")
            rel_type_names = {1: 'R_LARCH_32', 2: 'R_LARCH_64', 3: 'R_LARCH_RELATIVE', 4: 'R_LARCH_COPY', 5: 'R_LARCH_JUMP_SLOT', 6: 'R_LARCH_TLS_DTPMOD32', 7: 'R_LARCH_TLS_DTPMOD64', 8: 'R_LARCH_TLS_DTPREL32', 9: 'R_LARCH_TLS_DTPREL64', 10: 'R_LARCH_TLS_TPREL32', 11: 'R_LARCH_TLS_TPREL64'}
            
            for i, rel in enumerate(self.relocations[:10]):  # Show first 10
                rel_type_name = rel_type_names.get(rel['type'], f'0x{rel["type"]:x}')
                print(f"  [{i:2d}] offset=0x{rel['offset']:016x} type={rel_type_name} sym={rel['sym_index']} addend=0x{rel['addend']:016x}")
            
            if len(self.relocations) > 10:
                print(f"  ... and {len(self.relocations) - 10} more relocations")
            print()

class PEAnalyzer:
    """PE32+ file analyzer"""
    
    def __init__(self, data: bytes):
        self.data = data
        self.dos_header = None
        self.pe_header = None
        self.sections = []
        self._parse_dos_header()
        self._parse_pe_header()
        self._parse_sections()
    
    def _parse_dos_header(self):
        """Parse DOS header"""
        if len(self.data) < 64:
            raise ValueError("Not enough data for DOS header")
        
        if self.data[0:2] != b'MZ':
            raise ValueError("Invalid DOS header")
        
        self.dos_header = {
            'magic': self.data[0:2],
            'pe_offset': struct.unpack('<I', self.data[0x3c:0x40])[0]
        }
    
    def _parse_pe_header(self):
        """Parse PE header"""
        if not self.dos_header:
            return
        
        pe_offset = self.dos_header['pe_offset']
        if pe_offset + 24 > len(self.data):
            raise ValueError("Not enough data for PE header")
        
        if self.data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            raise ValueError("Invalid PE signature")
        
        pe_data = self.data[pe_offset+4:pe_offset+24]
        
        self.pe_header = {
            'signature': self.data[pe_offset:pe_offset+4],
            'machine': struct.unpack('<H', pe_data[0:2])[0],
            'num_sections': struct.unpack('<H', pe_data[2:4])[0],
            'timestamp': struct.unpack('<I', pe_data[4:8])[0],
            'ptr_to_symbol_table': struct.unpack('<I', pe_data[8:12])[0],
            'num_symbols': struct.unpack('<I', pe_data[12:16])[0],
            'size_of_optional_header': struct.unpack('<H', pe_data[16:18])[0],
            'characteristics': struct.unpack('<H', pe_data[18:20])[0]
        }
    
    def _parse_sections(self):
        """Parse PE sections"""
        if not self.pe_header:
            return
        
        pe_offset = self.dos_header['pe_offset']
        section_headers_offset = pe_offset + 24 + self.pe_header['size_of_optional_header']
        
        for i in range(self.pe_header['num_sections']):
            sh_offset = section_headers_offset + i * 40
            if sh_offset + 40 > len(self.data):
                break
            
            sh_data = self.data[sh_offset:sh_offset+40]
            
            name = sh_data[0:8].decode('ascii', errors='ignore').rstrip('\x00')
            virtual_size = struct.unpack('<I', sh_data[8:12])[0]
            virtual_addr = struct.unpack('<I', sh_data[12:16])[0]
            raw_size = struct.unpack('<I', sh_data[16:20])[0]
            raw_addr = struct.unpack('<I', sh_data[20:24])[0]
            reloc_addr = struct.unpack('<I', sh_data[24:28])[0]
            line_num_addr = struct.unpack('<I', sh_data[28:32])[0]
            num_relocs = struct.unpack('<H', sh_data[32:34])[0]
            num_line_nums = struct.unpack('<H', sh_data[34:36])[0]
            characteristics = struct.unpack('<I', sh_data[36:40])[0]
            
            section = {
                'name': name,
                'virtual_size': virtual_size,
                'virtual_addr': virtual_addr,
                'raw_size': raw_size,
                'raw_addr': raw_addr,
                'reloc_addr': reloc_addr,
                'line_num_addr': line_num_addr,
                'num_relocs': num_relocs,
                'num_line_nums': num_line_nums,
                'characteristics': characteristics
            }
            self.sections.append(section)
    
    def print_info(self):
        """Print PE information"""
        if not self.pe_header:
            return
        
        print(f"PE32+ Header:")
        print(f"  Signature: {self.pe_header['signature']}")
        
        machine_names = {0x6264: 'LoongArch64', 0x8664: 'x86-64', 0x014c: 'x86'}
        print(f"  Machine: 0x{self.pe_header['machine']:x} ({machine_names.get(self.pe_header['machine'], 'Unknown')})")
        print(f"  Number of sections: {self.pe_header['num_sections']}")
        print(f"  Characteristics: 0x{self.pe_header['characteristics']:x}")
        print()
        
        print("PE Sections:")
        for i, section in enumerate(self.sections):
            print(f"  [{i}] {section['name']:<8} vaddr=0x{section['virtual_addr']:08x} vsize=0x{section['virtual_size']:08x} raddr=0x{section['raw_addr']:08x} rsize=0x{section['raw_size']:08x}")
        print()

def find_elf_structures(data: bytes) -> List[Tuple[int, int]]:
    """Find ELF structures in the binary"""
    elf_positions = []
    pos = 0
    
    while True:
        pos = data.find(b'\x7fELF', pos)
        if pos == -1:
            break
        
        if pos + 64 <= len(data):
            try:
                elf_type = struct.unpack('<H', data[pos+16:pos+18])[0]
                machine = struct.unpack('<H', data[pos+18:pos+20])[0]
                
                if machine == 0x102:  # LoongArch
                    elf_positions.append((pos, elf_type))
            except:
                pass
        
        pos += 1
    
    return elf_positions

def analyze_binary_content(data: bytes, start: int, end: int, name: str):
    """Analyze binary content in a specific range"""
    print(f"{name} Content Analysis (0x{start:x} - 0x{end:x}):")
    print("-" * 50)
    
    if start >= len(data) or end > len(data) or start >= end:
        print("  Invalid range")
        return
    
    content = data[start:end]
    
    # Check for common patterns
    if b'\x7fELF' in content:
        print("  Contains ELF structure")
    
    if b'PE\x00\x00' in content:
        print("  Contains PE structure")
    
    # Check for strings
    strings = []
    current_string = b""
    for byte in content:
        if 32 <= byte <= 126:  # Printable ASCII
            current_string += bytes([byte])
        else:
            if len(current_string) >= 4:
                strings.append(current_string.decode('ascii'))
            current_string = b""
    
    if strings:
        print(f"  Found {len(strings)} strings:")
        for s in strings[:10]:  # Show first 10
            print(f"    '{s}'")
        if len(strings) > 10:
            print(f"    ... and {len(strings) - 10} more")
    
    # Check for null bytes
    null_count = content.count(b'\x00')
    print(f"  Null bytes: {null_count} ({null_count/len(content)*100:.1f}%)")
    
    # Check for common instruction patterns (LoongArch)
    la_patterns = [
        b'\x1c\x00',  # lu12iw
        b'\x03\x00',  # ori
        b'\x1d\x00',  # lu32id
        b'\x1e\x00',  # lu52id
    ]
    
    for pattern in la_patterns:
        count = content.count(pattern)
        if count > 0:
            print(f"  LoongArch instruction pattern {pattern.hex()}: {count} occurrences")
    
    print()

def analyze_vmlinux_efi(file_path: str):
    """Analyze vmlinux.efi file"""
    print(f"Analyzing: {file_path}")
    print("=" * 80)
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    print(f"File size: 0x{len(data):x} bytes ({len(data):,} bytes)")
    print()
    
    # Analyze PE32+ structure
    try:
        pe_analyzer = PEAnalyzer(data)
        pe_analyzer.print_info()
    except Exception as e:
        print(f"PE analysis failed: {e}")
        print()
    
    # Find ELF structures
    elf_positions = find_elf_structures(data)
    
    if elf_positions:
        print(f"Found {len(elf_positions)} ELF structure(s):")
        for i, (pos, elf_type) in enumerate(elf_positions):
            type_names = {1: 'ET_REL', 2: 'ET_EXEC', 3: 'ET_DYN', 4: 'ET_CORE'}
            print(f"  ELF #{i+1}: offset=0x{pos:x}, type={elf_type} ({type_names.get(elf_type, 'Unknown')})")
        print()
        
        # Analyze each ELF structure
        for i, (pos, elf_type) in enumerate(elf_positions):
            print(f"ELF Structure #{i+1} Analysis:")
            print("-" * 40)
            try:
                elf_analyzer = ELFAnalyzer(data, pos)
                elf_analyzer.print_info()
                
                # Analyze binary content around ELF
                elf_end = pos + 0x1000  # Assume ELF structure is within 4KB
                analyze_binary_content(data, pos, min(elf_end, len(data)), f"ELF Structure #{i+1}")
                
            except Exception as e:
                print(f"ELF analysis failed: {e}")
                print()
    else:
        print("No ELF structures found")
        print()
    
    # Analyze file structure
    print("File Structure Summary:")
    print("-" * 40)
    
    try:
        pe_start = 0
        pe_end = pe_analyzer.sections[-1]['raw_addr'] + pe_analyzer.sections[-1]['raw_size'] if pe_analyzer.sections else 0
        
        print(f"PE32+ Header: 0x{pe_start:x} - 0x{pe_end:x}")
        
        if elf_positions:
            elf_start = elf_positions[0][0]
            print(f"ELF Structure: 0x{elf_start:x} - 0x{len(data):x}")
            gap_size = elf_start - pe_end
            print(f"Gap: 0x{pe_end:x} - 0x{elf_start:x} ({gap_size} bytes)")
            
            if gap_size > 0:
                analyze_binary_content(data, pe_end, elf_start, "Gap between PE and ELF")
        else:
            print(f"Raw Data: 0x{pe_end:x} - 0x{len(data):x}")
    
    except Exception as e:
        print(f"Could not determine file structure: {e}")
    
    print()

def main():
    """Main function"""
    if len(sys.argv) != 2:
        print("Usage: python3 analyze_vmlinux_efi_detailed.py <vmlinux.efi_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found")
        sys.exit(1)
    
    try:
        analyze_vmlinux_efi(file_path)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
