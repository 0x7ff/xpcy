#include <fcntl.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define XPC_SYM_DICT(a) { a, "_xpc_dictionary_get_" a, 0 }
#define ELEM_CNT(a) (sizeof(a) / sizeof(*(a)))
#define STUB_INSN_CNT (3)
#define RD(a) extract32(a, 0, 5)
#define RM(a) extract32(a, 16, 5)
#define RN(a) extract32(a, 5, 5)
#define IS_LDR_X(a) (((a) & 0xff000000u) == 0x58000000u)
#define LDR_X_IMM(a) (sextract64(a, 5, 19) << 2u)
#define IS_NOP(a) ((a) == 0xd503201fu)
#define IS_BR(a) (((a) & 0xfffffc1fu) == 0xd61f0000u)
#define IS_BL(a) (((a) & 0xfc000000u) == 0x94000000u)
#define BL_IMM(a) (sextract64(a, 0, 26) << 2u)
#define IS_IN_RANGE(a, b, c) ((a) >= (b) && (a) <= (c))
#define IS_MOV_X(a) (((a) & 0xffe00000u) == 0xaa000000)
#define IS_ADR(a) (((a) & 0x1f000000u) == 0x10000000u)
#define ADR_IMM(a) ((sextract64(a, 5, 19) << 2u) | extract32(a, 29, 2))
#define IS_ADR_PAGE(a) extract32(a, 31, 1)
#define ADRP_ADDR(a) ((a) & ~0xfffull)
#define ADRP_IMM(a) (ADR_IMM(a) << 12u)
#define IS_LDR_X_UNSIGNED_IMM(a) (((a) & 0xffc00000u) == 0xf9400000u)
#define LDR_X_UNSIGNED_IMM(a) (extract32(a, 10, 12) << 3u)
#define IS_ADD_X(a) (((a) & 0xffc00000u) == 0x91000000u)
#define ADD_X_IMM(a) extract32(a, 10, 12)
#define IS_RET(a) ((a) == 0xd65f03c0u)

typedef struct {
	const char *type;
	const char *name;
	uint64_t addr;
} xpc_sym_t;

static inline uint32_t
extract32(uint32_t value, unsigned start, unsigned length) {
	return (value >> start) & (~0u >> (32u - length));
}

static inline uint64_t
sextract64(uint64_t value, unsigned start, unsigned length) {
	return (uint64_t)((int64_t)(value << (64u - length - start)) >> (64u - length));
}

static const struct segment_command_64 *
find_segment(const struct mach_header_64 *mhp, const char *seg_name) {
	const struct segment_command_64 *sgp = (const struct segment_command_64 *)((uintptr_t)mhp + sizeof(*mhp));
	uint32_t i;
	
	for(i = 0; i < mhp->ncmds; ++i) {
		if(sgp->cmd == LC_SEGMENT_64 && !strncmp(sgp->segname, seg_name, sizeof(sgp->segname))) {
			return sgp;
		}
		sgp = (const struct segment_command_64 *)((uintptr_t)sgp + sgp->cmdsize);
	}
	return NULL;
}

static const struct load_command *
find_load_command(const struct mach_header_64 *mhp, uint32_t cmd) {
	const struct load_command *lcp = (const struct load_command *)((uintptr_t)mhp + sizeof(*mhp));
	uint32_t i;
	
	for(i = 0; i < mhp->ncmds; ++i) {
		if(lcp->cmd == cmd) {
			return lcp;
		}
		lcp = (const struct load_command *)((uintptr_t)lcp + lcp->cmdsize);
	}
	return NULL;
}

static const struct section_64 *
find_section_type(const struct segment_command_64 *sgp, uint8_t type) {
	const struct section_64 *sp = (const struct section_64 *)((uintptr_t)sgp + sizeof(*sgp));
	uint32_t i;
	
	for(i = 0; i < sgp->nsects; ++i) {
		if((sp->flags & SECTION_TYPE) == type) {
			return sp;
		}
		++sp;
	}
	return NULL;
}

static const struct section_64 *
find_section_name(const struct segment_command_64 *sgp, const char *sect_name) {
	const struct section_64 *sp = (const struct section_64 *)((uintptr_t)sgp + sizeof(*sgp));
	uint32_t i;
	
	for(i = 0; i < sgp->nsects; ++i) {
		if(!strncmp(sp->segname, sgp->segname, sizeof(sp->segname)) && !strncmp(sp->sectname, sect_name, sizeof(sp->sectname))) {
			return sp;
		}
		++sp;
	}
	return NULL;
}

static size_t
find_symbols(const struct mach_header_64 *mhp, const struct segment_command_64 *seg_text, xpc_sym_t *syms, size_t sym_cnt) {
	const struct section_64 *sec_stubs, *sec_la_symbol_ptr;
	const uint32_t *indirect_symtab_idx_table, *insn;
	const struct dysymtab_command *sec_dysymtab;
	const struct segment_command_64 *seg_data;
	const struct symtab_command *sec_symtab;
	const struct nlist_64 *symtab;
	const char *strtab, *sym_name;
	uint64_t addr, ldr_addr, sym_addr;
	uint32_t i, k, symtab_idx;
	size_t j, found = 0;
	
	if((sec_stubs = find_section_type(seg_text, S_SYMBOL_STUBS)) &&
	   (seg_data = find_segment(mhp, SEG_DATA)) &&
	   (sec_la_symbol_ptr = find_section_type(seg_data, S_LAZY_SYMBOL_POINTERS)) &&
	   (sec_symtab = (const struct symtab_command *)find_load_command(mhp, LC_SYMTAB)) &&
	   (sec_dysymtab = (const struct dysymtab_command *)find_load_command(mhp, LC_DYSYMTAB)))
	{
		strtab = (const char *)((uintptr_t)mhp + sec_symtab->stroff);
		symtab = (const struct nlist_64 *)((uintptr_t)mhp + sec_symtab->symoff);
		indirect_symtab_idx_table = (const uint32_t *)((uintptr_t)mhp + sec_dysymtab->indirectsymoff) + sec_la_symbol_ptr->reserved1;
		insn = (const uint32_t *)((uintptr_t)mhp + sec_stubs->offset);
		for(i = 0; i < sec_la_symbol_ptr->size / sizeof(sym_addr); ++i) {
			symtab_idx = indirect_symtab_idx_table[i];
			if(!(symtab_idx & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS))) {
				sym_addr = sec_la_symbol_ptr->addr + (i * sizeof(sym_addr));
				sym_name = strtab + symtab[symtab_idx].n_un.n_strx;
				for(j = 0; j < sym_cnt; ++j) {
					if(syms[j].addr == 0 && !strcmp(sym_name, syms[j].name)) {
						for(k = 0; k < sec_stubs->size / sizeof(*insn); k += STUB_INSN_CNT) {
							if(IS_NOP(insn[k]) && IS_LDR_X(insn[k + 1]) && IS_BR(insn[k + 2])) {
								addr = sec_stubs->addr + (k * sizeof(*insn));
								ldr_addr = LDR_X_IMM(insn[k + 1]) + (addr + sizeof(*insn));
								if(ldr_addr == sym_addr) {
									syms[j].addr = addr;
									if(++found == sym_cnt) {
										return found;
									}
									break;
								}
							}
						}
					}
				}
			}
		}
	}
	return found;
}

static void
print_keys(const struct mach_header_64 *mhp, uint64_t len, const struct segment_command_64 *seg_text, const xpc_sym_t *syms, size_t sym_cnt) {
	const struct section_64 *sec_text, *sec_cstring;
	const uint32_t *insn;
	uint64_t off, addr, cstring_end, x[32] = { 0 };
	uint32_t i;
	size_t j;
	
	if((sec_text = find_section_name(seg_text, SECT_TEXT)) &&
	   (sec_cstring = find_section_name(seg_text, "__cstring"))) {
		cstring_end = sec_cstring->addr + sec_cstring->size;
		insn = (const uint32_t *)((uintptr_t)mhp + sec_text->offset);
		for(i = 0; i < sec_text->size / sizeof(*insn); ++i) {
			if(IS_LDR_X(insn[i])) {
				addr = sec_text->addr + (i * sizeof(*insn)) + LDR_X_IMM(insn[i]);
				off = addr - seg_text->vmaddr;
				if((off + sizeof(uint64_t)) <= len) {
					memcpy(&x[RD(insn[i])], (const void *)((uintptr_t)mhp + off), sizeof(uint64_t));
				}
			} else if(IS_ADR(insn[i])) {
				addr = sec_text->addr + (i * sizeof(*insn));
				if(IS_ADR_PAGE(insn[i])) {
					addr = ADRP_ADDR(addr) + ADRP_IMM(insn[i]);
				} else {
					addr += ADR_IMM(insn[i]);
				}
				x[RD(insn[i])] = addr;
			} else if(IS_ADD_X(insn[i])) {
				x[RD(insn[i])] = x[RN(insn[i])] + ADD_X_IMM(insn[i]);
			} else if(IS_LDR_X_UNSIGNED_IMM(insn[i])) {
				addr = x[RN(insn[i])] + LDR_X_UNSIGNED_IMM(insn[i]);
				off = addr - seg_text->vmaddr;
				if((off + sizeof(uint64_t)) <= len) {
					memcpy(&x[RD(insn[i])], (const void *)((uintptr_t)mhp + off), sizeof(uint64_t));
				} else {
					x[RD(insn[i])] = 0;
				}
			} else if(IS_MOV_X(insn[i])) {
				x[RD(insn[i])] = x[RM(insn[i])];
			} else if(IS_BL(insn[i])) {
				addr = sec_text->addr + (i * sizeof(*insn)) + BL_IMM(insn[i]);
				for(j = 0; j < sym_cnt; ++j) {
					if(addr == syms[j].addr && IS_IN_RANGE(x[1], sec_cstring->addr, cstring_end)) {
						printf("type: %s, name: %s\n", syms[j].type, (const char *)((uintptr_t)mhp + (x[1] - seg_text->vmaddr)));
						break;
					}
				}
			} else if(IS_RET(insn[i])) {
				memset(x, '\0', sizeof(x));
			}
		}
	}
}

static void
xpcy(const struct mach_header_64 *mhp, size_t len) {
	const struct segment_command_64 *seg_text;
	xpc_sym_t syms[] = {
		XPC_SYM_DICT("array"),
		XPC_SYM_DICT("bool"),
		XPC_SYM_DICT("data"),
		XPC_SYM_DICT("date"),
		XPC_SYM_DICT("date"),
		XPC_SYM_DICT("dictionary"),
		XPC_SYM_DICT("double"),
		XPC_SYM_DICT("int64"),
		XPC_SYM_DICT("string"),
		XPC_SYM_DICT("uint64"),
		XPC_SYM_DICT("uuid"),
		XPC_SYM_DICT("value")
	};
	
	if((seg_text = find_segment(mhp, SEG_TEXT)) &&
	   find_symbols(mhp, seg_text, syms, ELEM_CNT(syms)))
	{
		print_keys(mhp, len, seg_text, syms, ELEM_CNT(syms));
	}
}

int
main(int argc, char **argv) {
	if(argc != 2) {
		printf("Usage: %s Mach-O\n", argv[0]);
	} else {
		int fd = open(argv[1], O_RDONLY);
		size_t len = (size_t)lseek(fd, 0, SEEK_END);
		struct mach_header_64 *mhp = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
		close(fd);
		if(mhp != MAP_FAILED) {
			if(mhp->magic == MH_MAGIC_64 && mhp->cputype == CPU_TYPE_ARM64) {
				xpcy(mhp, len);
			}
			munmap(mhp, len);
		}
	}
}
