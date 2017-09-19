#include "sections.h"
#include "log.h"
#include <elf.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>


#if defined(__i386__)
#   define Elf_Ehdr Elf32_Ehdr
#   define Elf_Shdr Elf32_Shdr
#elif defined(__x86_64)
#   define Elf_Ehdr Elf64_Ehdr
#   define Elf_Shdr Elf64_Shdr
#endif


void read_elf_header(int32_t fd, Elf_Ehdr *elf_header)
{
	assert(elf_header != NULL);
	assert(lseek(fd, 0, SEEK_SET) == 0);
	assert(read(fd, (void *) elf_header, sizeof(Elf_Ehdr)) == sizeof(Elf_Ehdr));
}


bool is_ELF(Elf_Ehdr *eh)
{
	/* ELF magic bytes are 0x7f,'E','L','F'
	 * Using  octal escape sequence to represent 0x7f */
	return strncmp((char *) eh->e_ident, "\177ELF", 4) == 0;
}


void read_section_header_table(int32_t fd, Elf_Ehdr *eh, Elf_Shdr sh_table[])
{
	assert(lseek(fd, eh->e_shoff, SEEK_SET) == eh->e_shoff);
	for(uint32_t i = 0; i < eh->e_shnum; i++) {
		assert(read(fd, (void *) &sh_table[i], eh->e_shentsize) == eh->e_shentsize);
	}
}


char *read_section(int32_t fd, Elf_Shdr sh)
{
	char *buff = malloc(sh.sh_size);
	if(!buff) {
		LOG_F("failed to allocate %dbytes", sh.sh_size);
        return NULL;
	}

	assert(lseek(fd, sh.sh_offset, SEEK_SET) == sh.sh_offset);
	assert(read(fd, (void *) buff, sh.sh_size) == sh.sh_size);

	return buff;
}


int64_t section_find(const char *filename, const char *sec_name, section_bounds_t *bounds)
{
    int fd = open(filename, O_RDONLY | O_SYNC);
    if (fd == -1) {
        PLOG_F("failed to open %s", filename);
        return -1;
    }

    Elf_Ehdr eh;		/* elf-header is fixed size */
	Elf_Shdr* sh_tbl;	/* section-header table is variable size */
    read_elf_header(fd, &eh);
    if (!is_ELF(&eh)) {
        LOG_E("%s is not ELF", filename);
        close(fd);
        return -1;
    }

    /* Section header table :  */
	sh_tbl = malloc(eh.e_shentsize * eh.e_shnum);
	if(!sh_tbl) {
		LOG_F("failed to allocate %d bytes", (eh.e_shentsize * eh.e_shnum));
        close(fd);
		free(sh_tbl);
        return -1;
	}
	read_section_header_table(fd, &eh, sh_tbl);
    LOG_D("found %d sections", eh.e_shnum);

    /* Read section-header string-table */
    char *sh_str = read_section(fd, sh_tbl[eh.e_shstrndx]);
    close(fd);
    if (sh_str == NULL) {
		free(sh_tbl);
        return -1;
    }

    for(int64_t i = 0; i < eh.e_shnum; i++) {
        char *sh_name = sh_str + sh_tbl[i].sh_name;
        if (strstr(sh_name, sec_name) == NULL) {
            continue;
        }
        bounds->sec_start = sh_tbl[i].sh_addr;
        bounds->sec_end = sh_tbl[i].sh_addr + sh_tbl[i].sh_size;
		free(sh_str);
		free(sh_tbl);
        return bounds->sec_end - bounds->sec_start;
    }

	free(sh_str);
	free(sh_tbl);
    return 0;
}
