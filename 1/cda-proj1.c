/*********************************
 * Project for Binary Code Analysis (IAN)
 * Elf symbol table parser.
 * Author: Tomáš Sasák
 * Year: 2020
 *********************************/

#include <stdio.h>
#include <gelf.h>
#include <libelf.h>
#include <elf.h>
#include <stdbool.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/**
 * Functions prints error message on stderr.
 */
void print_err(char *msg)
{
    printf(msg, stderr);
}

/**
 * Method checks arguments and returns bool if its all good.
 */
bool check_args(int argc, char **argv)
{
    if(argc < 2)
    {
        print_err("Parameter must be elf file!\n");
        return false;
    }

    return true;
}

/**
 * Function opens file and returns file dscriptior.
 */
int open_file(char *name)
{
    int inputfd = open(name, O_RDONLY, 0);

    if(inputfd == -1)
    {
        print_err("Cannot open given elf file!\n");
    }

    return inputfd;
}

/**
 * Function fetches section offset by given name
 * in argument wantedSection. Returns offset to the section or -1 if not found
 * or wrong argument.
 */
Elf64_Off fetch_section(Elf *input, char *wantedSection)
{
    if(wantedSection == NULL)
        return -1;

    Elf *iter = input;
    bool found = false;

    // Get shstrtab to fetch names of sections
    size_t stringIndex;
    elf_getshdrstrndx(iter, &stringIndex);

    // Go through every section
    Elf_Scn *section = elf_nextscn(iter, NULL);
    GElf_Shdr *shdr = (GElf_Shdr *)malloc(sizeof(GElf_Shdr));

    int index = 1;

    while(section != NULL)
    {
        gelf_getshdr(section, shdr);

        char *sectionName = elf_strptr(iter, stringIndex, shdr->sh_name);
        if(strcmp(sectionName, wantedSection) == 0)
        {
            found = true;
            break;
        }

        index += 1;
        section = elf_nextscn(iter, section);
    }

    if(found)
    {
        return shdr->sh_offset;
    }

    return -1;
}

/**
 * Function prints out symbol table based on given offset to the symtab section
 * and strtab section in parameters.
 */
void print_symtab(Elf *input, Elf64_Off symtabOffset, Elf64_Off stringtabIndex)
{
    // Fetch section to get the section header to get size of the symtable section.
    // So there is known how many symbols are in table
    Elf_Scn *symtab = gelf_offscn(input, symtabOffset);
    GElf_Shdr symtabHeader;
    gelf_getshdr(symtab, &symtabHeader);

    // Get string table section to get the raw pointer to the 
    // strings.
    Elf_Scn *strtab = gelf_offscn(input, stringtabIndex);

    // Get elf header to get which x-bit architecture is used.
    GElf_Ehdr header;
    gelf_getehdr(input, &header);

    // Get the data structure to get raw pointer to the section.
    Elf_Data *symtabData = elf_getdata(symtab, NULL);
    Elf_Data *stringtabData = elf_getdata(strtab, NULL);

    // 64 bit elf
    if(header.e_ident[EI_CLASS] == ELFCLASS64)
    {
        int slided = 0;
        int index = 0;

        printf("      Value       Bind Type Size           Name\n");

        while(slided < symtabHeader.sh_size)
        {
            // Retype the pointer to the raw symbol table section to the
            // single symbol, cuz symbol table is array of symbols.
            // And index it.
            Elf64_Sym *sym = &(((Elf64_Sym *)symtabData->d_buf)[index]);

            // Retype the pointer to the raw string table section to the
            // corresponding string name of the symbol.
            char *name = ((char *)stringtabData->d_buf) + sym->st_name;
            // Skip empty names
            if(*name != '\0')
                printf("%016x    %u    %u    %u    %s   \n", sym->st_value, ELF64_ST_BIND(sym->st_info), ELF64_ST_TYPE(sym->st_info), sym->st_size, name);

            // Set index to next symbol
            index++;
            // Slide to the next size of the structure, to see 
            // how far program is in the table.
            slided += sizeof(Elf64_Sym);
        }
    }
    // 32 bit elf
    else if(header.e_ident[EI_CLASS] == ELFCLASS32)
    {
        int slided = 0;
        int index = 0;

        printf("      Value       Bind Type Size           Name\n");

        while(slided < symtabHeader.sh_size)
        {
            Elf32_Sym *sym = &(((Elf32_Sym *)symtabData->d_buf)[index]);

            char *name = ((char *)stringtabData->d_buf) + sym->st_name;
            if(*name != '\0')
                printf("%08x    %u    %u    %u    %s   \n", sym->st_value, ELF32_ST_BIND(sym->st_info), ELF32_ST_TYPE(sym->st_info), sym->st_size, name);

            index++;
            slided += sizeof(Elf32_Sym);
        }
    }
}

int main(int argc, char **argv)
{
    // Check arguments
    bool isOk = check_args(argc, argv);
    if(!isOk)
        return -1;

    // Open the given file
    int inputfd = open_file(argv[1]);
    if(inputfd == -1)
        return -1;

    // Set elf version
    elf_version(EV_CURRENT);

    // Get initial elf file descriptor.
    Elf *elfInput = elf_begin(inputfd, ELF_C_READ, NULL);
    if(elfInput == NULL)
    {
        printf("%s\n", elf_errmsg(-1));
        print_err("Cannot open elf file through libelf!\n");
        return -1;
    }

    // Fetch strings table.
    Elf64_Off strtabIndex = fetch_section(elfInput, ".strtab");
    if(strtabIndex == -1)
    {
        print_err("Strtab section has 0 records.");
        return -1;
    }

    // Fetch symtable section.
    Elf64_Off symtabOffset = fetch_section(elfInput, ".symtab");
    if (symtabOffset == -1)
    {
        print_err("Symtab section has 0 records.\n");
        return 0;
    }

    // Print the table
    print_symtab(elfInput, symtabOffset, strtabIndex);

    // Release resources
    elf_end(elfInput);
    close(inputfd);
    return 0;
}