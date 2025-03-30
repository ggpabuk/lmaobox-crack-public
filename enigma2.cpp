/*
this file decrypts main cheat module
it was written when cheat was on x86 and fixed to decrypt x64 builds later
many code how you see was took from hexrays decompiller
*/

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <cstdint>

#define SLOBYTE(x)   (*((int8_t*)&(x)))

PIMAGE_SECTION_HEADER __cdecl getImportAddressSection(char *ImportAddress, IMAGE_NT_HEADERS64 *peHeader)
{
    unsigned int sectionNumber; // edx
    PIMAGE_SECTION_HEADER result; // eax
    char *VirtualAddress; // ecx

    sectionNumber = 0;
    result = (PIMAGE_SECTION_HEADER)(((char *)&peHeader->OptionalHeader) + peHeader->FileHeader.SizeOfOptionalHeader);
    if (!peHeader->FileHeader.NumberOfSections)
        return 0;
    while (1)
    {
        VirtualAddress = (char *)result->VirtualAddress;
        if (ImportAddress >= VirtualAddress && ImportAddress < VirtualAddress + result->Misc.PhysicalAddress)
            break;
        ++sectionNumber;
        ++result;
        if (sectionNumber >= peHeader->FileHeader.NumberOfSections)
            return 0;
    }
    return result;
}

DWORD __cdecl GetImportDescriptor(int ImportAddress, IMAGE_NT_HEADERS64 *peHeader, int dllData)
{
    PIMAGE_SECTION_HEADER result; // eax

    result = getImportAddressSection((char*)ImportAddress, peHeader);
    if (result)
        return (DWORD)(dllData + ImportAddress + result->PointerToRawData - result->VirtualAddress);
    return (DWORD)result;
}



DWORD getVolumeSerialNumber()
{
    //DWORD VolumeSerialNumber;
    //GetVolumeInformationA("C:\\", 0, 0, &VolumeSerialNumber, 0, 0, 0, 0);// C:
    //return VolumeSerialNumber;
    return 0x123123; // hard coded number that can get using code above
}

char __cdecl idiotxor(char *data, unsigned int dllSize, const char *email)
{
    char result; // al
    unsigned int dataIter; // ebx
    char v5; // cl
    char v6; // [esp+8h] [ebp-8h]
    char i; // [esp+Ch] [ebp-4h]

    v6 = -1;
    result = getVolumeSerialNumber();
    dataIter = 0;
    for (i = result; dataIter < dllSize; data[dataIter - 1] ^= i ^ v6 ^ result ^ v5)
    {
        v5 = tolower(email[dataIter % strlen(email)]); // unxorring depend on email :)
        result = dataIter % 0xFA;
        ++dataIter;
    }
    return result;
};

IMAGE_NT_HEADERS64 *getPe(DWORD a)
{
    auto pe = (IMAGE_NT_HEADERS64 *)(a + ((IMAGE_DOS_HEADER *)a)->e_lfanew);
    return pe;
}

char *__cdecl xor2(char *a1, char a2 = -65)
{
    char *result; // eax

    for (result = a1; *result; ++result)
        *result ^= a2;
    return result;
}

int __stdcall sub_10002A7B(int dllData, PIMAGE_IMPORT_DESCRIPTOR descriptor, DWORD th32ProcessID, char a4, char a5)
{
    auto pe = getPe(dllData);
    auto ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)GetImportDescriptor(descriptor->Name, pe, dllData);

    auto p_Name = (IMAGE_IMPORT_DESCRIPTOR *)&descriptor->Name;
    while (ImportDescriptor)
    {
        auto v8 = (PIMAGE_IMPORT_DESCRIPTOR)GetImportDescriptor(((int *)p_Name)[1], pe, dllData);

        if (SLOBYTE(ImportDescriptor->Characteristics) < 0)
        {
            xor2((char *)ImportDescriptor);

            printf("%s\n", (char *)ImportDescriptor);
        }

        if (*((int *)v8))
        {
            while (1)
            {
                auto v15 = (PIMAGE_IMPORT_DESCRIPTOR)GetImportDescriptor(*((int *)v8), pe, dllData);
                if (v15)
                {
                    if (*((int *)v8) >= 0)
                    {
                        auto v14 = (char *)&v15->OriginalFirstThunk + 2;
                        if ((v15->OriginalFirstThunk & 0x800000) != 0)
                            xor2((char *)&v15->OriginalFirstThunk + 2, -36);

                        printf("%s\n", v14);
                    }
                    else
                    {
                        printf("1488!!!!\n");
                    }
                }

                //++v8;
                *(int *)(&v8) += 8; // this appeared because cheat x86->x64

                if (!*((int *)v8)) break;
            }
        }

        ++p_Name;
        ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)GetImportDescriptor(*((int *)p_Name), pe, dllData);
    }

    return 666;
}

int main()
{
    std::ifstream ifs(L"C:\\Users\\pivnoye-puzo\\Desktop\\response_content.bin", std::ios::binary | std::ios::ate); // dumped loader's http response
    auto size = (uint64_t)ifs.tellg();
    ifs.seekg(20480, std::ios::beg); // second payload offset; was sent in http headers
    auto image = (char *)malloc(size);
    ifs.read(image, size);
    idiotxor(image, size, "dsadsasadadsa@gmail.com"); // ur email here

    image[0] = 'M'; // fix pe magic
    image[1] = 'Z';

    auto pe = (IMAGE_NT_HEADERS64 *)(image + ((IMAGE_DOS_HEADER *)image)->e_lfanew);
    auto ImportDescriptor = GetImportDescriptor(pe->OptionalHeader.DataDirectory[1].VirtualAddress, pe, (int)image);
    sub_10002A7B((int)image, (PIMAGE_IMPORT_DESCRIPTOR)ImportDescriptor, 0, 0, 0);

    std::ofstream f(L"C:\\Users\\pivnoye-puzo\\Desktop\\gei.dll", std::ios::binary); // save injectable dll
    f.write(image, size);
    f.close();

    free(image);
    return 0;
}
