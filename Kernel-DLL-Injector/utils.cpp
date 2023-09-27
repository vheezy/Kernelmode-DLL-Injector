#include "utils.hpp"

// Function to read a file into memory and store its content in a vector of uint8_t.
bool utils::ReadFileToMemory(const std::string& file_path, std::vector<uint8_t>* out_buffer)
{
    // Open the file for binary reading.
    std::ifstream file_ifstream(file_path, std::ios::binary);

    // Check if the file opened successfully.
    if (!file_ifstream)
        return false;

    // Read the entire file into the out_buffer vector.
    out_buffer->assign((std::istreambuf_iterator<char>(file_ifstream)), std::istreambuf_iterator<char>());
    
    // Close the file stream.
    file_ifstream.close();

    return true;
}

// Function to create a file from memory.
bool utils::CreateFileFromMemory(const std::string& desired_file_path, const char* address, size_t size)
{
    // Open the file for binary writing.
    std::ofstream file_ofstream(desired_file_path.c_str(), std::ios_base::out | std::ios_base::binary);

    // Check if the file opened successfully.
    if (!file_ofstream.write(address, size))
    {
        // Close the file stream and return false if writing failed.
        file_ofstream.close();
        return false;
    }

    // Close the file stream after successful writing.
    file_ofstream.close();
    
    return true;
}

// Function to get the base address of a kernel-mode module by its name.
uint64_t utils::GetKernelModuleAddress(const std::string& module_name)
{
    void* buffer = nullptr;
    DWORD buffer_size = 0;

    // Query system information to get a list of loaded modules.
    NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);

    // Handle buffer size mismatch by reallocating and querying again.
    while (status == nt::STATUS_INFO_LENGTH_MISMATCH)
    {
        VirtualFree(buffer, 0, MEM_RELEASE);

        buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);
    }

    // Check if the query was successful.
    if (!NT_SUCCESS(status))
    {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return 0;
    }

    const auto modules = static_cast<nt::PRTL_PROCESS_MODULES>(buffer);

    for (auto i = 0u; i < modules->NumberOfModules; ++i)
    {
        // Get the name of the current module.
        const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[i].FullPathName) + modules->Modules[i].OffsetToFileName);

        // Compare the module names to find the desired one.
        if (!_stricmp(current_module_name.c_str(), module_name.c_str()))
        {
            // Return the base address of the found module.
            const uint64_t result = reinterpret_cast<uint64_t>(modules->Modules[i].ImageBase);

            VirtualFree(buffer, 0, MEM_RELEASE);
            return result;
        }
    }

    // Free allocated memory and return 0 if the module is not found.
    VirtualFree(buffer, 0, MEM_RELEASE);
    return 0;
}

// Function to compare two blocks of data based on a mask.
BOOLEAN utils::bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return 0;
    return (*szMask) == 0;
}

// Function to find a pattern within a given memory region.
uintptr_t utils::FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, char* szMask)
{
    // Calculate the maximum length for searching patterns.
    size_t max_len = dwLen - strlen(szMask);

    // Loop through the memory region to find the pattern.
    for (uintptr_t i = 0; i < max_len; i++)
        if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
            return (uintptr_t)(dwAddress + i);

    return 0;
}

// Function to find a section within a module by name.
PVOID utils::FindSection(char* sectionName, uintptr_t modulePtr, PULONG size)
{
    size_t namelength = strlen(sectionName);
    PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(modulePtr + ((PIMAGE_DOS_HEADER)modulePtr)->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);

    // Loop through the module's sections to find the desired section.
    for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i)
    {
        PIMAGE_SECTION_HEADER section = &sections[i];

        // Compare section names to find a match.
        if (memcmp(section->Name, sectionName, namelength) == 0 &&
            namelength == strlen((char*)section->Name))
        {
            // If a match is found, return the section's virtual address.
            if (size)
            {
                *size = section->Misc.VirtualSize;
            }
            return (PVOID)(modulePtr + section->VirtualAddress);
        }
    }

    // Return 0 if the section is not found.
    return 0;
}
