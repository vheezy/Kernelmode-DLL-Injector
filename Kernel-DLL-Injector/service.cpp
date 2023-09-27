#include "service.hpp"
#include "xorstr.hpp"

// Function to register and start a Windows-service using a kernel mode driver
bool service::RegisterAndStart(const std::string& driver_path)
{
	// Define constants and variables needed for the service registration
	const static DWORD ServiceTypeKernel = 1;
	const std::string driver_name = std::filesystem::path(driver_path).filename().string();
	const std::string servicesPath = "SYSTEM\\CurrentControlSet\\Services\\" + driver_name;
	const std::string nPath = "\\??\\" + driver_path;

	HKEY dservice;

	// Create Registry Key
	LSTATUS status = RegCreateKey(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice);

	// Check if registry key creation was successful
	if (status != ERROR_SUCCESS)
	{
		printf(xor ("[-] Can't create service key\n"));
		return false;
	}

	// Set the ImagePath registry value for the service
	// Then check if the Value was successfully set
	status = RegSetKeyValue(dservice, NULL, "ImagePath", REG_EXPAND_SZ, nPath.c_str(), (DWORD)nPath.size());
	if (status != ERROR_SUCCESS)
	{
		RegCloseKey(dservice);
		printf(xor ("[-] Can't create 'ImagePath' registry value\n"));
		return false;
	}

	// Set the Type value for the service
	// Then check if it was successfully set
	status = RegSetKeyValue(dservice, NULL, "Type", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	if (status != ERROR_SUCCESS)
	{
		RegCloseKey(dservice);
		printf(xor ("[-] Can't create 'Type' registry value\n"));
		return false;
	}

	// Close the reg key
	RegCloseKey(dservice);

	// Load the fuinctions from ntdll.dll for driver loading privs
	HMODULE ntdll = GetModuleHandle("ntdll.dll");
	if (ntdll == NULL) {
		return false;
	}

	// ***
	auto RtlAdjustPrivilege = (nt::RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
	auto NtLoadDriver = (nt::NtLoadDriver)GetProcAddress(ntdll, "NtLoadDriver");

	// Enable SE_LOAD_DRIVE_PRIVILEGE to load the driver
	ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	NTSTATUS Status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);

	// Check if we enabled succesfully
	if (!NT_SUCCESS(Status))
	{
		printf(xor ("Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator.\n"));
		return false;
	}

	// Prepare the service path and NtLoadDrive to load the driver
	std::wstring wdriver_name(driver_name.begin(), driver_name.end());
	wdriver_name = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + wdriver_name;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_name.c_str());
	
	Status = NtLoadDriver(&serviceStr);
	printf(xor ("[+] NtLoadDriver Status 0x%lx\n"), Status);
	return NT_SUCCESS(Status);
}

bool service::StopAndRemove(const std::string& driver_name)
{
	// Load the necessary functions from ntdll.dll
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
		return false;

	// Prepare the service path for the driver
	std::wstring wdriver_name(driver_name.begin(), driver_name.end());
	wdriver_name = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + wdriver_name;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_name.c_str());

	HKEY driver_service;
	std::string servicesPath = "SYSTEM\\CurrentControlSet\\Services\\" + driver_name;
	LSTATUS status = RegOpenKey(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &driver_service);

	// Check if the registry key exists
	if (status != ERROR_SUCCESS)
	{
		if (status == ERROR_FILE_NOT_FOUND) {
			return true; // The service does not exist so consider it removed
		}
		return false;
	}

	// Close the reg key
	RegCloseKey(driver_service);

	// Load the NtUnloadDrive function to unload the driver
	auto NtUnloadDriver = (nt::NtUnloadDriver)GetProcAddress(ntdll, "NtUnloadDriver");
	NTSTATUS st = NtUnloadDriver(&serviceStr);
	printf(xor ("[+] NtUnloadDriver Status 0x%lx\n"), st);
	if (st != 0x0) {
		printf(xor ("[-] Driver Unload Failed!!\n"));
	}
	
	// Delete the reg key and remove the service
	status = RegDeleteKey(HKEY_LOCAL_MACHINE, servicesPath.c_str());
	if (status != ERROR_SUCCESS)
	{
		return false;
	}
	return true;
}
