#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <NTSecAPI.h>
#include <tchar.h>

#pragma comment(lib,"Secur32.lib")

int main(int argc, char* argv[]) {
	ULONG LogonSessionCount;
	PLUID LogonSessionList;
	PSECURITY_LOGON_SESSION_DATA pLogonSessionData;
	NTSTATUS status;

	pLogonSessionData = (PSECURITY_LOGON_SESSION_DATA)malloc(sizeof(SECURITY_LOGON_SESSION_DATA));
	status = LsaEnumerateLogonSessions(&LogonSessionCount, &LogonSessionList);
	if (status != ERROR_SUCCESS)
	{
		printf("LsaEnumerateLogonSessions failed with status %u\r\n ",GetLastError());
	}
	printf("SessionCount %d\r\n", LogonSessionCount);
	for (int i = 0; i < LogonSessionCount; i++) {
		LsaGetLogonSessionData(LogonSessionList + i, &pLogonSessionData);
		_tprintf("%ws\\%ws\r\n",pLogonSessionData->LogonDomain,pLogonSessionData->UserName.Buffer);
	}
	LsaFreeReturnBuffer(pLogonSessionData);
 }
