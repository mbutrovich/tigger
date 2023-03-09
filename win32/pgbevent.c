/*-------------------------------------------------------------------------
 * pgbevent.c
 *		Defines the entry point for pgbevent dll.
 *		The DLL defines event source for pgbouncer tools
 *-------------------------------------------------------------------------
 */

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <olectl.h>
#include <string.h>

#define APP_KEY "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\pgbouncer"

/* Global variables */
static HANDLE g_module = NULL;	/* hModule of DLL */

/* Prototypes */
STDAPI DllRegisterServer(void);
STDAPI DllUnregisterServer(void);
BOOL WINAPI DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

/*
 * DllRegisterServer --- Instructs DLL to create its registry entries
 */
STDAPI DllRegisterServer(void)
{
	HKEY key;
	DWORD data;
	char buffer[_MAX_PATH];

	/* Set the name of DLL full path name. */
	if (!GetModuleFileName((HMODULE)g_module, buffer, sizeof(buffer))) {
		MessageBox(NULL, "Could not retrieve DLL filename", "pgbouncer error", MB_OK | MB_ICONSTOP);
		return SELFREG_E_TYPELIB;
	}

	/*
	 * Add our source name as a subkey under the Application key in
	 * the EventLog registry key.
	 */
	if (RegCreateKey(HKEY_LOCAL_MACHINE, APP_KEY, &key)) {
		MessageBox(NULL, "Could not create the registry key.", "pgbouncer error", MB_OK | MB_ICONSTOP);
		return SELFREG_E_TYPELIB;
	}

	/* Add the name to the EventMessageFile subkey. */
	if (RegSetValueEx(key, "EventMessageFile", 0, REG_EXPAND_SZ, (LPBYTE)buffer, strlen(buffer) + 1)) {
		MessageBox(NULL, "Could not set the event message file.", "pgbouncer error", MB_OK | MB_ICONSTOP);
		return SELFREG_E_TYPELIB;
	}

	/* Set the supported event types in the TypesSupported subkey. */
	data = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;

	if (RegSetValueEx(key, "TypesSupported", 0, REG_DWORD, (LPBYTE)&data, sizeof(DWORD))) {
		MessageBox(NULL, "Could not set the supported types.", "pgbouncer error", MB_OK | MB_ICONSTOP);
		return SELFREG_E_TYPELIB;
	}

	RegCloseKey(key);
	return S_OK;
}

/*
 * DllUnregisterServer --- Instructs DLL to remove only those entries created through DllRegisterServer
 */
STDAPI DllUnregisterServer(void)
{
	if (RegDeleteKey(HKEY_LOCAL_MACHINE, APP_KEY)) {
		MessageBox(NULL, "Could not delete the registry key.", "pgbouncer error", MB_OK | MB_ICONSTOP);
		return SELFREG_E_TYPELIB;
	}
	return S_OK;
}

/*
 * DllMain --- is an optional entry point into a DLL.
 */
BOOL WINAPI DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
		g_module = hModule;
	return TRUE;
}
