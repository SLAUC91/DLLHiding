#include "Process.h"
#include <iostream>

inline const char * const BoolToString(const bool b)
{
	return b ? "TRUE" : "FALSE";
}

//convert string to wstring
std::wstring s2ws(const std::string & s)
{
	int len;
	int slength = (int)s.length() + 1;
	len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
	std::wstring r(len, L'\0');
	MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, &r[0], len);
	return r;
}

int main(int argc, char* argv[]) {
	std::cout << "-----DLL Hider v1.0-----\n" << std::endl;
	if (argc > 3 || argc <= 2){
		std::cout << "Invalid arguments!" << std::endl;
		std::cout << "DllHiding.exe <Process Name> <DLL Name>" << std::endl;
		std::cout << "example: " << "DllHiding.exe firefox.exe d3d9.dll" << std::endl;
		return 0;
	}
	
	std::string strNameProcess = argv[1];
	std::string strDLLName = argv[2];
	std::wstring wstrDLLName = s2ws(strDLLName);

	Process * A = new Process(strNameProcess, wstrDLLName);

	std::cout << "Process Name: " << strNameProcess << " " << "DLL Name: " << strDLLName << std::endl;
	std::cout << "\n" << "Status:" << std::endl;
	std::cout << "\t" << "InLoadOrderModuleList: " << BoolToString(A->DLLInLoadStatus) << std::endl;
	std::cout << "\t" << "InMemoryOrderModuleList: " << BoolToString(A->DLLInMemStatus) << std::endl;
	std::cout << "\t" << "InInitializationOrderModuleList: " << BoolToString(A->DLLInInInitializationStatus) << std::endl;

	//Print InLoadOrderModuleList in forward order
	//A->ListModules(A->Pinfo.Process_ID, 0, 0);

	delete A;

	return 0;
}