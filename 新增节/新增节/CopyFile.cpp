#include <iostream>
#include <cstring>
#include "GetPEInfo.h"
#define MessageAddress 0x767F13D0
int main() {
	char name[] = "TestDLL.dll";
	char* Pname = name;
	char To_name[] = "file.exe";
	char* to_file = To_name;
	int expand = 0x1000;
	PEInfo* Ppefile;
	PEInfo pefile(Pname);
	Ppefile = &pefile;
	char funcName[] = "b";
	char* pFuncName = funcName;
	//pefile.GetExport(pFuncName);
	//pefile.fileToImage();
	//pefile.changeFile();
	//pefile.expandSection(expand );
	//第二个参数为文件需要扩大多少
	//pefile.ImageToFile(to_file,expand);
	return 1;
}