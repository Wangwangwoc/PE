#include <Windows.h>
#define MessageAddress 0x767F13D0
BYTE shellcode[] = { 0x6A,00,0x6A,00,0x6A,00,0x6A,00,0xE8,00,00,00,00,0xE9,00,00,00,00 };
class PEInfo {
public:
	PEInfo(char *file_name) {
		fileBuf = readFile(file_name);
		getPEinfo();
	}
	virtual  ~PEInfo() {
		if(fileBuf!=NULL){ 
			delete fileBuf; 
		}
		if (imageBuf != NULL) {
			delete imageBuf;
		}
	}
public:
	void* fileBuf;
	void* imageBuf;
	struct SECTION_HEADER {
		DWORD	Misc;                            // +0008h   -   节区的尺寸
		DWORD   VirtualAddress;                  // +000ch   -   节区的RVA地址
		DWORD   SizeOfRawData;                   // +0010h   -   在文件中对齐后的尺寸
		DWORD   PointerToRawData;                // +0014h   -   在文件中的偏移
	}head[10];
	struct {
	DWORD   VirtualAddress;                 // +0000h   -   数据的起始RVA
	DWORD   Size;                           // +0004h   -   数据块的长度
	}DATA_DIRECTORY[16];
	//PE偏移
	long e_lfanew;
	//标准头
	WORD    NumberOfSections;                    // +0006h   -   PE中节的数量
	WORD    SizeOfOptionalHeader;                // +0014h   -   扩展头结构的长度
	//扩展头
	DWORD   AddressOfEntryPoint;                   // +0028h   -   程序执行入口RVA
	DWORD   ImageBase;                             // +0034h   -   程序的建议装载地址
	DWORD   FileAlignment;                         // +003ch   -   文件中的节的对齐粒度
	DWORD   SizeOfImage;                           // +0050h   -   内存中的整个PE映象尺寸
	DWORD   SizeOfHeaders;                        // +0054h   -   所有头+节表的大小

	//读取文件到内存
	void* readFile(char* file_name);
	//获取 PE信息
	void getPEinfo();
	//文件内存拉伸为内存中的结构
	void* fileToImage();
	//从内存中的结构转换到文件结构
	void ImageToFile(char* file_name, int expand);
	//在文件中插入shellcode
	void* changeFile();
	//扩大文件最后一个节并插入shellcode
	void expandSection(int expand);
	//虚拟地址转文件地址
	int RVAToFOA(DWORD RVA);
	//获取导出表里的函数地址
	void GetExport(char* func_name);
	//获取重定位表数据
	void GetRelocs();
};
void PEInfo::GetExport(char* func_name) {
	DWORD FOA = 0;
	FOA = RVAToFOA(DATA_DIRECTORY[0].VirtualAddress);
	DWORD NumberOfName = *PDWORD((unsigned int)fileBuf + FOA + 0x18);
	printf("NumberOfName:%d\n", NumberOfName);
	DWORD AddressOfFunction = RVAToFOA(*PDWORD((unsigned int)fileBuf + FOA + 0x1c));
	printf("AddressOfFunction:0x%x\n", AddressOfFunction);
	DWORD AddressOfName = RVAToFOA(*PDWORD((unsigned int)fileBuf + FOA + 0x20));
	printf("AddressOfName:0x%x\n", AddressOfName);
	DWORD AddressOfNameOrd = RVAToFOA(*PDWORD((unsigned int)fileBuf + FOA + 0x24));
	printf("AddressOfNameOrd:0x%x\n", AddressOfNameOrd);
	char* funcName;
	unsigned int index=0;
	DWORD funcAddress = 0;
	for (int i = 0; i < NumberOfName; i++) {
		//这里学习到从具体地址取数据要规定数据类型
		FOA = RVAToFOA(*PDWORD((unsigned int)fileBuf + AddressOfName + i * 4));
		funcName = (char*)((unsigned int)fileBuf + FOA);
		if (*func_name == *funcName) {
			printf("函数名为%s\n", funcName);
			index = i;
			break;
		}
	} 
	unsigned int FuncIndex = 0;
	FuncIndex = *PWORD((unsigned int)fileBuf + AddressOfNameOrd + index * 2);
	printf("函数地址序号为0x%d\n", FuncIndex);
	funcAddress = *PDWORD((unsigned int)fileBuf + AddressOfFunction + FuncIndex * 4);
	printf("函数地址为0x%x\n", funcAddress);
}
void PEInfo::GetRelocs() {
	DWORD FOA = 0;
	FOA=RVAToFOA(DATA_DIRECTORY[5].VirtualAddress);
	printf("重定位表地址: 0x%x\n", FOA);
	DWORD sizeOfBlock = 0;
	unsigned int number = 0;
	WORD flag = 0;
	for (int i = 0; 1; i++) {
		DWORD relocsVirtualAddress=*PDWORD((unsigned int)fileBuf + FOA);
		sizeOfBlock = *PDWORD((unsigned int)fileBuf + FOA+4);
		FOA += sizeOfBlock;		//每次迁移当前地址到下一个重定位表头
		number = (sizeOfBlock - 8) / 2;		//求得重定位表内个数
		printf("需要修改的地址: 0x%x\n", relocsVirtualAddress);
		printf("sizeOfBlock: 0x%x\n", sizeOfBlock);
		if (relocsVirtualAddress == 0) {
			break;
		}
		for (int j = 0; j < number; j++) {
			flag = *PWORD((unsigned int)fileBuf + FOA + 8 + j * 2 );
			WORD offset = flag & 0x0FFF;
			if (flag >> 12 == 3) {
				printf("需要修改的虚拟地址为0x%x\n", relocsVirtualAddress + offset);
			}
		}
		printf("*********************************\n");
	}


}

void* PEInfo::readFile(char* file_name) {
	FILE* pFile = NULL;
	SIZE_T lSize;
	fopen_s(&pFile, file_name, "rb");
	if (pFile == NULL)
	{
		fputs("File error", stderr);
		exit(1);
	}
	//获取文件大小
	fseek(pFile, 0, SEEK_END);
	lSize = ftell(pFile);
	rewind(pFile);
	printf("size = %d\n", lSize);

	void* buf = NULL;
	//buf = VirtualAlloc(NULL,lSize,0x20000000,PAGE_EXECUTE_READWRITE);
	//申请内存
	buf = malloc(lSize);
	if (buf == NULL) {
		printf("申请内存失败\n");
		exit(1);
	}
	fread(buf, 1, lSize, pFile);
	fclose(pFile);
	return buf;
}
int PEInfo::RVAToFOA(DWORD RVA) {
	DWORD  offset = 0;
	for (int i = 1; i < NumberOfSections; i++) {
		if (RVA < head[i].VirtualAddress && RVA>=head[i - 1].VirtualAddress) {
			offset = RVA - head[i - 1].VirtualAddress;
			offset = offset + head[i - 1].PointerToRawData;
			return offset;
		}
		if (i == NumberOfSections - 1) {
			offset = RVA - head[i].VirtualAddress;
			return offset + head[i].PointerToRawData;
		}
	}
}
void PEInfo::ImageToFile(char* file_name, int expand) {
	FILE* pFile = NULL;
	SIZE_T fileSize = 0;
	void* toFilebuf = NULL;
	if (fopen_s(&pFile, file_name, "wb+") != 0) {
		exit(1);
	}
	if (pFile == NULL)
	{
		fputs("File error", stderr);
		exit(1);
	}
	fileSize = head[NumberOfSections - 1].PointerToRawData + head[NumberOfSections - 1].SizeOfRawData;
	printf("file sieze 0x%x", fileSize);
	toFilebuf = malloc(fileSize);
	if (toFilebuf == NULL) {
		printf("malloc toFilebuf error\n");
		exit(1);
	}
	memset(toFilebuf, 0, fileSize);
	memcpy(toFilebuf, imageBuf, SizeOfHeaders);
	for (int i = 0; i < NumberOfSections; i++) {
		memcpy((void*)((unsigned int)toFilebuf + head[i].PointerToRawData), (void*)((unsigned int)imageBuf + head[i].VirtualAddress), head[i].SizeOfRawData);
	}
	fwrite(toFilebuf, 1, fileSize, pFile);
	fclose(pFile);
	free(toFilebuf);

}
void* PEInfo::fileToImage() {
	//申请空间;
	imageBuf = malloc(SizeOfImage + 0x1000);
	if (imageBuf == NULL) {
		printf("malloc buf2 error\n");
		return NULL;
	}
	memset(imageBuf, 0, SizeOfImage + 0x1000);
	//拷贝头+节表
	memcpy(imageBuf, fileBuf, SizeOfHeaders);
	for (int i = 0; i < NumberOfSections; i++) {
		memcpy((void*)((unsigned int)imageBuf + head[i].VirtualAddress), (void*)((unsigned int)fileBuf + head[i].PointerToRawData), head[i].SizeOfRawData);
	}
}
void PEInfo::getPEinfo() {
	void* P = NULL;
	//获取PE头大小
	P = (long*)P;
	P = &e_lfanew;
	memcpy(P, (void*)((unsigned int)fileBuf + 0x3C), 4);
	printf("PE头的偏移地址: 0x%x\n", e_lfanew);

	//PE中节的数量
	P = (WORD*)P;
	P = &NumberOfSections;
	memcpy(P, (void*)((unsigned int)fileBuf + e_lfanew + 0x6), 2);
	printf("节的数量:%d\n", NumberOfSections);

	//扩展头长度
	P = (DWORD*)P;
	P = &SizeOfOptionalHeader;
	memcpy(P, (void*)((unsigned int)fileBuf + e_lfanew + 0x14), 4);
	printf("扩展头长度:0x%x\n", SizeOfOptionalHeader);

	//程序执行入口RVA
	P = (DWORD*)P;
	P = &AddressOfEntryPoint;
	memcpy(P, (void*)((unsigned int)fileBuf + e_lfanew + 0x28), 4);
	printf("程序执行入口RVA:0x%x\n", AddressOfEntryPoint);

	//程序的建议装载地址
	P = (DWORD*)P;
	P = &ImageBase;
	memcpy(P, (void*)((unsigned int)fileBuf + e_lfanew + 0x34), 4);
	printf("程序的建议装载地址:0x%x\n", ImageBase);

	//所有头+节表的大小
	P = (DWORD*)P;
	P = &SizeOfHeaders;
	memcpy(P, (void*)((unsigned int)fileBuf + e_lfanew + 0x54), 4);
	printf("所有头+节表的大小:0x%x\n", SizeOfHeaders);

	//整个在内存中的大小
	P = (DWORD*)P;
	P = &SizeOfImage;
	memcpy(P, (void*)((unsigned int)fileBuf + e_lfanew + 0x50), 4);
	printf("整个在内存中的大小:0x%x\n", SizeOfImage);

	//文件中的节的对齐粒度
	P = (DWORD*)P;
	P = &FileAlignment;
	memcpy(P, (void*)((unsigned int)fileBuf + e_lfanew + 0x3c), 4);
	printf("文件中的节的对齐粒度:0x%x\n", FileAlignment);

	//存储节的数据结构
	DWORD temp;
	P = (DWORD*)P;
	P = &temp;
	for (int i = 0; i < 16; i++) {
		memcpy(P, (void*)((unsigned int)fileBuf + e_lfanew + 0x78 + 0x8 * i + 0x0), 4);
		DATA_DIRECTORY[i].VirtualAddress = temp;
		memcpy(P, (void*)((unsigned int)fileBuf + e_lfanew + 0x78 + 0x8 * i + 0x4), 4);
		DATA_DIRECTORY[i].Size = temp;
		printf("VirtualAddress: 0x%x Size 0x%x\n", DATA_DIRECTORY[i].VirtualAddress, DATA_DIRECTORY[i].Size);
	}
	char PEname[9] = { 0 };
	for (int i = 0; i < NumberOfSections; i++) {
		memcpy(P, (void*)((unsigned int)fileBuf + e_lfanew + SizeOfOptionalHeader + 0x18 + 0x28 * i + 0x8), 4);
		head[i].Misc = temp;
		memcpy(PEname, (void*)((unsigned int)fileBuf + e_lfanew + SizeOfOptionalHeader + 0x18 + 0x28 * i), 8);
		memcpy(P, (void*)((unsigned int)fileBuf + e_lfanew + SizeOfOptionalHeader + 0x18 + 0x28 * i + 0x10), 4);
		head[i].SizeOfRawData = temp;
		memcpy(P, (void*)((unsigned int)fileBuf + e_lfanew + SizeOfOptionalHeader + 0x18 + 0x28 * i + 0xc), 4);
		head[i].VirtualAddress = temp;
		memcpy(P, (void*)((unsigned int)fileBuf + e_lfanew + SizeOfOptionalHeader + 0x18 + 0x28 * i + 0x14), 4);
		head[i].PointerToRawData = temp;
		printf("PEname: %s Misc: 0x%x PointerToRawData 0x%x SizeOfRawData 0x%x  VirtualAddress 0x%x\n", PEname, head[i].Misc, head[i].PointerToRawData, head[i].SizeOfRawData, head[i].VirtualAddress);
	}
}
void* PEInfo::changeFile() {
	unsigned shellAddress = 0;
	int flag = 0;
	for (int i = 0; i < NumberOfSections; i++) {
		if (head[i].SizeOfRawData - head[i].Misc > 20) {
			//在中间找空闲段插入代码
			shellAddress = head[i].VirtualAddress + head[i].Misc;
			flag = i;
			break;
		}
	}
	int X = MessageAddress - (shellAddress + ImageBase + 13);
	printf("距离为%x\n", X);
	int* pX = &X;
	BYTE* BPX = (BYTE*)pX;
	for (int i = 0; i < 4; i++) {
		shellcode[9 + i] = BPX[i];
	}
	int Y = AddressOfEntryPoint - (shellAddress + 18);
	int* pY = &Y;
	BYTE* BPY = (BYTE*)pY;
	for (int i = 0; i < 4; i++) {
		shellcode[14 + i] = BPY[i];
	}
	printf("插入到第%d节\n", flag + 1);
	memcpy((void*)((unsigned int)imageBuf + head[flag].VirtualAddress + head[flag].Misc), shellcode, sizeof(shellcode));
	unsigned int* PShellCode = &shellAddress;
	memcpy((void*)((unsigned int)imageBuf + e_lfanew + 0x28), (void*)PShellCode, 4);
	printf("ShellCode入口地址为 0x%x\n", shellAddress);
	return imageBuf;
}
void PEInfo::expandSection(int expand) {
	void* P;
	unsigned shellAddress = 0;
	SizeOfImage += 0x1000;
	P = &SizeOfImage;
	memcpy((void*)((unsigned int)imageBuf + e_lfanew + 0x50), P, 4);
	int oldSizeOfRawData = head[NumberOfSections - 1].SizeOfRawData;//保存最后一个节的原始大小
	int newLastSizeOfRawData = head[NumberOfSections - 1].SizeOfRawData + expand;
	//改变最后文件填写的大小
	head[NumberOfSections - 1].SizeOfRawData = head[NumberOfSections - 1].SizeOfRawData + expand;
	int newLastMisc = head[NumberOfSections - 1].Misc + expand;
	head[NumberOfSections - 1].Misc = head[NumberOfSections - 1].Misc + expand;
	P = &newLastMisc;
	memcpy((void*)((unsigned int)imageBuf + e_lfanew + SizeOfOptionalHeader + 0x18 + 0x28 * (NumberOfSections - 1) + 0x8), P, 4);
	P = &newLastSizeOfRawData;
	memcpy((void*)((unsigned int)imageBuf + e_lfanew + SizeOfOptionalHeader + 0x18 + 0x28 * (NumberOfSections - 1) + 0x10), P, 4);

	shellAddress = head[NumberOfSections - 1].VirtualAddress + oldSizeOfRawData;
	int X = MessageAddress - (shellAddress + ImageBase + 13);
	int* pX = &X;
	BYTE* BPX = (BYTE*)pX;
	for (int i = 0; i < 4; i++) {
		shellcode[9 + i] = BPX[i];
	}
	int Y = AddressOfEntryPoint - (shellAddress + 18);
	int* pY = &Y;
	BYTE* BPY = (BYTE*)pY;
	for (int i = 0; i < 4; i++) {
		shellcode[14 + i] = BPY[i];
	}
	memcpy((void*)((unsigned int)imageBuf + head[NumberOfSections - 1].VirtualAddress + oldSizeOfRawData), shellcode, sizeof(shellcode));
	unsigned int* PShellCode = &shellAddress;
	memcpy((void*)((unsigned int)imageBuf + e_lfanew + 0x28), (void*)PShellCode, 4);
	printf("ShellCode入口地址为 0x%x\n", shellAddress);
}