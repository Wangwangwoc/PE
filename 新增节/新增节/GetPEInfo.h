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
		DWORD	Misc;                            // +0008h   -   �����ĳߴ�
		DWORD   VirtualAddress;                  // +000ch   -   ������RVA��ַ
		DWORD   SizeOfRawData;                   // +0010h   -   ���ļ��ж����ĳߴ�
		DWORD   PointerToRawData;                // +0014h   -   ���ļ��е�ƫ��
	}head[10];
	struct {
	DWORD   VirtualAddress;                 // +0000h   -   ���ݵ���ʼRVA
	DWORD   Size;                           // +0004h   -   ���ݿ�ĳ���
	}DATA_DIRECTORY[16];
	//PEƫ��
	long e_lfanew;
	//��׼ͷ
	WORD    NumberOfSections;                    // +0006h   -   PE�нڵ�����
	WORD    SizeOfOptionalHeader;                // +0014h   -   ��չͷ�ṹ�ĳ���
	//��չͷ
	DWORD   AddressOfEntryPoint;                   // +0028h   -   ����ִ�����RVA
	DWORD   ImageBase;                             // +0034h   -   ����Ľ���װ�ص�ַ
	DWORD   FileAlignment;                         // +003ch   -   �ļ��еĽڵĶ�������
	DWORD   SizeOfImage;                           // +0050h   -   �ڴ��е�����PEӳ��ߴ�
	DWORD   SizeOfHeaders;                        // +0054h   -   ����ͷ+�ڱ�Ĵ�С

	//��ȡ�ļ����ڴ�
	void* readFile(char* file_name);
	//��ȡ PE��Ϣ
	void getPEinfo();
	//�ļ��ڴ�����Ϊ�ڴ��еĽṹ
	void* fileToImage();
	//���ڴ��еĽṹת�����ļ��ṹ
	void ImageToFile(char* file_name, int expand);
	//���ļ��в���shellcode
	void* changeFile();
	//�����ļ����һ���ڲ�����shellcode
	void expandSection(int expand);
	//�����ַת�ļ���ַ
	int RVAToFOA(DWORD RVA);
	//��ȡ��������ĺ�����ַ
	void GetExport(char* func_name);
	//��ȡ�ض�λ������
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
		//����ѧϰ���Ӿ����ַȡ����Ҫ�涨��������
		FOA = RVAToFOA(*PDWORD((unsigned int)fileBuf + AddressOfName + i * 4));
		funcName = (char*)((unsigned int)fileBuf + FOA);
		if (*func_name == *funcName) {
			printf("������Ϊ%s\n", funcName);
			index = i;
			break;
		}
	} 
	unsigned int FuncIndex = 0;
	FuncIndex = *PWORD((unsigned int)fileBuf + AddressOfNameOrd + index * 2);
	printf("������ַ���Ϊ0x%d\n", FuncIndex);
	funcAddress = *PDWORD((unsigned int)fileBuf + AddressOfFunction + FuncIndex * 4);
	printf("������ַΪ0x%x\n", funcAddress);
}
void PEInfo::GetRelocs() {
	DWORD FOA = 0;
	FOA=RVAToFOA(DATA_DIRECTORY[5].VirtualAddress);
	printf("�ض�λ���ַ: 0x%x\n", FOA);
	DWORD sizeOfBlock = 0;
	unsigned int number = 0;
	WORD flag = 0;
	for (int i = 0; 1; i++) {
		DWORD relocsVirtualAddress=*PDWORD((unsigned int)fileBuf + FOA);
		sizeOfBlock = *PDWORD((unsigned int)fileBuf + FOA+4);
		FOA += sizeOfBlock;		//ÿ��Ǩ�Ƶ�ǰ��ַ����һ���ض�λ��ͷ
		number = (sizeOfBlock - 8) / 2;		//����ض�λ���ڸ���
		printf("��Ҫ�޸ĵĵ�ַ: 0x%x\n", relocsVirtualAddress);
		printf("sizeOfBlock: 0x%x\n", sizeOfBlock);
		if (relocsVirtualAddress == 0) {
			break;
		}
		for (int j = 0; j < number; j++) {
			flag = *PWORD((unsigned int)fileBuf + FOA + 8 + j * 2 );
			WORD offset = flag & 0x0FFF;
			if (flag >> 12 == 3) {
				printf("��Ҫ�޸ĵ������ַΪ0x%x\n", relocsVirtualAddress + offset);
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
	//��ȡ�ļ���С
	fseek(pFile, 0, SEEK_END);
	lSize = ftell(pFile);
	rewind(pFile);
	printf("size = %d\n", lSize);

	void* buf = NULL;
	//buf = VirtualAlloc(NULL,lSize,0x20000000,PAGE_EXECUTE_READWRITE);
	//�����ڴ�
	buf = malloc(lSize);
	if (buf == NULL) {
		printf("�����ڴ�ʧ��\n");
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
	//����ռ�;
	imageBuf = malloc(SizeOfImage + 0x1000);
	if (imageBuf == NULL) {
		printf("malloc buf2 error\n");
		return NULL;
	}
	memset(imageBuf, 0, SizeOfImage + 0x1000);
	//����ͷ+�ڱ�
	memcpy(imageBuf, fileBuf, SizeOfHeaders);
	for (int i = 0; i < NumberOfSections; i++) {
		memcpy((void*)((unsigned int)imageBuf + head[i].VirtualAddress), (void*)((unsigned int)fileBuf + head[i].PointerToRawData), head[i].SizeOfRawData);
	}
}
void PEInfo::getPEinfo() {
	void* P = NULL;
	//��ȡPEͷ��С
	P = (long*)P;
	P = &e_lfanew;
	memcpy(P, (void*)((unsigned int)fileBuf + 0x3C), 4);
	printf("PEͷ��ƫ�Ƶ�ַ: 0x%x\n", e_lfanew);

	//PE�нڵ�����
	P = (WORD*)P;
	P = &NumberOfSections;
	memcpy(P, (void*)((unsigned int)fileBuf + e_lfanew + 0x6), 2);
	printf("�ڵ�����:%d\n", NumberOfSections);

	//��չͷ����
	P = (DWORD*)P;
	P = &SizeOfOptionalHeader;
	memcpy(P, (void*)((unsigned int)fileBuf + e_lfanew + 0x14), 4);
	printf("��չͷ����:0x%x\n", SizeOfOptionalHeader);

	//����ִ�����RVA
	P = (DWORD*)P;
	P = &AddressOfEntryPoint;
	memcpy(P, (void*)((unsigned int)fileBuf + e_lfanew + 0x28), 4);
	printf("����ִ�����RVA:0x%x\n", AddressOfEntryPoint);

	//����Ľ���װ�ص�ַ
	P = (DWORD*)P;
	P = &ImageBase;
	memcpy(P, (void*)((unsigned int)fileBuf + e_lfanew + 0x34), 4);
	printf("����Ľ���װ�ص�ַ:0x%x\n", ImageBase);

	//����ͷ+�ڱ�Ĵ�С
	P = (DWORD*)P;
	P = &SizeOfHeaders;
	memcpy(P, (void*)((unsigned int)fileBuf + e_lfanew + 0x54), 4);
	printf("����ͷ+�ڱ�Ĵ�С:0x%x\n", SizeOfHeaders);

	//�������ڴ��еĴ�С
	P = (DWORD*)P;
	P = &SizeOfImage;
	memcpy(P, (void*)((unsigned int)fileBuf + e_lfanew + 0x50), 4);
	printf("�������ڴ��еĴ�С:0x%x\n", SizeOfImage);

	//�ļ��еĽڵĶ�������
	P = (DWORD*)P;
	P = &FileAlignment;
	memcpy(P, (void*)((unsigned int)fileBuf + e_lfanew + 0x3c), 4);
	printf("�ļ��еĽڵĶ�������:0x%x\n", FileAlignment);

	//�洢�ڵ����ݽṹ
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
			//���м��ҿ��жβ������
			shellAddress = head[i].VirtualAddress + head[i].Misc;
			flag = i;
			break;
		}
	}
	int X = MessageAddress - (shellAddress + ImageBase + 13);
	printf("����Ϊ%x\n", X);
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
	printf("���뵽��%d��\n", flag + 1);
	memcpy((void*)((unsigned int)imageBuf + head[flag].VirtualAddress + head[flag].Misc), shellcode, sizeof(shellcode));
	unsigned int* PShellCode = &shellAddress;
	memcpy((void*)((unsigned int)imageBuf + e_lfanew + 0x28), (void*)PShellCode, 4);
	printf("ShellCode��ڵ�ַΪ 0x%x\n", shellAddress);
	return imageBuf;
}
void PEInfo::expandSection(int expand) {
	void* P;
	unsigned shellAddress = 0;
	SizeOfImage += 0x1000;
	P = &SizeOfImage;
	memcpy((void*)((unsigned int)imageBuf + e_lfanew + 0x50), P, 4);
	int oldSizeOfRawData = head[NumberOfSections - 1].SizeOfRawData;//�������һ���ڵ�ԭʼ��С
	int newLastSizeOfRawData = head[NumberOfSections - 1].SizeOfRawData + expand;
	//�ı�����ļ���д�Ĵ�С
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
	printf("ShellCode��ڵ�ַΪ 0x%x\n", shellAddress);
}