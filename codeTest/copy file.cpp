#include <iostream>
#include <windows.h>
#include <cstring>
#define MessageAddress 0x767F13D0
BYTE shellcode[] ={0x6A,00,0x6A,00,0x6A,00,0x6A,00,0xE8,00,00,00,00,0xE9,00,00,00,00};
struct SECTION_HEADER{
	DWORD	Misc;                            // +0008h   -   �����ĳߴ�
	DWORD   VirtualAddress;                  // +000ch   -   ������RVA��ַ
	DWORD   SizeOfRawData;                   // +0010h   -   ���ļ��ж����ĳߴ�
    DWORD   PointerToRawData;                // +0014h   -   ���ļ��е�ƫ��
	}head[10];
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

//GET PE
void getPEinfo(void *buf){
	void *P = NULL;
	//��ȡPEͷ��С
	P=(long*)P;
	P = &e_lfanew;
	memcpy(P,(void *)((unsigned int)buf+0x3C),4);
	printf("PEͷ��ƫ�Ƶ�ַ: 0x%x\n",e_lfanew);

	//PE�нڵ�����
	P=(WORD *)P;
	P=&NumberOfSections;
	memcpy(P,(void *)((unsigned int)buf+e_lfanew+0x6),2);
	printf("�ڵ�����:%d\n",NumberOfSections);

	//��չͷ����
	P=(DWORD *)P;
	P=&SizeOfOptionalHeader;
	memcpy(P,(void *)((unsigned int)buf+e_lfanew+0x14),4);
	printf("��չͷ����:0x%x\n",SizeOfOptionalHeader);
	
	//����ִ�����RVA
	P=(DWORD *)P;
	P=&AddressOfEntryPoint;
	memcpy(P,(void *)((unsigned int)buf+e_lfanew+0x28),4);
	printf("����ִ�����RVA:0x%x\n",AddressOfEntryPoint);

	//����Ľ���װ�ص�ַ
	P=(DWORD *)P;
	P=&ImageBase;
	memcpy(P,(void *)((unsigned int)buf+e_lfanew+0x34),4);
	printf("����Ľ���װ�ص�ַ:0x%x\n",ImageBase);

	//����ͷ+�ڱ�Ĵ�С
	P=(DWORD *)P;
	P=&SizeOfHeaders;
	memcpy(P,(void *)((unsigned int)buf+e_lfanew+0x54),4);
	printf("����ͷ+�ڱ�Ĵ�С:0x%x\n",SizeOfHeaders);

	//�������ڴ��еĴ�С
	P=(DWORD *)P;
	P=&SizeOfImage;
	memcpy(P,(void *)((unsigned int)buf+e_lfanew+0x50),4);
	printf("�������ڴ��еĴ�С:0x%x\n",SizeOfImage);

	//�ļ��еĽڵĶ�������
	P=(DWORD *)P;
	P=&FileAlignment;
	memcpy(P,(void *)((unsigned int)buf+e_lfanew+0x3c),4);
	printf("�ļ��еĽڵĶ�������:0x%x\n",FileAlignment);

	//�洢�ڵ����ݽṹ
	DWORD temp;
	P=(DWORD *)P;
	P=&temp;
	char name[9]={0};
	for(int i=0;i<NumberOfSections;i++){
		memcpy(P,(void *)((unsigned int)buf+e_lfanew+SizeOfOptionalHeader+0x18+0x28*i+0x8),4);
		head[i].Misc=temp;
		memcpy(name,(void *)((unsigned int)buf+e_lfanew+SizeOfOptionalHeader+0x18+0x28*i),8);
		memcpy(P,(void *)((unsigned int)buf+e_lfanew+SizeOfOptionalHeader+0x18+0x28*i+0x10),4);
		head[i].SizeOfRawData=temp;
		memcpy(P,(void *)((unsigned int)buf+e_lfanew+SizeOfOptionalHeader+0x18+0x28*i+0xc),4);
		head[i].VirtualAddress=temp;
		memcpy(P,(void *)((unsigned int)buf+e_lfanew+SizeOfOptionalHeader+0x18+0x28*i+0x14),4);
		head[i].PointerToRawData=temp;
		printf("name: %s Misc: 0x%x PointerToRawData 0x%x SizeOfRawData 0x%x \n",name,head[i].Misc,head[i].PointerToRawData,head[i].SizeOfRawData);
	}
}
//File->Image
void * fileToImage(void * buf){
	//����ռ�
	void *buf2=NULL;
	buf2=malloc(SizeOfImage);
	if(buf2==NULL){
		printf("malloc buf2 error\n");
		return NULL;
	}
	memset(buf2,0,SizeOfImage);
	//����ͷ+�ڱ�
	memcpy(buf2,buf,SizeOfHeaders);
	for(int i=0;i<NumberOfSections;i++){
		memcpy((void *)((unsigned int)buf2+head[i].VirtualAddress),(void *)((unsigned int)buf+head[i].PointerToRawData),head[i].SizeOfRawData);
	}
	return buf2;
}

//Image->File
void ImageToFile(void *Imagebuf,char *file_name){
	FILE *pFile;
	SIZE_T fileSize;
	void *toFilebuf;
	pFile = fopen(file_name,"wb+");
	if (pFile==NULL)
    {
        fputs ("File error",stderr);
        exit (1);
    }
	fileSize=head[NumberOfSections-1].PointerToRawData+head[NumberOfSections-1].SizeOfRawData;
	printf("file sieze 0x%x",fileSize);
	toFilebuf = malloc(fileSize);
	if(toFilebuf==NULL){
		printf("malloc toFilebuf error\n");
		exit(1);
	}
	memset(toFilebuf,0,fileSize);
	memcpy(toFilebuf,Imagebuf,SizeOfHeaders);
	for(int i=0;i<NumberOfSections;i++){
		memcpy((void *)((unsigned int)toFilebuf+head[i].PointerToRawData),(void *)((unsigned int)Imagebuf+head[i].VirtualAddress),head[i].SizeOfRawData);
	}
	fwrite(toFilebuf,1,fileSize,pFile);
	fclose(pFile);
	free(toFilebuf);

}

//readFile
void* readFile(char *file_name){
	FILE *pFile;
	SIZE_T lSize;
	pFile = fopen(file_name,"rb");
	if (pFile==NULL)
    {
        fputs ("File error",stderr);
        exit (1);
    }
	//��ȡ�ļ���С
	fseek (pFile , 0 , SEEK_END);
    lSize = ftell (pFile);
	rewind(pFile);
	printf("size = %d\n",lSize);

	void * buf = NULL;
	//buf = VirtualAlloc(NULL,lSize,0x20000000,PAGE_EXECUTE_READWRITE);
	//�����ڴ�
	buf = malloc(lSize);
	if(buf == NULL){
		printf("�����ڴ�ʧ��\n");
		exit(1);
	}
	fread(buf,1,lSize,pFile);
	fclose(pFile);
	return buf;
}
//change File
void* changeFile(void *imageBuf){
	unsigned shellAddress=0;
	int flag;
	for(int i=0;i<NumberOfSections;i++){
		if(head[i].SizeOfRawData-head[i].Misc>20){
			//���м��ҿ��жβ������
			shellAddress=head[i].VirtualAddress+head[i].Misc;
			flag=i;
			break;
		}
	}
	int X =MessageAddress-(shellAddress+ImageBase+13);
	printf("����Ϊ%x\n",X);
	int* pX = &X;
	BYTE *BPX=(BYTE*)pX;
	for(i=0;i<4;i++){
		shellcode[9+i]=BPX[i];
	}
	int Y=AddressOfEntryPoint-(shellAddress+18);
	int* pY = &Y;
	BYTE *BPY=(BYTE*)pY;
	for(i=0;i<4;i++){
		shellcode[14+i]=BPY[i];
	}
	printf("���뵽��%d��\n",flag+1);
	memcpy((void *)((unsigned int)imageBuf+head[flag].VirtualAddress+head[flag].Misc),shellcode,sizeof(shellcode));
	unsigned int *PShellCode = &shellAddress;
	memcpy((void *)((unsigned int)imageBuf+e_lfanew+0x28),(void*)PShellCode,4);
	printf("ShellCode��ڵ�ַΪ 0x%x\n",shellAddress);
	return imageBuf;
	
}
void main(){
	char *file_name="cpp1.exe";
	void *fileBuf;
	void *imageBuf;
	char *file_name2="file.exe";
	fileBuf = readFile(file_name);
	getPEinfo(fileBuf);
	imageBuf = fileToImage(fileBuf);
	imageBuf = changeFile(imageBuf);
	ImageToFile(imageBuf,file_name2);
	free(fileBuf);
	free(imageBuf);
}