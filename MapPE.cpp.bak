#include <windows.h> // Compiled with: i686-w64-mingw32-g++-win32 -static-libgcc -static-libstdc++ MapPE.cpp -o MapPE.exe
#include <fstream>
#include <stdio.h>
#include <iostream>

using namespace std;


void PrintInfo(char *);
void Dump(char*);
void CheckIntegrity(char*,char*,int);
void Banner();


int main(int argc, char const *argv[])
{

	if(argc<2){
		Banner();
		cout << "Usage: \n\tMapPE.exe  input.exe\n";
		exit(1);
	}

	Banner();


	fstream File;
	File.open (argv[1], std::fstream::in | std::fstream::out | std::fstream::binary);
	if(File.is_open()){


		File.seekg(0, File.end);
		int FileSize = File.tellg();
		File.seekg(0, File.beg);

		char * PE = (char*)VirtualAlloc(NULL,FileSize,MEM_COMMIT,PAGE_READWRITE);

		//char * PE = new char[FileSize];
		
		for(int i = 0; i < FileSize; i++){
			File.get(PE[i]);
		}

		PrintInfo(PE);
		
		Dump(PE);
		
	}
	else{
		cout << "[!] Unable to open file (" << argv[1] << ")\n";
		exit(1);	
	}


	return 0;
}

void PrintInfo(char * PE){

	IMAGE_DOS_HEADER * DOSHeader; // For Nt DOS Header symbols
	IMAGE_NT_HEADERS * NtHeader; // For Nt PE Header objects & symbols
	IMAGE_SECTION_HEADER * SectionHeader;
	_IMAGE_FILE_HEADER * FileHeader;
	IMAGE_OPTIONAL_HEADER * OptHeader;
	_IMAGE_DATA_DIRECTORY * ImportTable;
	_IMAGE_DATA_DIRECTORY * ImportAddressTable;
	_IMAGE_DATA_DIRECTORY * ExportTable;
	_IMAGE_DATA_DIRECTORY * RelocationTable;

	DOSHeader = PIMAGE_DOS_HEADER(PE); // Initialize Variable
	NtHeader = PIMAGE_NT_HEADERS(DWORD(PE) + DOSHeader->e_lfanew); // Initialize	
	FileHeader = &NtHeader->FileHeader;
	OptHeader = &NtHeader->OptionalHeader;


	if(PE[0] == 'M' && PE[1] == 'Z'){
		cout << "[+] \"MZ\" magic number found !\n";
		if(NtHeader->Signature == IMAGE_NT_SIGNATURE){
			cout << "[+] Valid \"PE\" signature \n\n";

			cout << "[-------------------------------------]\n";

			printf("[*] ImageBase: 0x%x\n", OptHeader->ImageBase);
			printf("[*] Address Of Entry: 0x%x\n", (OptHeader->ImageBase+OptHeader->AddressOfEntryPoint));

			cout << "[*] Number Of Sections: " << FileHeader->NumberOfSections << endl;
			cout << "[*] Number Of Symbols: " << FileHeader->NumberOfSymbols << endl;

			cout << "[*] Size Of Image: " << OptHeader->SizeOfImage << " bytes\n";
			cout << "[*] Size Of Headers: " << OptHeader->SizeOfHeaders << " bytes\n";

			printf("[*] Checksum: 0x%x\n", OptHeader->CheckSum);
			printf("[*] Subsystem: 0x%x\n", OptHeader->Subsystem);


			ExportTable = &OptHeader->DataDirectory[0];
			ImportTable = &OptHeader->DataDirectory[1];
			RelocationTable = &OptHeader->DataDirectory[5];
			ImportAddressTable = &OptHeader->DataDirectory[12];


			printf("[*] Export Table: 0x%x\n", (ExportTable->VirtualAddress+OptHeader->ImageBase));
			printf("[*] Import Table: 0x%x\n", (ImportTable->VirtualAddress+OptHeader->ImageBase));
			printf("[*] Import Address Table: 0x%x\n", (ImportAddressTable->VirtualAddress+OptHeader->ImageBase));
			printf("[*] Relocation Table: 0x%x\n", (RelocationTable->VirtualAddress+OptHeader->ImageBase));

			cout << "[-------------------------------------]\n\n\n";


			for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++){
				SectionHeader = PIMAGE_SECTION_HEADER(DWORD(PE) + DOSHeader->e_lfanew + 248 + (i * 40));
				cout << "##########################################\n";
				cout << "#                                        #\n";
				cout << "#   ";
				for(int c = 0; c < 8; c++){
					if(SectionHeader->Name[c] == NULL){
						cout << " ";
					}
					else{
						cout << SectionHeader->Name[c];
					}
				}
				cout << " -> ";
				printf("0x%x", (SectionHeader->VirtualAddress+OptHeader->ImageBase)); 
				cout << "                 #\n";
				
				for(int j = 0; j < (SectionHeader->SizeOfRawData/(OptHeader->SizeOfImage/20)); j++){
					cout << "#                                        #\n";
				}
			}

			cout << "########################################## -> ";
			printf("0x%x\n\n", (OptHeader->SizeOfImage+OptHeader->ImageBase));
		}
		else{
			cout << "[!] PE signature missing ! \n";
			cout << "[!] File is not a valid PE :( \n";
			exit(1);
		}	
	}
	else{
		cout << "[!] Magic number not valid !\n";
		cout << "[!] File is not a valid PE :(\n";
		exit(1);
	}
	

}



/*
WriteProcessMemory(PI.hProcess, LPVOID(DWORD(pImageBase) + SectionHeader->VirtualAddress),LPVOID(DWORD(Image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
*/


void Dump(char * PE){

	IMAGE_DOS_HEADER * DOSHeader; // For Nt DOS Header symbols
	IMAGE_NT_HEADERS * NtHeader; // For Nt PE Header objects & symbols
	IMAGE_SECTION_HEADER * SectionHeader;
	IMAGE_SECTION_HEADER * NextSectionHeader;
	_IMAGE_FILE_HEADER * FileHeader;
	IMAGE_OPTIONAL_HEADER * OptHeader;	


	DOSHeader = PIMAGE_DOS_HEADER(PE); // Initialize Variable
	NtHeader = PIMAGE_NT_HEADERS(DWORD(PE) + DOSHeader->e_lfanew); // Initialize	
	FileHeader = &NtHeader->FileHeader;
	OptHeader = &NtHeader->OptionalHeader;



	DWORD ImageBase = OptHeader->ImageBase;

	system("del Mem.map");

	fstream File;
	File.open ("Mem.map", std::fstream::in | std::fstream::out | std::fstream::app | std::fstream::binary);
	if(File.is_open()){

		cout << "[>] Maping PE headers...\n";
		printf("[>] 0x%x\n", ImageBase);
		File.write((char*)PE, NtHeader->OptionalHeader.SizeOfHeaders);
		ImageBase += NtHeader->OptionalHeader.SizeOfHeaders;

		SectionHeader = PIMAGE_SECTION_HEADER(DWORD(PE) + DOSHeader->e_lfanew + 248);
							
		while(1){
			if((OptHeader->ImageBase+SectionHeader->VirtualAddress) > ImageBase){
				File << (char)NULL;
				ImageBase++;
			}
			else{
				break;
			}	
		}

		printf("[>] 0x%x\n", ImageBase);


		cout << "[>] Maping sections... " << endl;
		for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
		{
			SectionHeader = PIMAGE_SECTION_HEADER(DWORD(PE) + DOSHeader->e_lfanew + 248 + (i * 40));
			cout << "[>]  " << SectionHeader->Name << endl;
			printf("[>] 0x%x\n", ImageBase);


			File.write((char*)(DWORD(PE) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData);
			ImageBase += SectionHeader->SizeOfRawData;


			if (i <= (NtHeader->FileHeader.NumberOfSections-2));
			{
				NextSectionHeader = PIMAGE_SECTION_HEADER(DWORD(PE) + DOSHeader->e_lfanew + 248 + ((i+1) * 40));
							
				while(1){
					if((OptHeader->ImageBase+NextSectionHeader->VirtualAddress) > ImageBase){
						File << (char)NULL;
						ImageBase++;
					}
					else{
						break;
					}	
				}
			}

			printf("[>] 0x%x\n", ImageBase);
		}

		while(1){
			if((OptHeader->SizeOfImage+OptHeader->ImageBase) > ImageBase){
				File << (char)NULL;
				ImageBase++;
			}
			else{
				break;
			}	
		}

		cout << "\n[+] File mapping completed !\n";

		cout << "\n[*] Starting integrity checks...\n";
		

		File.seekg(0, File.end);
		int MapSize = File.tellg();
		File.seekg(0, File.beg);

		cout << "\n[*] Mapped size: " << MapSize << endl;



		char * Map = (char*)VirtualAlloc(NULL,MapSize,MEM_COMMIT,PAGE_READWRITE);

		for(int i = 0; i < MapSize; i++){
			File.get(Map[i]);
		}

		CheckIntegrity(PE,Map,MapSize);

		File.close();

		cout << "\n[+] Mapped image dumped into Mem.map\n";

	}
	else{
		cout << "[!] Can't create dump file !";
		exit(1);
	}
}


void CheckIntegrity(char * PE, char * Map, int MapSize){

	IMAGE_DOS_HEADER * DOSHeader; // Dos header pointer 
	IMAGE_NT_HEADERS * NtHeader; // NTHeader pointer
	IMAGE_SECTION_HEADER * SectionHeader; // Section header pointer
	_IMAGE_FILE_HEADER * FileHeader; // File pointer
	IMAGE_OPTIONAL_HEADER * OptHeader; // Optional hader pointer
	_IMAGE_DATA_DIRECTORY * ImportTable; // Data directory pointer
	_IMAGE_DATA_DIRECTORY * ImportAddressTable;	// Address of IAT
	IMAGE_IMPORT_DESCRIPTOR * ImportDescriptor; // Image import descriptor pointer


	DOSHeader = PIMAGE_DOS_HEADER(PE); // Initialize Variable
	NtHeader = PIMAGE_NT_HEADERS(DWORD(PE) + DOSHeader->e_lfanew); // Initialize Ntheader	
	FileHeader = &NtHeader->FileHeader; 
	OptHeader = &NtHeader->OptionalHeader;
	ImportTable = &OptHeader->DataDirectory[2];
	ImportAddressTable = &OptHeader->DataDirectory[13];


/*
	cout << "\n[*] Checking for bounded imports................... ";

	if()
*/

	cout << "\n[*] Checking image size............................ ";

	if(OptHeader->SizeOfImage != MapSize){
		cout << "[FAILED] \n\n" << "[!] Image size does not match :(\n";
		exit(1);
	}
	cout << "[OK]";



	cout << "\n[*] Checking section alignment..................... ";

	for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++){
		SectionHeader = PIMAGE_SECTION_HEADER(DWORD(PE) + DOSHeader->e_lfanew + 248 + (i * 40));
		for(int j = 0; j < (SectionHeader->SizeOfRawData/10); j++){
			
			if(PE[SectionHeader->PointerToRawData+j] != Map[SectionHeader->VirtualAddress+j]) {
				cout << "[FAILED] \n\n" << "[!] Broken section alignment :(\n";
				exit(1);
			}
		}
	}
	cout << "[OK]\n";


	cout << "[*] Checking data directory intervals.............. ";

	ImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(ImportTable->VirtualAddress+OptHeader->ImageBase);

	for(int i = 0; i < (ImportAddressTable->Size/10); i++){
		if(Map[ImportDescriptor->FirstThunk+i] != Map[ImportAddressTable->VirtualAddress+i]){
			cout << "[FAILED] \n\n" << "Incorrect data directory intervals :(\n";
			exit(1);			
		}
	}
	cout << "[OK]\n";



}




void Banner(){

cout << "                     _____________________\n";
cout << "  _____ _____  ______\\______   \\_   _____/\n";
cout << " /     \\__  \\ \\____ \\|     ___/|    __)_ \n";
cout << "|  Y Y  \\/ __ \\|  |_> >    |    |        \\\n";
cout << "|__|_|  (____  /   __/|____|   /_______  /\n";
cout << "      \\/     \\/|__|                    \\/ \n";

cout << "\nAuthor: Ege Balci\n";
cout << "Github: github.com/egebalci/mappe\n\n";

}