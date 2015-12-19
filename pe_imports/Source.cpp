#include <iostream>
#include <fstream>
#include <iomanip>
#include <Windows.h>

using namespace std;

#define Is2power(x) (!(x & (x - 1)))
#define ALIGN_DOWN(x, align) (x & ~(align - 1))
#define ALIGN_UP(x, align) ((x & (align - 1)) ? ALIGN_DOWN(x, align) + align : x)

int main(int argc, const char* argv[])
{
	if (argc != 2)
	{
		cout << "Usage: pe_imports.exe pe_file" << endl;
		return 0;
	}
	ifstream pefile;
	pefile.open(argv[1], ios::in | ios::binary);
	if (!pefile.is_open())
	{
		cout << "Can't open file" << endl;
		return 0;
	}

	pefile.seekg(0, ios::end);
	streamoff filesize = pefile.tellg();
	pefile.seekg(0);

	IMAGE_DOS_HEADER dos_header;
	pefile.read(reinterpret_cast<char*>(&dos_header), sizeof(IMAGE_DOS_HEADER));
	if (pefile.bad() || pefile.eof())
	{
		cout << "Unable to read IMAGE_DOS_HEADER" << endl;
		return 0;
	}

	if (dos_header.e_magic != 'ZM')
	{
		cout << "IMAGE_DOS_HEADER signature is incorrect" << endl;
		return 0;
	}

	if ((dos_header.e_lfanew % sizeof(DWORD)) != 0)
	{
		cout << "PE header is not DWORD-aligned" << endl;
		return 0;
	}

	pefile.seekg(dos_header.e_lfanew);
	if (pefile.bad() || pefile.fail())
	{
		std::cout << "Cannot reach IMAGE_NT_HEADERS" << std::endl;
		return 0;
	}

	IMAGE_NT_HEADERS nt_headers;
	pefile.read(reinterpret_cast<char*>(&nt_headers), sizeof(IMAGE_NT_HEADERS));
	//pefile.read(reinterpret_cast<char*>(&nt_headers), sizeof(IMAGE_NT_HEADERS) - sizeof(IMAGE_DATA_DIRECTORY) * 16);
	if (pefile.bad() || pefile.eof())
	{
		std::cout << "Error reading IMAGE_NT_HEADERS32" << std::endl;
		return 0;
	}
	if (nt_headers.Signature != 'EP')
	{
		std::cout << "Incorrect PE signature" << std::endl;
		return 0;
	}

	switch (nt_headers.OptionalHeader.Magic)
	{
	case 0x10B:
		cout << "This PE is PE32" << endl;
		break;
	case 0x20B:
		cout << "This PE is PE64" << endl;
		break;
	default:
		cout << "Incorrect PE Magic" << endl;
		return 0;
	}
	IMAGE_FILE_HEADER file_header = nt_headers.FileHeader;
	cout << hex << showbase << file_header.Characteristics << endl;
	DWORD first_section = dos_header.e_lfanew + nt_headers.FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD);

	pefile.seekg(first_section);
	if (pefile.bad() || pefile.fail())
	{
		cout << "Cannot reach section headers" << endl;
		return 0;
	}
	cout << hex << showbase << left;

	for (int i = 0; i < nt_headers.FileHeader.NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER header;
		pefile.read(reinterpret_cast<char*>(&header), sizeof(IMAGE_SECTION_HEADER));
		if (pefile.bad() || pefile.eof())
		{
			cout << "Error reading section header" << endl;
			return 0;
		}
		if (!header.SizeOfRawData && !header.Misc.VirtualSize)
		{
			cout << "Virtual and Physical sizes of section can't be 0 at the same time" << endl;
			return 0;
		}

		if (header.SizeOfRawData != 0)
		{
			//Проверим, что инициализированные данные секции также не вылетают за пределы нашего PE-файла
			if (ALIGN_DOWN(header.PointerToRawData, nt_headers.OptionalHeader.FileAlignment) + header.SizeOfRawData > filesize)
			{
				cout << "Incorrect section address or size" << endl;
				return 0;
			}

			//в этой переменной мы сохраним выровненный виртуальный размер секции
			DWORD virtual_size_aligned;

			//если виртуальный размер секции был выставлен в ноль,
			if (header.Misc.VirtualSize == 0)
				//то ее выровненный виртуальный размер равен ее реальному размеру инициализированных данных,
				//выровненному на границу SectionAlignment
				virtual_size_aligned = ALIGN_UP(header.SizeOfRawData, nt_headers.OptionalHeader.SectionAlignment);
			else
				//а иначе он равен ее виртуальному размеру,
				//выровненному на границу SectionAlignment
				virtual_size_aligned = ALIGN_UP(header.Misc.VirtualSize, nt_headers.OptionalHeader.SectionAlignment);
			//Проверим, что виртуальное пространство секции не вылетает за пределы виртуального пространства всего PE-файла
			if (header.VirtualAddress + virtual_size_aligned > ALIGN_UP(nt_headers.OptionalHeader.SizeOfImage, nt_headers.OptionalHeader.SectionAlignment))
			{
				std::cout << "Incorrect section address or size" << std::endl;
				return 0;
			}
			//имя секции может иметь размер до 8 символов
			char name[9] = { 0 };
			memcpy(name, header.Name, 8);
			//выводим имя секции
			std::cout << std::setw(20) << "Section: " << name << std::endl << "=======================" << std::endl;
			//ее размеры, адреса
			std::cout << std::setw(20) << "Virtual size:" << header.Misc.VirtualSize << std::endl;
			std::cout << std::setw(20) << "Raw size:" << header.SizeOfRawData << std::endl;
			std::cout << std::setw(20) << "Virtual address:" << header.VirtualAddress << std::endl;
			std::cout << std::setw(20) << "Raw address:" << header.PointerToRawData << std::endl;

			//и самые важные характеристики
			std::cout << std::setw(20) << "Characteristics: ";
			if (header.Characteristics & IMAGE_SCN_MEM_READ)
				std::cout << "R ";
			if (header.Characteristics & IMAGE_SCN_MEM_WRITE)
				std::cout << "W ";
			if (header.Characteristics & IMAGE_SCN_MEM_EXECUTE)
				std::cout << "X ";
			if (header.Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
				std::cout << "discardable ";
			if (header.Characteristics & IMAGE_SCN_MEM_SHARED)
				std::cout << "shared";

			std::cout << std::endl << std::endl;
		}

	}
}