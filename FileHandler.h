#pragma once
#ifndef FILEHANDLER_H
#define FILEHANDLER_H


#include <iostream>
#include <string>

#include <fstream>
#include <vector>
#include <iostream>
#include <iomanip>


////////////////////////////
/////////defines////////////
///////////////////////////

#define FILEME "me.info"
#define FILETRANSFER "transfer.info"

#define NAMESIZE 255

constexpr uint32_t CRC32_POLY = 0xEDB88320u;


class File {
public:
	static unsigned char* remove_path(std::string);
	static void crateClientFiles(std::string, std::string);
	static bool fileExist(std::string);
	static void crateMeFile(std::string, std::string, std::string);
	static std::vector<std::string> read_file(const std::string&);
	static std::vector<uint8_t> file_open(std::string);

	static std::string getServerConnData();
	static unsigned char* getFileName();
	static unsigned char* getUserName();
	static unsigned char* getUserNameM();
	static std::string getId();

	static uint32_t crc32File(const char*);
};




class Hex{
public:
	static std::string stringToHex(const uint8_t*, const uint8_t*, bool use_uppercase = false, bool insert_spaces = false);
	static std::vector<uint8_t> hexToBytes(const std::string& hex_string);
};



/* FILEHANDLER_H */
#endif 