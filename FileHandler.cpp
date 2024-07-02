#include "FileHandler.h"
#include <zlib.h>




// check if the file  exists
bool File::fileExist(std::string fileName) {
    std::ifstream file(fileName);
    return file.good();
}


void File::crateMeFile(std::string name, std::string uid, std::string key) {
    std::ofstream file(FILEME); // create file object and open the file
    if (file.is_open()) { // check if file was successfully opened
        file << name << '\n' << uid << '\n' << key << '\n';
        file.close(); // close the file
    }
    else
        std::cerr << "Error opening file!" << std::endl;
}



std::vector<std::string> File::read_file(const std::string& filename) {
    std::ifstream infile(filename);
    // check if the file was opened successfully
    if (!infile.is_open()) 
        return {};
    std::vector<std::string> lines;
    for (int i = 0; i < 3; ++i) {
        std::string line;
        if (std::getline(infile, line)) {
            lines.push_back(line);
        }
    }
    // check if there was an error while reading the file
    if (infile.fail()) 
        return {};
    // close the file
    infile.close();
    return lines;
}



std::vector<uint8_t> File::file_open(std::string file_name){
    std::ifstream input(file_name, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Error opening input file");
    }
    // Read the input file into a vector
    std::vector<uint8_t> input_data((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    input.close();
    return input_data;
}



unsigned char* File::remove_path(std::string filepath) {
    // Find the index of the last forward slash in the string
    unsigned char newch[NAMESIZE] = "";

    std::size_t last_slash_index = filepath.find_last_of('\\');
    if (last_slash_index == std::string::npos)
        std::memcpy(&newch[0], &filepath[0], filepath.length());
    else
        // Extract the substring after the last forward slash
        filepath = filepath.substr(last_slash_index + 1);
    std::memcpy(&newch[0], &filepath[0], filepath.length());
    return newch;
}



uint32_t File::crc32File(const char* file_path) {
    FILE* fp = fopen(file_path, "rb");
    if (!fp) return 0;

    uint32_t crc = 0xFFFFFFFFu;
    uint8_t buffer[1024];
    size_t bytes_read = 0;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0)
        for (size_t i = 0; i < bytes_read; ++i) {
            crc ^= buffer[i];
            for (int j = 0; j < 8; ++j) 
                crc = (crc >> 1) ^ ((crc & 1) * CRC32_POLY);
        }
    fclose(fp);
    return ~crc;
}



std::string File::getId() {
    return read_file(FILEME)[1];
}

std::string File::getServerConnData() {
    return read_file(FILETRANSFER)[0];
}
unsigned char* File::getUserName() {
    std::string username = (read_file(FILETRANSFER)[1]);
    unsigned char payloadchar[NAMESIZE] = "";
    std::memcpy(&payloadchar[0], &username[0], username.length());
    return payloadchar;
}

unsigned char* File::getUserNameM() {
    std::string username = (read_file(FILEME)[0]);
    unsigned char payloadchar[NAMESIZE] = "";
    std::memcpy(&payloadchar[0], &username[0], username.length());
    return payloadchar;
}

unsigned char* File::getFileName() {
    std::string filename = (read_file(FILETRANSFER)[2]);
    unsigned char payloadchar[NAMESIZE] = "";
    std::memcpy(&payloadchar[0], &filename[0], filename.length());
    return payloadchar;
}



std::string Hex::stringToHex(const uint8_t* first, const uint8_t* last, bool use_uppercase, bool insert_spaces)
{
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    if (use_uppercase)
        ss << std::uppercase;
    while (first != last)
    {
        ss << std::setw(2) << static_cast<int>(*first++);
        if (insert_spaces && (first != last)) {
            ss << " ";
        }
    }
    return ss.str();
}
std::vector<uint8_t> Hex::hexToBytes(const std::string& hex_string) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex_string.length(); i += 2) {
        std::string byte_string = hex_string.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byte_string, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}


