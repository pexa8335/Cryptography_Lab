#include <iostream>
#include <cstdint>
#include <iomanip>
#include <string>
#include <vector>
#include <cstring>
#include <fstream>
#include <locale>
#include <chrono>
#include <filesystem>
#include <windows.h>
#ifdef _WIN32
#include <windows.h> // Cần cho SetConsoleOutputCP trên Windows
#endif

using namespace std;

// ======================= Cấu hình UTF-8 =======================
void setupUTF8() {
    #ifdef __linux__
    std::locale::global(std::locale("C.UTF-8"));
#endif

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
}
// ======================== Các hàm AES cơ bản ========================

// S-Box dùng trong SubBytes (được rút gọn)
const uint8_t SBox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};



// Rcon dùng trong KeyExpansion
const uint8_t Rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

// Nhân với 2 trong GF(2^8)
uint8_t xtime(uint8_t x) {
    return (x & 0x80) ? ((x << 1) ^ 0x1B) : (x << 1);
}

// Nhân hai số trong GF(2^8)
uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return p;
}

// Mở rộng khóa (Key Expansion)
void KeyExpansion(const uint8_t key[16], uint8_t roundKeys[176]) {
    memcpy(roundKeys, key, 16);
    for (int i = 16, rconIndex = 0; i < 176; i += 4) {
        uint8_t temp[4];
        memcpy(temp, roundKeys + i - 4, 4);
        if (i % 16 == 0) {
            uint8_t t = temp[0];
            temp[0] = SBox[temp[1]] ^ Rcon[rconIndex++];
            temp[1] = SBox[temp[2]];
            temp[2] = SBox[temp[3]];
            temp[3] = SBox[t];
        }
        for (int j = 0; j < 4; j++) {
            roundKeys[i + j] = roundKeys[i + j - 16] ^ temp[j];
        }
    }
}

// Các bước mã hóa AES
void SubBytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) state[i] = SBox[state[i]];
}

void ShiftRows(uint8_t state[16]) {
    uint8_t temp;
    temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;
    temp = state[2]; state[2] = state[10]; state[10] = temp;
    temp = state[6]; state[6] = state[14]; state[14] = temp;
    temp = state[3]; state[3] = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = temp;
}

void MixColumns(uint8_t state[16]) {
    uint8_t temp[16];
    for (int i = 0; i < 4; i++) {
        temp[i * 4] = gmul(2, state[i * 4]) ^ gmul(3, state[i * 4 + 1]) ^ state[i * 4 + 2] ^ state[i * 4 + 3];
        temp[i * 4 + 1] = state[i * 4] ^ gmul(2, state[i * 4 + 1]) ^ gmul(3, state[i * 4 + 2]) ^ state[i * 4 + 3];
        temp[i * 4 + 2] = state[i * 4] ^ state[i * 4 + 1] ^ gmul(2, state[i * 4 + 2]) ^ gmul(3, state[i * 4 + 3]);
        temp[i * 4 + 3] = gmul(3, state[i * 4]) ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ gmul(2, state[i * 4 + 3]);
    }
    memcpy(state, temp, 16);
}

void AddRoundKey(uint8_t state[16], const uint8_t roundKey[16]) {
    for (int i = 0; i < 16; i++) state[i] ^= roundKey[i];
}

void InvShiftRows(uint8_t state[16]) {
    uint8_t temp;

    // Hàng 1: dịch phải 1 byte
    temp = state[13];
    state[13] = state[9]; 
    state[9] = state[5]; 
    state[5] = state[1]; 
    state[1] = temp;

    // Hàng 2: dịch phải 2 byte
    temp = state[2]; 
    state[2] = state[10]; 
    state[10] = temp;
    temp = state[6]; 
    state[6] = state[14]; 
    state[14] = temp;

    // Hàng 3: dịch phải 3 byte
    temp = state[3]; 
    state[3] = state[7]; 
    state[7] = state[11]; 
    state[11] = state[15]; 
    state[15] = temp;
}

const uint8_t InvSBox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

void InvSubBytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] = InvSBox[state[i]];
    }
}

void InvMixColumns(uint8_t state[16]) {
    uint8_t temp[16];
    for (int i = 0; i < 4; i++) {
        temp[i * 4] = gmul(0x0E, state[i * 4]) ^ gmul(0x0B, state[i * 4 + 1]) ^ gmul(0x0D, state[i * 4 + 2]) ^ gmul(0x09, state[i * 4 + 3]);
        temp[i * 4 + 1] = gmul(0x09, state[i * 4]) ^ gmul(0x0E, state[i * 4 + 1]) ^ gmul(0x0B, state[i * 4 + 2]) ^ gmul(0x0D, state[i * 4 + 3]);
        temp[i * 4 + 2] = gmul(0x0D, state[i * 4]) ^ gmul(0x09, state[i * 4 + 1]) ^ gmul(0x0E, state[i * 4 + 2]) ^ gmul(0x0B, state[i * 4 + 3]);
        temp[i * 4 + 3] = gmul(0x0B, state[i * 4]) ^ gmul(0x0D, state[i * 4 + 1]) ^ gmul(0x09, state[i * 4 + 2]) ^ gmul(0x0E, state[i * 4 + 3]);
    }
    memcpy(state, temp, 16);
}

// Mã hóa một khối AES 128-bit
void AES_Encrypt_Block(const uint8_t plaintext[16], const uint8_t key[16], uint8_t ciphertext[16]) {
    uint8_t state[16], roundKeys[176];
    memcpy(state, plaintext, 16);
    KeyExpansion(key, roundKeys);

    // Vòng đầu tiên: AddRoundKey
    AddRoundKey(state, roundKeys);

    // 9 vòng chính
    for (int round = 1; round < 10; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + (round * 16));
    }

    // Vòng cuối cùng (không có MixColumns)
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + 160);

    memcpy(ciphertext, state, 16);
}


// ======================= AES Decryption =======================
void AES_Decrypt_Block(const uint8_t ciphertext[16], const uint8_t key[16], uint8_t plaintext[16]) {
    uint8_t state[16], roundKeys[176];
    memcpy(state, ciphertext, 16);
    KeyExpansion(key, roundKeys);

    // Vòng đầu tiên: AddRoundKey (từ khóa cuối cùng)
    AddRoundKey(state, roundKeys + 160);

    // 9 vòng chính
    for (int round = 9; round > 0; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys + (round * 16));
        InvMixColumns(state);
    }

    // Vòng cuối cùng (không có InvMixColumns)
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys);

    memcpy(plaintext, state, 16);
}

// Chuyển `string` UTF-8 thành `vector<uint8_t>`
vector<uint8_t> stringToBytes(const string& str) {
    return vector<uint8_t>(str.begin(), str.end());
}

// Chuyển `vector<uint8_t>` thành `string` UTF-8
string bytesToString(const vector<uint8_t>& bytes) {
    return string(bytes.begin(), bytes.end());
}

// ======================= Hỗ trợ xử lý chuỗi và byte =======================

// Chuyển chuỗi hex (32 ký tự) thành mảng 16 byte
void hexStringToBytes(const string& hex, uint8_t* bytes) {
    for (size_t i = 0; i < 16; i++) {
        bytes[i] = static_cast<uint8_t>(stoi(hex.substr(i * 2, 2), nullptr, 16));
    }
}

// In mảng byte dưới dạng hex
void printHex(const uint8_t* data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(data[i]) << "";
    }
    cout << endl;
}

void printHex(const string& label, const uint8_t* data, size_t length) {
    cout << label << ": ";
    for (size_t i = 0; i < length; i++) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(data[i]) << "";
    }
    cout << endl;
}

void applyPKCS7Padding(uint8_t* &data, size_t length, size_t& padded_length) {
    size_t padding_value = 16 - (length % 16);

    for (size_t i = length; i < length + padding_value; i++) {
        data[i] = static_cast<uint8_t>(padding_value);
    }
    
    padded_length = length + padding_value;
    // printHex(data, padded_length);
}


// Loại bỏ padding PKCS#7
size_t removePKCS7Padding(uint8_t* data, size_t length) {
    if (length == 0) {
        throw length_error("Lỗi: Dữ liệu rỗng khi xóa padding!");
    }

    uint8_t padding_value = data[length - 1];

    if (padding_value == 0 || padding_value > 16) {
        throw length_error("Lỗi: Padding không hợp lệ (giá trị sai)!");
    }

    for (size_t i = 0; i < padding_value; i++) {
        if (data[length - 1 - i] != padding_value) {
            throw length_error("Lỗi: Padding không hợp lệ (dữ liệu bị lỗi)!");
        }
    }

    return length - padding_value;
}


// Hàm mã hóa AES-CBC
void AES_CBC_Encrypt(const uint8_t* plaintext, size_t length, const uint8_t key[16], const uint8_t iv[16], uint8_t* ciphertext) {
    size_t padded_length = 0;
    uint8_t* padded_plaintext = new uint8_t[length + 16];
    memcpy(padded_plaintext, plaintext, length);
    applyPKCS7Padding(padded_plaintext, length, padded_length);

    uint8_t prev_block[16];
    memcpy(prev_block, iv, 16);

    for (size_t i = 0; i < padded_length; i += 16) {
        uint8_t block[16];
        uint8_t encrypted_block[16];

        memcpy(block, padded_plaintext + i, 16);
        for (int j = 0; j < 16; j++) block[j] ^= prev_block[j];

        AES_Encrypt_Block(block, key, encrypted_block);
        memcpy(ciphertext + i, encrypted_block, 16);
        memcpy(prev_block, encrypted_block, 16);
    }

    delete[] padded_plaintext;
}


// Hàm giải mã AES-CBC
void AES_CBC_Decrypt(const uint8_t* ciphertext, size_t length, const uint8_t key[16], const uint8_t iv[16], uint8_t* plaintext, size_t& plaintext_length) {

    uint8_t prev_block[16];
    memcpy(prev_block, iv, 16);

    for (size_t i = 0; i < length; i += 16) {
        uint8_t decrypted_block[16];
        AES_Decrypt_Block(ciphertext + i, key, decrypted_block);

        for (int j = 0; j < 16; j++) decrypted_block[j] ^= prev_block[j];

        memcpy(plaintext + i, decrypted_block, 16);
        memcpy(prev_block, ciphertext + i, 16);
    }

    plaintext_length = removePKCS7Padding(plaintext, length);
}

using namespace chrono;
#include <fstream>

void measure_execution_time(const string &filename, const uint8_t key[16], const uint8_t iv[16]) {
    // Extract file size from filename for display
    string file_size = filename.substr(filename.find_last_of("/") + 1);
    
    ifstream file(filename, ios::binary);
    if (!file) {
        cerr << "Không thể mở tệp: " << filename << endl;
        return;
    }

    vector<char> buffer((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    file.close();
    
    size_t plaintext_length = buffer.size();
    size_t padded_length = ((plaintext_length / 16) + 1) * 16;

    uint8_t* plaintext_data = new uint8_t[padded_length]();
    memcpy(plaintext_data, buffer.data(), plaintext_length);

    uint8_t* ciphertext = new uint8_t[padded_length]();
    uint8_t* decrypted = new uint8_t[padded_length]();
    size_t decrypted_length = 0;

    const int iterations = 10000;
    
    // Measure encryption time (10000 iterations)
    auto start_encrypt = high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
        AES_CBC_Encrypt(plaintext_data, plaintext_length, key, iv, ciphertext);
    }
    auto end_encrypt = high_resolution_clock::now();
    duration<double> encrypt_time = end_encrypt - start_encrypt;
    
    // Measure decryption time (10000 iterations)
    auto start_decrypt = high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
        AES_CBC_Decrypt(ciphertext, padded_length, key, iv, decrypted, decrypted_length);
    }
    auto end_decrypt = high_resolution_clock::now();
    duration<double> decrypt_time = end_decrypt - start_decrypt;
    
    // Print results clearly
    cout << file_size << " - Mã hóa (" << iterations << " lần): " 
         << fixed << setprecision(6) << encrypt_time.count() << " giây" << endl;
    cout << file_size << " - Giải mã (" << iterations << " lần): " 
         << fixed << setprecision(6) << decrypt_time.count() << " giây" << endl;

    delete[] plaintext_data;
    delete[] ciphertext;
    delete[] decrypted;
}


// ======================= Main - Chương trình chính =======================
int main() {

    setupUTF8(); // Cấu hình UTF-8 cho Windows

    cout << "Nhập khóa (32 ký tự hex liên tục): ";
    string key_input, iv_input;
    cin >> key_input;
    cout << "Nhập IV (32 ký tự hex liên tục): ";
    cin >> iv_input;

    uint8_t key[16], iv[16];
    hexStringToBytes(key_input, key);
    hexStringToBytes(iv_input, iv);

    vector<string> file_paths = {
        "test_inputs/input_1KB.bin",
        "test_inputs/input_10KB.bin",
        "test_inputs/input_50KB.bin",
        "test_inputs/input_100KB.bin",
        "test_inputs/input_500KB.bin",
        "test_inputs/input_1024KB.bin",
        "test_inputs/input_2048KB.bin",
        "test_inputs/input_5120KB.bin"
    };

    cout << "====== Thời gian xử lý các file (10000 lần) ======" << endl;
    for (const auto &file : file_paths) {
        measure_execution_time(file, key, iv);
    }
    cout << "=================================================" << endl;
    // Nhập plaintext (Unicode)
    cout << "Nhập plaintext: ";
    cin.ignore();
    string plaintext;
    getline(cin, plaintext);

    // Chuyển `string` thành `vector<uint8_t>`
    vector<uint8_t> plaintext_bytes = stringToBytes(plaintext);
    size_t plaintext_length = plaintext_bytes.size();
    size_t padded_length = ((plaintext_length / 16) + 1) * 16;

    uint8_t* plaintext_data = new uint8_t[padded_length]();
    memcpy(plaintext_data, plaintext_bytes.data(), plaintext_length);

    uint8_t* ciphertext = new uint8_t[padded_length]();
    AES_CBC_Encrypt(plaintext_data, plaintext_length, key, iv, ciphertext);

    cout << "Ciphertext: ";
    printHex(ciphertext, padded_length);

    // Giải mã
    uint8_t* decrypted_text = new uint8_t[padded_length]();
    size_t decrypted_length = 0;
    AES_CBC_Decrypt(ciphertext, padded_length, key, iv, decrypted_text, decrypted_length);

    // Chuyển kết quả giải mã từ `vector<uint8_t>` thành `string`
    vector<uint8_t> decrypted_bytes(decrypted_text, decrypted_text + decrypted_length);
    string decrypted_str = bytesToString(decrypted_bytes);

    cout << "Decrypted text: " << decrypted_str << endl;


    delete[] plaintext_data;
    delete[] ciphertext;
    delete[] decrypted_text;

    return 0;
}