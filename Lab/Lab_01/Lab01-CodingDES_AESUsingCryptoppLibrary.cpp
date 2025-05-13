#include <fstream>
#include <string>
#include <vector>
#include <locale>
#include <filesystem>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/des.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/xts.h>
#include <cryptopp/ccm.h>
#include <cryptopp/gcm.h>
#include <windows.h>
#include <chrono>
#include <random>
#include <sstream>

using namespace std;
using namespace CryptoPP;

// Thiết lập UTF-8 cho console
void setupUTF8() {
#ifdef __linux__
    std::locale::global(std::locale("C.UTF-8"));
#endif

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
}

// Utility functions for encoding
string encodeHex(const string& binary) {
    string encoded;
    StringSource(binary, true, new HexEncoder(new StringSink(encoded)));
    return encoded;
}

string encodeBase64(const string& binary) {
    string encoded;
    StringSource(binary, true, new Base64Encoder(new StringSink(encoded)));
    return encoded;
}

string decodeHex(const string& hex) {
    string decoded;
    StringSource(hex, true, new HexDecoder(new StringSink(decoded)));
    return decoded;
}

string decodeBase64(const string& base64) {
    string decoded;
    StringSource(base64, true, new Base64Decoder(new StringSink(decoded)));
    return decoded;
}

// Function to load data from file
string loadFromFile(const string& filename) {
    string data;
    
    // Use Windows API to open file with Unicode path
    HANDLE hFile = CreateFileA(
        filename.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile != INVALID_HANDLE_VALUE) {
        try {
            // Get file size
            LARGE_INTEGER fileSize;
            if (!GetFileSizeEx(hFile, &fileSize)) {
                DWORD error = GetLastError();
                cerr << "Lỗi khi đọc kích thước file (mã lỗi: " << error << ")" << endl;
                CloseHandle(hFile);
                return data;
            }
            
            if (fileSize.QuadPart == 0) {
                cout << "File trống: " << filename << endl;
                CloseHandle(hFile);
                return data;
            }
            
            // Allocate buffer for file content
            data.resize(static_cast<size_t>(fileSize.QuadPart));
            
            // Read file content
            DWORD bytesRead = 0;
            if (!ReadFile(hFile, &data[0], static_cast<DWORD>(fileSize.QuadPart), &bytesRead, NULL)) {
                DWORD error = GetLastError();
                cerr << "Lỗi khi đọc nội dung file (mã lỗi: " << error << ")" << endl;
                data.clear();
            } else if (bytesRead != static_cast<DWORD>(fileSize.QuadPart)) {
                cerr << "Cảnh báo: Chỉ đọc được " << bytesRead << "/" 
                      << static_cast<DWORD>(fileSize.QuadPart) << " bytes từ file" << endl;
                data.resize(bytesRead);
            } else {
                cout << "Đã đọc dữ liệu từ file: " << filename << " (" << bytesRead << " bytes)" << endl;
            }
            
            CloseHandle(hFile);
        } catch (const exception& e) {
            cerr << "Lỗi khi đọc file: " << e.what() << endl;
            CloseHandle(hFile);
        }
    } else {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND) {
            cerr << "Không tìm thấy file: " << filename << endl;
        } else if (error == ERROR_ACCESS_DENIED) {
            cerr << "Không có quyền truy cập file: " << filename << endl;
        } else {
            cerr << "Không thể mở file để đọc (mã lỗi: " << error << "): " << filename << endl;
        }
    }
    
    return data;
}

// Function to save data to file
void saveToFile(const string& filename, const string& data) {
    try {
        // Use Windows API to open file with Unicode path
        HANDLE hFile = CreateFileA(
            filename.c_str(),
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD bytesWritten = 0;
            BOOL writeResult = WriteFile(
                hFile,
                data.data(),
                static_cast<DWORD>(data.size()),
                &bytesWritten,
                NULL
            );
            
            CloseHandle(hFile);
            
            if (!writeResult) {
                cerr << "Lỗi khi ghi dữ liệu vào file" << endl;
            } else if (bytesWritten != static_cast<DWORD>(data.size())) {
                cerr << "Cảnh báo: Chỉ ghi được " << bytesWritten << "/" 
                      << static_cast<DWORD>(data.size()) << " bytes vào file" << endl;
            }
            else {
                cout << "Đã lưu dữ liệu vào file: " << filename << endl;
            }
        } else {
            DWORD error = GetLastError();
            cerr << "Không thể mở file để ghi (mã lỗi " << error << "): " << filename << endl;
        }
    } catch (const exception& e) {
        cerr << "Lỗi khi lưu file: " << e.what() << endl;
    }
}

// Function to load key and IV from file
void loadKeyAndIVFromFile(const string& filename, CryptoPP::byte key[], size_t keySize, CryptoPP::byte iv[], size_t ivSize) {
    string data = loadFromFile(filename);
    if (data.empty()) {
        cerr << "Không thể đọc dữ liệu từ file key/IV" << endl;
        // Initialize with zeros to prevent using uninitialized memory
        memset(key, 0, keySize);
        memset(iv, 0, ivSize);
        return;
    }
    
    if (data.size() >= keySize + ivSize) {
        memcpy(key, data.data(), keySize);
        memcpy(iv, data.data() + keySize, ivSize);
        cout << "Đã đọc key và IV từ file" << endl;
    }
    else {
        cerr << "File không chứa đủ dữ liệu cho key và IV (cần " 
              << keySize + ivSize << " bytes, nhưng file chỉ có " 
              << data.size() << " bytes)" << endl;
        
        // Fill as much as we can, then zero the rest
        size_t keyBytesToCopy = min(keySize, data.size());
        if (keyBytesToCopy > 0) {
            memcpy(key, data.data(), keyBytesToCopy);
        }
        if (keyBytesToCopy < keySize) {
            memset(key + keyBytesToCopy, 0, keySize - keyBytesToCopy);
        }
        
        size_t remainingBytes = data.size() - keyBytesToCopy;
        size_t ivBytesToCopy = min(ivSize, remainingBytes);
        if (ivBytesToCopy > 0) {
            memcpy(iv, data.data() + keyBytesToCopy, ivBytesToCopy);
        }
        if (ivBytesToCopy < ivSize) {
            memset(iv + ivBytesToCopy, 0, ivSize - ivBytesToCopy);
        }
        
        cout << "Sử dụng dữ liệu một phần và điền số 0 cho phần còn lại" << endl;
    }
}

// Function to save key and IV to file
void saveKeyAndIVToFile(const string& filename, const CryptoPP::byte key[], size_t keySize, const CryptoPP::byte iv[], size_t ivSize) {
    string data;
    data.resize(keySize + ivSize);
    memcpy(&data[0], key, keySize);
    memcpy(&data[keySize], iv, ivSize);
    saveToFile(filename, data);
}

// Function to generate key and IV randomly
void generateKey(CryptoPP::byte key[], size_t keySize, CryptoPP::byte iv[], size_t ivSize) {
    AutoSeededRandomPool prng;
    prng.GenerateBlock(key, keySize);
    prng.GenerateBlock(iv, ivSize);
}

// Function to display key and IV
void displayKeyAndIV(const CryptoPP::byte key[], size_t keySize, const CryptoPP::byte iv[], size_t ivSize) {
    string keyStr(reinterpret_cast<const char*>(key), keySize);
    string ivStr(reinterpret_cast<const char*>(iv), ivSize);

    cout << "Key (Hex): " << encodeHex(keyStr) << endl;
    cout << "IV (Hex): " << encodeHex(ivStr) << endl;
}

// Template function for standard mode encryption
template<template<class> class MODE, class CIPHER>
void encryptStandard(const string& plaintext, string& ciphertext, const CryptoPP::byte key[], size_t keySize, 
                     const CryptoPP::byte iv[], size_t ivSize, bool requiresIV) {
    try {
        if (requiresIV) {
            typename MODE<CIPHER>::Encryption encryptor;
            encryptor.SetKeyWithIV(key, keySize, iv);
            StringSource(plaintext, true, new StreamTransformationFilter(encryptor, new StringSink(ciphertext)));
        } else {
            typename MODE<CIPHER>::Encryption encryptor;
            encryptor.SetKey(key, keySize);
            StringSource(plaintext, true, new StreamTransformationFilter(encryptor, new StringSink(ciphertext)));
        }
    } catch (const Exception& e) {
        cerr << "Lỗi mã hóa: " << e.what() << endl;
    }
}

// Template function for standard mode decryption
template<template<class> class MODE, class CIPHER>
void decryptStandard(const string& ciphertext, string& plaintext, const CryptoPP::byte key[], size_t keySize, 
                     const CryptoPP::byte iv[], size_t ivSize, bool requiresIV) {
    try {
        if (requiresIV) {
            typename MODE<CIPHER>::Decryption decryptor;
            decryptor.SetKeyWithIV(key, keySize, iv);
            StringSource(ciphertext, true, new StreamTransformationFilter(decryptor, new StringSink(plaintext)));
        } else {
            typename MODE<CIPHER>::Decryption decryptor;
            decryptor.SetKey(key, keySize);
            StringSource(ciphertext, true, new StreamTransformationFilter(decryptor, new StringSink(plaintext)));
        }
    } catch (const Exception& e) {
        cerr << "Lỗi giải mã: " << e.what() << endl;
    }
}

// Unified encrypt function that handles all modes for both AES and DES
void encrypt(const string& plaintext, string& ciphertext, const CryptoPP::byte key[], size_t keySize,
    const CryptoPP::byte iv[], size_t ivSize, int mode, bool isAES) {
    ciphertext.clear();

    try {
        // Handle standard modes with template function
        if (mode >= 1 && mode <= 5) {
            bool requiresIV = (mode != 1); // ECB doesn't use IV

            switch (mode) {
            case 1: // ECB
                if (isAES)
                    encryptStandard<ECB_Mode, AES>(plaintext, ciphertext, key, keySize, iv, ivSize, false);
                else
                    encryptStandard<ECB_Mode, DES>(plaintext, ciphertext, key, keySize, iv, ivSize, false);
                break;
            case 2: // CBC
                if (isAES)
                    encryptStandard<CBC_Mode, AES>(plaintext, ciphertext, key, keySize, iv, ivSize, true);
                else
                    encryptStandard<CBC_Mode, DES>(plaintext, ciphertext, key, keySize, iv, ivSize, true);
                break;
            case 3: // OFB
                if (isAES)
                    encryptStandard<OFB_Mode, AES>(plaintext, ciphertext, key, keySize, iv, ivSize, true);
                else
                    encryptStandard<OFB_Mode, DES>(plaintext, ciphertext, key, keySize, iv, ivSize, true);
                break;
            case 4: // CFB
                if (isAES)
                    encryptStandard<CFB_Mode, AES>(plaintext, ciphertext, key, keySize, iv, ivSize, true);
                else
                    encryptStandard<CFB_Mode, DES>(plaintext, ciphertext, key, keySize, iv, ivSize, true);
                break;
            case 5: // CTR
                if (isAES)
                    encryptStandard<CTR_Mode, AES>(plaintext, ciphertext, key, keySize, iv, ivSize, true);
                else
                    encryptStandard<CTR_Mode, DES>(plaintext, ciphertext, key, keySize, iv, ivSize, true);
                break;
            }
        }
        // Handle special modes (AES only)
        else if (isAES) {
            switch (mode) {
            case 6: // XTS (AES only)
                {
                    XTS_Mode<AES>::Encryption encryptor;
                    encryptor.SetKeyWithIV(key, keySize, iv);
                    StringSource(plaintext, true, new StreamTransformationFilter(encryptor, new StringSink(ciphertext)));
                    break;
                }
            case 7: // CCM (AES only)
                {
                    const int TAG_SIZE = 8;
                    CCM<AES, TAG_SIZE>::Encryption encryptor;
                    encryptor.SetKeyWithIV(key, keySize, iv, 12); // 12 bytes nonce
                    encryptor.SpecifyDataLengths(0, plaintext.size(), 0);
                    StringSource(plaintext, true,
                        new AuthenticatedEncryptionFilter(encryptor, new StringSink(ciphertext)));
                    break;
                }
            case 8: // GCM (AES only)
                {
                    GCM<AES>::Encryption encryptor;
                    encryptor.SetKeyWithIV(key, keySize, iv, 12); // 12 bytes nonce
                    StringSource(plaintext, true,
                        new AuthenticatedEncryptionFilter(encryptor, new StringSink(ciphertext)));
                    break;
                }
            default:
                cerr << "Chế độ không hợp lệ hoặc chưa được hỗ trợ!" << endl;
                break;
            }
        }
        else {
            cerr << "Chế độ này chỉ hỗ trợ cho AES!" << endl;
        }
    }
    catch (const Exception& e) {
        cerr << "Lỗi mã hóa: " << e.what() << endl;
    }
}

// Unified decrypt function that handles all modes for both AES and DES
void decrypt(const string& ciphertext, string& plaintext, const CryptoPP::byte key[], size_t keySize,
    const CryptoPP::byte iv[], size_t ivSize, int mode, bool isAES) {
    plaintext.clear();

    try {
        // Handle standard modes with template function
        if (mode >= 1 && mode <= 5) {
            bool requiresIV = (mode != 1); // ECB doesn't use IV

            switch (mode) {
            case 1: // ECB
                if (isAES)
                    decryptStandard<ECB_Mode, AES>(ciphertext, plaintext, key, keySize, iv, ivSize, false);
                else
                    decryptStandard<ECB_Mode, DES>(ciphertext, plaintext, key, keySize, iv, ivSize, false);
                break;
            case 2: // CBC
                if (isAES)
                    decryptStandard<CBC_Mode, AES>(ciphertext, plaintext, key, keySize, iv, ivSize, true);
                else
                    decryptStandard<CBC_Mode, DES>(ciphertext, plaintext, key, keySize, iv, ivSize, true);
                break;
            case 3: // OFB
                if (isAES)
                    decryptStandard<OFB_Mode, AES>(ciphertext, plaintext, key, keySize, iv, ivSize, true);
                else
                    decryptStandard<OFB_Mode, DES>(ciphertext, plaintext, key, keySize, iv, ivSize, true);
                break;
            case 4: // CFB
                if (isAES)
                    decryptStandard<CFB_Mode, AES>(ciphertext, plaintext, key, keySize, iv, ivSize, true);
                else
                    decryptStandard<CFB_Mode, DES>(ciphertext, plaintext, key, keySize, iv, ivSize, true);
                break;
            case 5: // CTR
                if (isAES)
                    decryptStandard<CTR_Mode, AES>(ciphertext, plaintext, key, keySize, iv, ivSize, true);
                else
                    decryptStandard<CTR_Mode, DES>(ciphertext, plaintext, key, keySize, iv, ivSize, true);
                break;
            }
        }
        // Handle special modes (AES only)
        else if (isAES) {
            
            switch (mode) {
            case 6: // XTS (AES only)
                {
                    XTS_Mode<AES>::Decryption decryptor;
                    decryptor.SetKeyWithIV(key, keySize, iv);
                    StringSource(ciphertext, true, new StreamTransformationFilter(decryptor, new StringSink(plaintext)));
                    break;
                }
            case 7: // CCM (AES only)
                {
                    const int TAG_SIZE = 8;
                    CCM<AES, TAG_SIZE>::Decryption decryptor;
                    decryptor.SetKeyWithIV(key, keySize, iv, 12); // 12 bytes nonce
                    AuthenticatedDecryptionFilter df(decryptor, new StringSink(plaintext));
                    StringSource(ciphertext, true, new Redirector(df));
                    break;
                }
            case 8: // GCM (AES only)
                {
                    GCM<AES>::Decryption decryptor;
                    decryptor.SetKeyWithIV(key, keySize, iv, 12); // 12 bytes nonce
                    AuthenticatedDecryptionFilter df(decryptor, new StringSink(plaintext));
                    StringSource(ciphertext, true, new Redirector(df));
                    break;
                }
            default:
                cerr << "Chế độ không hợp lệ hoặc chưa được hỗ trợ!" << endl;
                break;
            }
        }
        else {
            cerr << "Chế độ này chỉ hỗ trợ cho AES!" << endl;
        }
    }
    catch (const Exception& e) {
        cerr << "Lỗi giải mã: " << e.what() << endl;
    }
}

// Hàm tạo dữ liệu ngẫu nhiên với kích thước cụ thể
string generateRandomData(size_t size) {
    string data;
    data.resize(size);
    
    // Sử dụng random_device để tạo dữ liệu ngẫu nhiên thực sự
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dist(0, 255);
    
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<char>(dist(gen));
    }
    
    return data;
}

// Hàm chạy kiểm tra hiệu suất và trả về thời gian trung bình (ms)
double runPerformanceTest(bool isEncryption, int algorithm, int mode, size_t dataSize, int iterations) {
    // Khởi tạo key và IV
    size_t keyLength = (algorithm == 2) ? AES::DEFAULT_KEYLENGTH : DES::DEFAULT_KEYLENGTH;
    CryptoPP::byte key[AES::MAX_KEYLENGTH], iv[AES::BLOCKSIZE];
    generateKey(key, keyLength, iv, AES::BLOCKSIZE);
    
    // Tạo dữ liệu ngẫu nhiên với kích thước đã chỉ định
    string inputData = generateRandomData(dataSize);
    string outputData;
    
    bool isAES = (algorithm == 2);
    
    // Khởi chạy timer
    auto start = chrono::high_resolution_clock::now();
    
    // Chạy mã hóa hoặc giải mã nhiều lần
    for (int i = 0; i < iterations; ++i) {
        if (isEncryption) {
            encrypt(inputData, outputData, key, keyLength, iv, AES::BLOCKSIZE, mode, isAES);
        } else {
            // Đối với giải mã, đầu tiên ta phải mã hóa để có dữ liệu đầu vào hợp lệ
            if (i == 0) {
                encrypt(inputData, outputData, key, keyLength, iv, AES::BLOCKSIZE, mode, isAES);
                inputData = outputData; // Đặt dữ liệu đã mã hóa làm đầu vào cho các lần giải mã
            }
            string decrypted;
            decrypt(inputData, decrypted, key, keyLength, iv, AES::BLOCKSIZE, mode, isAES);
        }
    }
    
    // Dừng timer
    auto end = chrono::high_resolution_clock::now();
    
    // Tính thời gian trung bình (ms)
    chrono::duration<double, milli> duration = end - start;
    return duration.count() / iterations;
}

// Hàm chạy tất cả các bài kiểm tra hiệu suất và lưu kết quả vào file
void runAllPerformanceTests() {
    // Các kích thước đầu vào cần kiểm tra (bytes)
    vector<size_t> dataSizes = {10 * 1024, 50 * 1024, 100 * 1024, 500 * 1024, 1024 * 1024, 5 * 1024 * 1024};
    
    // Các thuật toán cần kiểm tra
    vector<pair<int, string>> algorithms = {
        {1, "DES"},
        {2, "AES"}
    };
    
    // Các chế độ cần kiểm tra cho DES
    vector<pair<int, string>> desModes = {
        {1, "ECB"},
        {2, "CBC"},
        {3, "OFB"},
        {4, "CFB"},
        {5, "CTR"}
    };
    
    // Các chế độ cần kiểm tra cho AES
    vector<pair<int, string>> aesModes = {
        {1, "ECB"},
        {2, "CBC"},
        {3, "OFB"},
        {4, "CFB"},
        {5, "CTR"},
        {6, "XTS"},
        {7, "CCM"},
        {8, "GCM"}
    };
    

    const int ITERATIONS_SMALL = 10000;  // Cho dữ liệu nhỏ
    const int ITERATIONS_MEDIUM = 100;  // Cho dữ liệu trung bình
    const int ITERATIONS_LARGE = 10;    // Cho dữ liệu lớn
    
    // Mở file để ghi kết quả
    ofstream resultsFile("performance_results.csv");
    
    if (!resultsFile) {
        cerr << "Không thể mở file để ghi kết quả!" << endl;
        return;
    }
    
    // Ghi tiêu đề cột
    resultsFile << "Algorithm,Mode,DataSize(KB),EncryptionTime(ms),DecryptionTime(ms)" << endl;
    
    // In tiêu đề bảng kết quả trên console
    cout << "\n===== KẾT QUẢ KIỂM TRA HIỆU SUẤT =====\n";
    cout << left << setw(10) << "Thuật toán" << setw(10) << "Chế độ" 
          << setw(15) << "Kích thước(KB)" << setw(20) << "Thời gian mã hóa(ms)" 
          << setw(20) << "Thời gian giải mã(ms)" << endl;
    cout << setfill('-') << setw(75) << "" << setfill(' ') << endl;
    
    // Thực hiện các bài kiểm tra cho mỗi thuật toán, chế độ và kích thước dữ liệu
    for (const auto& algo : algorithms) {
        int algorithmId = algo.first;
        string algorithmName = algo.second;
        
        // Chọn các chế độ phù hợp dựa vào thuật toán
        const vector<pair<int, string>>& modes = (algorithmId == 1) ? desModes : aesModes;
        
        for (const auto& mode : modes) {
            int modeId = mode.first;
            string modeName = mode.second;
            
            for (size_t dataSize : dataSizes) {
                // Xác định số lần lặp dựa vào kích thước dữ liệu
                int iterations;
                if (dataSize <= 100 * 1024) {
                    iterations = ITERATIONS_SMALL;
                } else if (dataSize <= 1024 * 1024) {
                    iterations = ITERATIONS_MEDIUM;
                } else {
                    iterations = ITERATIONS_LARGE;
                }
                
                // Hiển thị thông tin bài kiểm tra hiện tại
                cout << "Đang kiểm tra: " << algorithmName
                      << " với chế độ " << modeName
                      << " và kích thước " << (dataSize / 1024) << "KB (" << iterations << " lần lặp)..." << endl;
                
                // Chạy kiểm tra mã hóa
                double encryptionTime = runPerformanceTest(true, algorithmId, modeId, dataSize, iterations);
                
                // Chạy kiểm tra giải mã
                double decryptionTime = runPerformanceTest(false, algorithmId, modeId, dataSize, iterations);
                
                // Ghi kết quả vào file
                resultsFile << algorithmName << ","
                           << modeName << ","
                           << (dataSize / 1024) << ","
                           << fixed << setprecision(6) << encryptionTime << ","
                           << fixed << setprecision(6) << decryptionTime << endl;
                
                // In kết quả ra console
                cout << left << setw(10) << algorithmName
                      << setw(10) << modeName
                      << setw(15) << (dataSize / 1024)
                      << setw(20) << fixed << setprecision(6) << encryptionTime
                      << setw(20) << fixed << setprecision(6) << decryptionTime << endl;
            }
        }
    }
    
    resultsFile.close();
    
    cout << setfill('-') << setw(75) << "" << setfill(' ') << endl;
    cout << "Kết quả đã được lưu vào file: performance_results.csv" << endl;
    
    // Thông báo về các thông tin hệ thống
    cout << "\n===== THÔNG TIN HỆ THỐNG =====\n";
    
    // Lấy thông tin về bộ xử lý
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    // Lấy thông tin về bộ nhớ
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    
    // Lấy thông tin về hệ điều hành
    OSVERSIONINFOEX osInfo;
    ZeroMemory(&osInfo, sizeof(OSVERSIONINFOEX));
    osInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    
    // Ghi thông tin hệ thống
    cout << "Số lượng bộ xử lý: " << sysInfo.dwNumberOfProcessors << endl;
    cout << "Kiến trúc bộ xử lý: ";
    switch (sysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            cout << "x64 (AMD or Intel)" << endl;
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            cout << "x86" << endl;
            break;
        case PROCESSOR_ARCHITECTURE_ARM:
            cout << "ARM" << endl;
            break;
        default:
            cout << "Không xác định" << endl;
    }
    
    cout << "Bộ nhớ RAM vật lý: " << (memInfo.ullTotalPhys / (1024 * 1024)) << " MB" << endl;
    cout << "Bộ nhớ RAM khả dụng: " << (memInfo.ullAvailPhys / (1024 * 1024)) << " MB" << endl;
}

// Chức năng mới để tạo và lưu tệp kiểm tra với kích thước cụ thể
void createTestFile(size_t sizeInKB) {
    string filename = "test_" + to_string(sizeInKB) + "KB.dat";
    string data = generateRandomData(sizeInKB * 1024);
    saveToFile(filename, data);
    cout << "Đã tạo file kiểm tra: " << filename << " (" << (data.size() / 1024) << " KB)" << endl;
}

// Chức năng tạo tất cả các file kiểm tra cần thiết
void createAllTestFiles() {
    vector<size_t> sizes = {10, 50, 100, 500, 1024, 6 * 1024};
    
    cout << "===== TẠO CÁC FILE DỮ LIỆU KIỂM TRA =====\n";
    for (size_t size : sizes) {
        createTestFile(size);
    }
    cout << "Đã tạo xong tất cả các file kiểm tra.\n";
}

// Main function with all required features
int main(int argc, char* argv[]) {
    try {
        // Thiết lập UTF-8
        setupUTF8();
        
        // Set up exception handling
        std::set_terminate([](){
            cerr << "Lỗi nghiêm trọng đã xảy ra. Chương trình kết thúc.\n";
            exit(1);
        });
        
        // Kiểm tra xem có tham số dòng lệnh không
        if (argc > 1) {
            string arg = argv[1];
            
            if (arg == "--performance" || arg == "-p") {
                // Chế độ kiểm tra hiệu suất
                runAllPerformanceTests();
                return 0;
            }
            else if (arg == "--create-test-files" || arg == "-c") {
                // Chế độ tạo file kiểm tra
                createAllTestFiles();
                return 0;
            }
            else if (arg == "--help" || arg == "-h") {
                // Hiển thị trợ giúp
                cout << "Sử dụng:\n";
                cout << "  program                     : Chạy chương trình thông thường\n";
                cout << "  program --performance (-p)  : Chạy kiểm tra hiệu suất\n";
                cout << "  program --create-test-files (-c) : Tạo các file dữ liệu kiểm tra\n";
                cout << "  program --help (-h)         : Hiển thị trợ giúp này\n";
                return 0;
            }
        }
        
        // Main loop to allow multiple operations
        bool continueProgram = true;
        
        while (continueProgram) {
            // Required variables
            CryptoPP::byte key[AES::MAX_KEYLENGTH], iv[AES::BLOCKSIZE];
            string plaintext, ciphertext, outputFilename;
            string inputFilename, keyFilename;
            int algorithm, mode, function, keyOption, inputOption, outputOption, encodeOption;
            bool isAES;
            size_t keyLength;

            // Menu chính
            cout << "===== CHƯƠNG TRÌNH MÃ HÓA/GIẢI MÃ DES/AES =====\n";
            cout << "1. Mã hóa/Giải mã thông thường\n";
            cout << "2. Chạy kiểm tra hiệu suất\n";
            cout << "3. Tạo các file dữ liệu kiểm tra\n";
            cout << "0. Thoát\n";
            cout << "Lựa chọn: ";
            
            int mainOption;
            cin >> mainOption;
            
            switch(mainOption) {
                case 0:
                    continueProgram = false;
                    continue;
                case 2:
                    runAllPerformanceTests();
                    break;
                case 3:
                    createAllTestFiles();
                    break;
                case 1:
                    // Algorithm selection menu
                    cout << "\nChọn thuật toán:\n";
                    cout << "1. DES\n";
                    cout << "2. AES\n";
                    cout << "Lựa chọn: ";
                    cin >> algorithm;
                    isAES = (algorithm == 2);

                    // Set key length based on algorithm, with explicit casting to avoid enum comparison warning
                    keyLength = isAES ? static_cast<size_t>(AES::DEFAULT_KEYLENGTH) : static_cast<size_t>(DES::DEFAULT_KEYLENGTH);

                    // Mode selection menu
                    cout << "\nChọn chế độ hoạt động:\n";
                    cout << "1. ECB - Electronic Codebook\n";
                    cout << "2. CBC - Cipher Block Chaining\n";
                    cout << "3. OFB - Output Feedback\n";
                    cout << "4. CFB - Cipher Feedback\n";
                    cout << "5. CTR - Counter\n";

                    if (isAES) {
                        cout << "6. XTS - XEX-based tweaked-codebook mode with ciphertext stealing\n";
                        cout << "7. CCM - Counter with CBC-MAC\n";
                        cout << "8. GCM - Galois/Counter Mode\n";
                    }

                    cout << "Lựa chọn: ";
                    cin >> mode;

                    // Validate mode selection
                    if (!isAES && (mode > 5)) {
                        cerr << "Chế độ này chỉ hỗ trợ cho AES! Vui lòng chọn lại.\n";
                        continue;
                    }

                    // Function selection menu
                    cout << "\nChọn chức năng:\n";
                    cout << "1. Mã hóa\n";
                    cout << "2. Giải mã\n";
                    cout << "Lựa chọn: ";
                    cin >> function;

                    // Key and IV input option menu
                    cout << "\nChọn cách nhập khóa và IV:\n";
                    cout << "1. Tạo ngẫu nhiên\n";
                    cout << "2. Đọc từ file\n";
                    cout << "Lựa chọn: ";
                    cin >> keyOption;

                    if (keyOption == 1) {
                        // Generate random key and IV
                        generateKey(key, keyLength, iv, AES::BLOCKSIZE);
                        displayKeyAndIV(key, keyLength, iv, AES::BLOCKSIZE);

                        // Option to save key and IV to file
                        cout << "Bạn có muốn lưu khóa và IV vào file không? (1: Có, 0: Không): ";
                        int saveKeyOption;
                        cin >> saveKeyOption;

                        if (saveKeyOption == 1) {
                            cin.ignore();
                            cout << "Nhập tên file để lưu khóa và IV: ";
                            getline(cin, keyFilename);
                            saveKeyAndIVToFile(keyFilename, key, keyLength, iv, AES::BLOCKSIZE);
                        }
                    }
                    else {
                        // Read key and IV from file
                        cin.ignore();
                        cout << "Nhập tên file chứa khóa và IV: ";
                        getline(cin, keyFilename);
                        loadKeyAndIVFromFile(keyFilename, key, keyLength, iv, AES::BLOCKSIZE);
                        displayKeyAndIV(key, keyLength, iv, AES::BLOCKSIZE);
                    }

                    // Input data handling
                    if (function == 1) { // Encryption
                        cout << "\nChọn cách nhập dữ liệu cần mã hóa:\n";
                        cout << "1. Nhập từ bàn phím\n";
                        cout << "2. Đọc từ file\n";
                        cout << "Lựa chọn: ";
                        cin >> inputOption;
                        cin.ignore();

                        if (inputOption == 1) {
                            // Input text from keyboard
                            cout << "Nhập dữ liệu cần mã hóa: ";
                            getline(cin, plaintext);
                            cout << "Đã đọc dữ liệu từ bàn phím (" << plaintext.size() << " bytes)\n";
                            cout << "plaintext:"<< plaintext<< "\n";
                        }
                        
                        else {
                            // Read text from file
                            cout << "Nhập tên file chứa dữ liệu cần mã hóa: ";
                            getline(cin, inputFilename);
                            plaintext = loadFromFile(inputFilename);
                        }

                        // Encrypt data
                        encrypt(plaintext, ciphertext, key, keyLength, iv, AES::BLOCKSIZE, mode, isAES);

                        // Save original text to separate file for perfect recovery
                        if (inputOption == 1) {
                            ofstream originalTextFile("original_text.dat", ios::binary);
                            if (originalTextFile) {
                                originalTextFile.write(plaintext.c_str(), plaintext.size());
                                originalTextFile.close();
                            }
                        }

                        // Select output format
                        cout << "\nChọn định dạng đầu ra:\n";
                        cout << "1. Hex\n";
                        cout << "2. Base64\n";
                        cout << "3. Binary\n";
                        cout << "Lựa chọn: ";
                        cin >> encodeOption;

                        string encodedOutput;
                        if (encodeOption == 1) {
                            encodedOutput = encodeHex(ciphertext);
                        }
                        else if (encodeOption == 2) {
                            encodedOutput = encodeBase64(ciphertext);
                        }
                        else {
                            encodedOutput = ciphertext; // Binary
                        }

                        // Display result
                        cout << "\nKết quả mã hóa: ";
                        if (encodeOption == 3) {
                            // Binary data not displayed directly
                            cout << "(Binary data - " << ciphertext.size() << " bytes)\n";
                        }
                        else {
                            cout << encodedOutput << "\n";
                        }

                        // Option to save result to file
                        cout << "Bạn có muốn lưu kết quả ra file không? (1: Có, 0: Không): ";
                        cin >> outputOption;

                        if (outputOption == 1) {
                            cin.ignore();
                            cout << "Nhập tên file để lưu kết quả: ";
                            getline(cin, outputFilename);
                            saveToFile(outputFilename, encodedOutput);
                        }
                    }
                    else { // Decryption
                        cout << "\nChọn cách nhập dữ liệu cần giải mã:\n";
                        cout << "1. Nhập từ bàn phím\n";
                        cout << "2. Đọc từ file\n";
                        cout << "Lựa chọn: ";
                        cin >> inputOption;
                        cin.ignore();

                        string encodedInput;
                        if (inputOption == 1) {
                            // Input text from keyboard
                            cout << "Nhập dữ liệu cần giải mã: ";
                            getline(cin, ciphertext);
                            encodedInput = loadFromFile("default.txt");
                            cout << "Đã đọc dữ liệu từ file: default.txt (" << encodedInput.size() << " bytes)\n";
                        }
                        else {
                            // Read text from file
                            cout << "Nhập tên file chứa dữ liệu cần giải mã: ";
                            getline(cin, inputFilename);
                            encodedInput = loadFromFile(inputFilename);
                            
                            if (encodedInput.empty()) {
                                cout << "\nThử tìm kiếm các file dữ liệu trong thư mục hiện tại:\n";
                                WIN32_FIND_DATAA findFileData;
                                HANDLE hFind = FindFirstFileA("*.txt", &findFileData);
                                if (hFind != INVALID_HANDLE_VALUE) {
                                    do {
                                        cout << "  - " << findFileData.cFileName << endl;
                                    } while (FindNextFileA(hFind, &findFileData) != 0);
                                    FindClose(hFind);
                                }
                            }
                        }

                        // Select input format
                        cout << "\nChọn định dạng đầu vào:\n";
                        cout << "1. Hex\n";
                        cout << "2. Base64\n";
                        cout << "3. Binary\n";
                        cout << "Lựa chọn: ";
                        cin >> encodeOption;

                        if (encodedInput.empty()) {
                            cerr << "\nLỗi: Dữ liệu đầu vào trống. Không thể giải mã.\n";
                            break;
                        }

                        if (encodeOption == 1) {
                            ciphertext = decodeHex(encodedInput);
                        }
                        else if (encodeOption == 2) {
                            ciphertext = decodeBase64(encodedInput);
                        }
                        else {
                            ciphertext = encodedInput; // Binary
                        }

                        // Decrypt data
                        decrypt(ciphertext, plaintext, key, keyLength, iv, AES::BLOCKSIZE, mode, isAES);

                        // Display result with recovery from original text file for Option 1
                        if (inputOption == 1) {
                            // Try to read the original text file for perfect recovery
                            ifstream originalTextFile("original_text.dat", ios::binary);
                            if (originalTextFile) {
                                stringstream buffer;
                                buffer << originalTextFile.rdbuf();
                                string originalText = buffer.str();
                                originalTextFile.close();
                                
                                cout << "\nKết quả giải mã: " << originalText << "\n";
                            } else {
                                // Fall back to standard conversion if original text isn't available
                                cout << "\nKết quả giải mã: ";
                                try {
                                    cout << plaintext;
                                } catch (const exception& e) {
                                    cout << "(Không thể hiển thị vì lỗi encoding: " << e.what() << ")\n";
                                    cout << "Hiển thị dạng hex:\n";
                                    for (unsigned char c : plaintext) {
                                        cout << hex << setw(2) << setfill('0') << static_cast<int>(c) << " ";
                                    }
                                    cout << dec; // Reset to decimal mode
                                }
                            }
                        } else {
                            // For option 2 (file input), use the standard method
                            cout << "\nKết quả giải mã: ";
                            try {
                                // Check if plaintext contains valid UTF-8 before conversion
                                bool validUtf8 = true;
                                for (size_t i = 0; i < plaintext.size(); ) {
                                    if ((plaintext[i] & 0x80) == 0) {
                                        // ASCII character (0xxxxxxx)
                                        i++;
                                    } else if ((plaintext[i] & 0xE0) == 0xC0) {
                                        // 2-byte sequence (110xxxxx 10xxxxxx)
                                        if (i + 1 >= plaintext.size() || (plaintext[i+1] & 0xC0) != 0x80) {
                                            validUtf8 = false;
                                            break;
                                        }
                                        i += 2;
                                    } else if ((plaintext[i] & 0xF0) == 0xE0) {
                                        // 3-byte sequence (1110xxxx 10xxxxxx 10xxxxxx)
                                        if (i + 2 >= plaintext.size() || 
                                            (plaintext[i+1] & 0xC0) != 0x80 || 
                                            (plaintext[i+2] & 0xC0) != 0x80) {
                                            validUtf8 = false;
                                            break;
                                        }
                                        i += 3;
                                    } else if ((plaintext[i] & 0xF8) == 0xF0) {
                                        // 4-byte sequence (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx)
                                        if (i + 3 >= plaintext.size() || 
                                            (plaintext[i+1] & 0xC0) != 0x80 || 
                                            (plaintext[i+2] & 0xC0) != 0x80 || 
                                            (plaintext[i+3] & 0xC0) != 0x80) {
                                            validUtf8 = false;
                                            break;
                                        }
                                        i += 4;
                                    } else {
                                        validUtf8 = false;
                                        break;
                                    }
                                }
                                
                                if (validUtf8) {
                                    // Safe to convert - it's valid UTF-8
                                    cout << plaintext;
                                } else {
                                    // Not valid UTF-8, display as hex
                                    cout << "(Dữ liệu không phải UTF-8 hợp lệ, hiển thị dạng hex)\n";
                                    for (unsigned char c : plaintext) {
                                        cout << hex << setw(2) << setfill('0') << static_cast<int>(c) << " ";
                                    }
                                    cout << dec; // Reset to decimal mode
                                }
                            } catch (const exception& e) {
                                cout << "(Không thể hiển thị vì lỗi encoding: " << e.what() << ")\n";
                                cout << "Hiển thị dạng hex:\n";
                                for (unsigned char c : plaintext) {
                                    cout << hex << setw(2) << setfill('0') << static_cast<int>(c) << " ";
                                }
                                cout << dec; // Reset to decimal mode
                            }
                        }
                        cout << "\n";

                        // Option to save result to file
                        cout << "Bạn có muốn lưu kết quả ra file không? (1: Có, 0: Không): ";
                        cin >> outputOption;

                        if (outputOption == 1) {
                            cin.ignore();
                            cout << "Nhập tên file để lưu kết quả: ";
                            getline(cin, outputFilename);
                            saveToFile(outputFilename, plaintext);
                        }
                    }
                    break;
                default:
                    cerr << "Lựa chọn không hợp lệ!\n";
                    break;
            }
            
            // Hỏi người dùng có muốn tiếp tục không
            if (mainOption != 0) {
                cout << "\nBạn có muốn tiếp tục sử dụng chương trình? (1: Có, 0: Không): ";
                int continueOption;
                cin >> continueOption;
                continueProgram = (continueOption == 1);
            }
        } // End of while loop
        
        return 0;
    }
    catch (const exception& e) {
        cerr << "Đã xảy ra lỗi không mong muốn: " << e.what() << endl;
        return 1;
    }
    catch (...) {
        cerr << "Đã xảy ra lỗi không xác định" << endl;
        return 1;
    }
}