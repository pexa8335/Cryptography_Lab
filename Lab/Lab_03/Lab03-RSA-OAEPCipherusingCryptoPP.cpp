#include <iostream>
#include <fstream> // For file I/O
#include <string>
#include <vector>
#include <stdexcept>
#include <sstream>
#include <iomanip>   // For std::setprecision, std::fixed
#include <limits>    // For std::numeric_limits
#include <chrono>    // For timing
#include <numeric>   // For std::accumulate (optional, can do manual sum)

// Crypto++ Headers
#include <cryptopp/cryptlib.h>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>    // AutoSeededRandomPool, OS_GenerateRandomBlock
#include <cryptopp/rsa.h>      // RSAES_OAEP_SHA_Encryptor/Decryptor
#include <cryptopp/files.h>    // FileSource, FileSink
#include <cryptopp/hex.h>      // HexEncoder, HexDecoder
#include <cryptopp/base64.h>   // Base64Encoder, Base64Decoder
#include <cryptopp/asn.h>      // DER encoding/decoding
#include <cryptopp/secblock.h> // For SecByteBlock

using namespace CryptoPP;
using std::cerr;
using std::cout;
using std::cin;
using std::endl;
using std::string;
using std::vector;
using std::runtime_error;
using std::ifstream;
using std::ofstream;
using std::ios;
using std::fixed;
using std::setprecision;

// --- Helper Functions for Saving/Loading Keys (DER Format) ---
// (Giữ nguyên)
bool SavePublicKeyDER(const string& filename, const RSA::PublicKey& key) {
    try { FileSink file(filename.c_str()); key.DEREncodePublicKey(file); return true; }
    catch (const Exception& e) { cerr << "Error saving public key (DER): " << e.what() << endl; return false; }
}
bool SavePrivateKeyDER(const string& filename, const RSA::PrivateKey& key) {
    try { FileSink file(filename.c_str()); key.DEREncodePrivateKey(file); return true; }
    catch (const Exception& e) { cerr << "Error saving private key (DER): " << e.what() << endl; return false; }
}
bool LoadPublicKeyDER(const string& filename, RSA::PublicKey& key) {
    try {
        FileSource file(filename.c_str(), true); key.BERDecodePublicKey(file, false, file.MaxRetrievable());
        AutoSeededRandomPool rng; if (!key.Validate(rng, 3)) { cerr << "Public key validation failed." << endl; return false; } return true;
    } catch (const Exception& e) { cerr << "Error loading public key (DER): " << e.what() << endl; return false; }
}
bool LoadPrivateKeyDER(const string& filename, RSA::PrivateKey& key) {
    try {
        FileSource file(filename.c_str(), true); key.BERDecodePrivateKey(file, false, file.MaxRetrievable());
        AutoSeededRandomPool rng; if (!key.Validate(rng, 3)) { cerr << "Private key validation failed." << endl; return false; } return true;
    } catch (const Exception& e) { cerr << "Error loading private key (DER): " << e.what() << endl; return false; }
}


// --- Helper Functions for File I/O ---
// (Giữ nguyên)
bool ReadFile(const string& filename, string& data) {
    try {
        ifstream file(filename, ios::in | ios::binary); if (!file) { cerr << "Cannot open read file: " << filename << endl; return false; }
        file.seekg(0, ios::end); std::streamsize size = file.tellg(); file.seekg(0, ios::beg);
        if (size > 0) { vector<char> buffer(size); if (file.read(buffer.data(), size)) { data.assign(buffer.begin(), buffer.end()); return true; } else { cerr << "Error reading file: " << filename << endl; return false; } }
        else if (size == 0) { data = ""; return true; } else { cerr << "Error file size: " << filename << endl; return false; }
    } catch (const std::exception& e) { cerr << "Exception reading file " << filename << ": " << e.what() << endl; return false; }
}
bool WriteFile(const string& filename, const string& data) {
    try {
        ofstream file(filename, ios::out | ios::binary | ios::trunc); if (!file) { cerr << "Cannot open write file: " << filename << endl; return false; }
        file.write(data.data(), data.size()); return true;
    } catch (const std::exception& e) { cerr << "Exception writing file " << filename << ": " << e.what() << endl; return false; }
}
// Overload cho SecByteBlock để dễ dùng hơn trong generate sample
bool WriteFile(const string& filename, const SecByteBlock& data) {
    try {
        ofstream file(filename, ios::out | ios::binary | ios::trunc); if (!file) { cerr << "Cannot open write file: " << filename << endl; return false; }
        file.write(reinterpret_cast<const char*>(data.data()), data.size()); return true;
    } catch (const std::exception& e) { cerr << "Exception writing file " << filename << ": " << e.what() << endl; return false; }
}


// --- Utility to clear input buffer ---
// (Giữ nguyên)
void clear_cin_buffer() {
    cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

// --- Core Logic Functions ---

// 1. Xử lý Tạo khóa (Interactive)
// (Giữ nguyên)
void handle_key_generation_interactive() {
    string pubFile, privFile;
    cout << "Enter desired public key filename (e.g., public.der): "; getline(cin, pubFile);
    cout << "Enter desired private key filename (e.g., private.der): "; getline(cin, privFile);
    if (pubFile.empty() || privFile.empty()) { cerr << "Error: Key filenames cannot be empty." << endl; return; }
    cout << "Generating RSA key pair (3072 bits)..." << endl;
    AutoSeededRandomPool rng; RSA::PrivateKey rsaPrivate;
    try {
        rsaPrivate.GenerateRandomWithKeySize(rng, 3072); RSA::PublicKey rsaPublic(rsaPrivate);
        if (!rsaPrivate.Validate(rng, 3) || !rsaPublic.Validate(rng, 3)) throw runtime_error("Key validation failed.");
        if (!SavePublicKeyDER(pubFile, rsaPublic)) return; cout << "Public key saved to: " << pubFile << endl;
        if (!SavePrivateKeyDER(privFile, rsaPrivate)) return; cout << "Private key saved to: " << privFile << endl;
        cout << "Key generation successful." << endl;
    } catch (const CryptoPP::Exception& e) { cerr << "Crypto++ Exception during key gen: " << e.what() << endl; }
    catch (const std::exception& e) { cerr << "Standard Exception during key gen: " << e.what() << endl; }
}

// 2. Xử lý Mã hóa (Interactive)
// (Giữ nguyên)
void handle_encryption_interactive() {
    string keyFile, inFile, outFile, format_str; RSA::PublicKey publicKey;
    cout << "Enter public key filename (DER): "; getline(cin, keyFile); if (!LoadPublicKeyDER(keyFile, publicKey)) return;
    cout << "Enter input plaintext filename: "; getline(cin, inFile);
    cout << "Enter output ciphertext filename (or '-' for stdout): "; getline(cin, outFile);
    cout << "Enter output format (BIN, HEX, BASE64): "; getline(cin, format_str);
    for (char &c : format_str) { c = toupper(c); } if (format_str != "BIN" && format_str != "HEX" && format_str != "BASE64") { cerr << "Invalid format." << endl; return; }
    string plaintext; if (!ReadFile(inFile, plaintext)) return; cout << "Encrypting..." << endl;
    string ciphertext; AutoSeededRandomPool rng; RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    try { StringSource ss_plain(plaintext, true, new PK_EncryptorFilter(rng, encryptor, new StringSink(ciphertext))); }
    catch (const CryptoPP::Exception& e) { cerr << "Encryption failed: " << e.what() << ". Plaintext too long?" << endl; return; }
    cout << "Encryption successful. Outputting..." << endl;
    try {
        if (outFile == "-") {
            if (format_str == "BIN") { cout.write(ciphertext.data(), ciphertext.size()); }
            else if (format_str == "HEX") { StringSource(ciphertext, true, new HexEncoder(new FileSink(std::cout))); cout << endl; }
            else { StringSource(ciphertext, true, new Base64Encoder(new FileSink(std::cout), true)); cout << endl; }
        } else {
            if (format_str == "BIN") { if (!WriteFile(outFile, ciphertext)) return; }
            else { ofstream out_file(outFile); if (!out_file) { cerr << "Cannot open output file: " << outFile << endl; return; }
                   if (format_str == "HEX") { StringSource(ciphertext, true, new HexEncoder(new FileSink(out_file))); }
                   else { StringSource(ciphertext, true, new Base64Encoder(new FileSink(out_file), true)); } }
            cout << "Ciphertext saved to: " << outFile << endl;
        }
    } catch (const CryptoPP::Exception& e) { cerr << "Error writing output: " << e.what() << endl; }
}


// 3. Xử lý Giải mã (Interactive)
// (Giữ nguyên)
void handle_decryption_interactive() {
    string keyFile, inFile, outFile, format_str; RSA::PrivateKey privateKey;
    cout << "Enter private key filename (DER): "; getline(cin, keyFile); if (!LoadPrivateKeyDER(keyFile, privateKey)) return;
    cout << "Enter input ciphertext filename: "; getline(cin, inFile);
    cout << "Enter output recovered plaintext filename (or '-' for stdout): "; getline(cin, outFile);
    cout << "Enter input format (BIN, HEX, BASE64): "; getline(cin, format_str);
    for (char &c : format_str) { c = toupper(c); } if (format_str != "BIN" && format_str != "HEX" && format_str != "BASE64") { cerr << "Invalid format." << endl; return; }
    string input_data, ciphertext_raw; if (!ReadFile(inFile, input_data)) return; cout << "Decoding input..." << endl;
    try {
        if (format_str == "BIN") { ciphertext_raw = input_data; }
        else if (format_str == "HEX") { StringSource(input_data, true, new HexDecoder(new StringSink(ciphertext_raw))); }
        else { string cleaned; for(char c : input_data) if (isalnum(c) || c == '+' || c == '/' || c == '=') cleaned += c; StringSource(cleaned, true, new Base64Decoder(new StringSink(ciphertext_raw))); }
    } catch (const CryptoPP::Exception& e) { cerr << "Error decoding input: " << e.what() << endl; return; }
    cout << "Decrypting..." << endl; string recovered_plaintext; AutoSeededRandomPool rng; RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    try { StringSource ss_cipher(ciphertext_raw, true, new PK_DecryptorFilter(rng, decryptor, new StringSink(recovered_plaintext))); }
    catch (const CryptoPP::Exception& e) { cerr << "Decryption failed: " << e.what() << ". Wrong key/data/format?" << endl; return; }
    cout << "Decryption successful. Outputting..." << endl;
    try {
        if (outFile == "-") { cout.write(recovered_plaintext.data(), recovered_plaintext.size()); cout << endl; }
        else { if (!WriteFile(outFile, recovered_plaintext)) return; cout << "Recovered plaintext saved to: " << outFile << endl; }
    } catch (const std::exception& e) { cerr << "Error writing output: " << e.what() << endl; }
}


// 4. Xử lý Benchmark
// (Giữ nguyên)
void handle_benchmark() {
    string pubKeyFile, privKeyFile; RSA::PublicKey publicKey; RSA::PrivateKey privateKey;
    cout << "Enter public key filename (DER) for benchmark: "; getline(cin, pubKeyFile); if (!LoadPublicKeyDER(pubKeyFile, publicKey)) return;
    cout << "Enter private key filename (DER) for benchmark: "; getline(cin, privKeyFile); if (!LoadPrivateKeyDER(privKeyFile, privateKey)) return;
    const int NUM_RUNS = 10000;
    const vector<size_t> input_sizes = { 1*1024, 10*1024, 100*1024, 512*1024, 1*1024*1024 };
    size_t max_plaintext_len = publicKey.GetModulus().ByteCount() - 2 * 20 - 2;
    cout << "RSA key modulus size: " << publicKey.GetModulus().BitCount() << " bits (" << publicKey.GetModulus().ByteCount() << " bytes)" << endl;
    cout << "Max theoretical plaintext length for RSA-OAEP-SHA1: " << max_plaintext_len << " bytes" << endl << endl;
    AutoSeededRandomPool rng; RSAES_OAEP_SHA_Encryptor encryptor(publicKey); RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    cout << fixed << setprecision(4);
    for (size_t current_size : input_sizes) {
        cout << "--- Benchmarking Input Size: " << (current_size / 1024.0) << " KB (" << current_size << " bytes) ---" << endl;
        if (current_size > max_plaintext_len) { cout << "Skipping size: Exceeds maximum plaintext length." << endl << endl; continue; }
        SecByteBlock input_data(current_size); OS_GenerateRandomBlock(false, input_data.data(), input_data.size());
        string plaintext(reinterpret_cast<const char*>(input_data.data()), input_data.size());
        std::chrono::duration<double, std::milli> total_enc_time(0.0), total_dec_time(0.0);
        string ciphertext, recovered; cout << "Running " << NUM_RUNS << " iterations..." << endl;
        for (int i = 0; i < NUM_RUNS; ++i) {
            try {
                ciphertext.clear(); auto start_enc = std::chrono::high_resolution_clock::now();
                StringSource ss_enc(plaintext, true, new PK_EncryptorFilter(rng, encryptor, new StringSink(ciphertext)));
                auto end_enc = std::chrono::high_resolution_clock::now(); total_enc_time += (end_enc - start_enc);
            } catch (const CryptoPP::Exception& e) { cerr << "\nEnc Error (run " << i+1 << "): " << e.what() << endl; total_enc_time = std::chrono::duration<double, std::milli>::max(); break; }
            if (total_enc_time == std::chrono::duration<double, std::milli>::max()) { total_dec_time = std::chrono::duration<double, std::milli>::max(); break; }
            try {
                 recovered.clear(); auto start_dec = std::chrono::high_resolution_clock::now();
                 StringSource ss_dec(ciphertext, true, new PK_DecryptorFilter(rng, decryptor, new StringSink(recovered)));
                 auto end_dec = std::chrono::high_resolution_clock::now(); total_dec_time += (end_dec - start_dec);
            } catch (const CryptoPP::Exception& e) { cerr << "\nDec Error (run " << i+1 << "): " << e.what() << endl; total_dec_time = std::chrono::duration<double, std::milli>::max(); break; }
        }
        if (total_enc_time != std::chrono::duration<double, std::milli>::max() && total_dec_time != std::chrono::duration<double, std::milli>::max()) {
             double avg_enc_time = total_enc_time.count() / NUM_RUNS; double avg_dec_time = total_dec_time.count() / NUM_RUNS;
             cout << "Average Encryption Time: " << avg_enc_time << " ms" << endl;
             cout << "Average Decryption Time: " << avg_dec_time << " ms" << endl << endl;
        } else { cout << "Benchmark calculation skipped due to errors." << endl << endl; }
    }
    cout << "--- Benchmark Completed ---" << endl;
}

// 5. *** MỚI: Xử lý Tạo File Mẫu ***
void handle_generate_sample_files() {
    cout << "Generating sample plaintext files..." << endl;
    const vector<std::pair<string, size_t>> sample_files = {
        {"sample_1kb.txt", 1 * 1024},
        {"sample_10kb.txt", 10 * 1024},
        {"sample_1mb.txt", 1 * 1024 * 1024}
        // Thêm kích thước khác nếu muốn
    };

    AutoSeededRandomPool rng; // Dùng để tạo dữ liệu ngẫu nhiên

    for (const auto& pair : sample_files) {
        const string& filename = pair.first;
        const size_t size = pair.second;

        cout << "Generating " << filename << " (" << size << " bytes)... ";
        SecByteBlock random_data(size);
        try {
            OS_GenerateRandomBlock(false, random_data.data(), random_data.size()); // false = non-blocking

            if (WriteFile(filename, random_data)) {
                cout << "Done." << endl;
            } else {
                // Lỗi đã được in trong WriteFile
                cout << "Failed." << endl;
            }
        } catch (const CryptoPP::Exception& e) {
             cerr << "\nError generating random data for " << filename << ": " << e.what() << endl;
        } catch (const std::exception& e) {
             cerr << "\nError writing file " << filename << ": " << e.what() << endl;
        }
    }
    cout << "Sample file generation complete." << endl;
}


// --- Main Program Menu ---
int main() {
    int choice = 0;

    // Optional: Set console to UTF-8 if needed
    #ifdef _WIN32
        // SetConsoleOutputCP(CP_UTF8);
        // SetConsoleCP(CP_UTF8);
    #endif

    while (choice != 6) { // Thay đổi điều kiện thoát thành 6
        cout << "\n===== RSA Tool Menu =====" << endl;
        cout << "1. Generate RSA Key Pair (3072-bit DER)" << endl;
        cout << "2. Encrypt File" << endl;
        cout << "3. Decrypt File" << endl;
        cout << "4. Generate Sample Files (1KB, 10KB, 1MB)" << endl; // Thêm lựa chọn mới
        cout << "5. Run Encryption/Decryption Benchmark" << endl;    // Đổi số thứ tự
        cout << "6. Exit" << endl;                                   // Đổi số thứ tự
        cout << "Enter your choice: ";

        if (!(cin >> choice)) {
            cerr << "Invalid input. Please enter a number." << endl;
            cin.clear();
            clear_cin_buffer();
            continue;
        }
        clear_cin_buffer();

        try {
            switch (choice) {
                case 1:
                    handle_key_generation_interactive();
                    break;
                case 2:
                    handle_encryption_interactive();
                    break;
                case 3:
                    handle_decryption_interactive();
                    break;
                case 4: // Gọi hàm mới
                    handle_generate_sample_files();
                    break;
                case 5: // Đổi case cho benchmark
                    handle_benchmark();
                    break;
                case 6: // Đổi case cho exit
                    cout << "Exiting program." << endl;
                    break;
                default:
                    cerr << "Invalid choice. Please try again." << endl;
            }
        } catch (const CryptoPP::Exception& e) {
            cerr << "\n*** An operation failed (Crypto++ Exception): " << e.what() << " ***" << endl;
        } catch (const std::exception& e) {
            cerr << "\n*** An operation failed (Standard Exception): " << e.what() << " ***" << endl;
        } catch (...) {
            cerr << "\n*** An unknown error occurred during the operation. ***" << endl;
        }

        // Chỉ đợi Enter nếu không phải là lựa chọn thoát
        if (choice != 6) {
             cout << "\nPress Enter to return to menu...";
             cin.get();
        }
    }

    return 0;
}