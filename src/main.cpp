#include <algorithm>
#if defined(WIN32) 
#include <conio.h>
#endif
#include <fstream>
#include <iostream>
#include <memory>
#include <queue>
#include <stdio.h>
#include <string>
#include <vector>

using namespace std;

// Allow us to use sprintf
// https://stackoverflow.com/questions/119578/disabling-warnings-generated-via-crt-secure-no-deprecate
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

//
// Utilities
//

// parse a two-character hex value (for example, f8) into a byte
// for example, f8 will return 248
// assumes pointer passed in is valid.
// If an invalid value is passed in, returns -1;
uint8_t util_parse_byte_hex(const char* pHex) {
    uint8_t val = 0;

    for (size_t i = 0; i < 2; i++)
    {
        uint8_t c = pHex[i];
        if (c >= '0' && c <= '9') {
            val = val * 16 + c - '0';
        }
        else if (c >= 'a' && c <= 'f') {
            val = val * 16 + c - 'a' + 10;
        }
        else if (c >= 'A' && c <= 'F') {
            val = val * 16 + c - 'A' + 10;
        }
        else {
            return -1;
        }
    }
    return val;
}

// Decode a string into a buffer of bytes called output
// Assumes that there are at least output_length * 2 values in hex
void util_hex_decode(const char* hex, uint8_t* output, size_t output_length) {
    for (size_t i = 0; i < output_length; i++)
    {
        output[i] = util_parse_byte_hex(hex);
        hex += 2;
    }
}

void test_util_parse_byte_hex() {
    char* input = "f8";
    printf("parsing %s, returning %d\n", input, util_parse_byte_hex(input));

    input = "49";  // 73
    printf("parsing %s, returning %d\n", input, util_parse_byte_hex(input));
}

// Convert 3 bytes from src into four encoded characters
// assumes that dst has space for four more characters
// assumes that src points to at least 3 bytes
// https://en.wikipedia.org/wiki/Base64
void util_base64_encode(char* dst, uint8_t* src) {
    uint8_t c1 = (*src & 0xfc) >> 2;
    uint8_t c2 = ((*src & 0x03) << 4) + ((src[1] & 0xf0) >> 4);
    uint8_t c3 = ((src[1] & 0x0f) << 2) + ((src[2] & 0xc0) >> 6);
    uint8_t c4 = src[2] & 0x3f;
    uint8_t sbc[4] = { c1, c2, c3, c4 };
    for (size_t i = 0; i < 4; i++)
    {
        uint8_t six_bits = sbc[i];
        char c;
        if (six_bits < 26) {
            c = 'A' + six_bits;
        }
        else if (six_bits < 52) {
            c = 'a' + six_bits - 26;
        }
        else if (six_bits < 62) {
            c = '0' + six_bits - 52;
        }
        else if (six_bits == 62) {
            c = '+';
        }
        else {
            // six_bits == 63
            c = '/';
        }
        dst[i] = c;
    }
}

void test_util_base64_encode() {
    uint8_t input[3] = { 0x4d, 0x61, 0x6e };
    char result[5] = { 0 };
    util_base64_encode(result, input);
    printf("encoding 0x4d626e, returning %s\n", result);
}

// https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
static const int B64index[256] = { 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 62, 63, 62, 62, 63, 52, 53, 54, 55,
56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,  0,  0,  1,  2,  3,  4,  5,  6,
7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,
0,  0,  0, 63,  0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51 };

std::string util_base64_decode(const void* data, const size_t len)
{
    unsigned char* p = (unsigned char*)data;
    int pad = len > 0 && (len % 4 || p[len - 1] == '=');
    const size_t L = ((len + 3) / 4 - pad) * 4;
    std::string str(L / 4 * 3 + pad, '\0');

    for (size_t i = 0, j = 0; i < L; i += 4)
    {
        int n = B64index[p[i]] << 18 | B64index[p[i + 1]] << 12 | B64index[p[i + 2]] << 6 | B64index[p[i + 3]];
        str[j++] = n >> 16;
        str[j++] = n >> 8 & 0xFF;
        str[j++] = n & 0xFF;
    }
    if (pad)
    {
        int n = B64index[p[L]] << 18 | B64index[p[L + 1]] << 12;
        str[str.size() - 1] = n >> 16;

        if (len > L + 2 && p[L + 2] != '=')
        {
            n |= B64index[p[L + 2]] << 6;
            str.push_back(n >> 8 & 0xFF);
        }
    }
    return str;
}

void test_util_base64_decode()
{
    string input = "YW55IGNhcm5hbCBwbGVhc3Vy";
    cout << util_base64_decode(input.c_str(), input.length()) << endl;
}

void util_xor_buffers(const uint8_t *bytes1, const uint8_t *bytes2, uint8_t *output, size_t num_bytes) {
    for (size_t i = 0; i < num_bytes; i++)
    {
        output[i] = bytes1[i] ^ bytes2[i];
    }
}

void util_xor_buffer(const uint8_t *bytes1, const uint8_t byte2, uint8_t *output, size_t num_bytes) {
    for (size_t i = 0; i < num_bytes; i++)
    {
        output[i] = bytes1[i] ^ byte2;
    }
}

void util_xor_buffer_repeating(const uint8_t *input, const uint8_t *keys, uint8_t *output, size_t input_size, size_t key_size) {
    int key_index = 0;
    for (size_t i = 0; i < input_size; i++) {
        uint8_t current_key = keys[key_index];
        output[i] = input[i] ^ current_key;
        key_index++;
        key_index %= key_size;
    }
}

void util_print_hex(char* output, size_t output_len, uint8_t *bytes, size_t num_bytes) {
    for (size_t i = 0; i < num_bytes; i++)
    {
        sprintf(output + i * 2, "%02x", bytes[i]);
    }
}

void util_print_hex(uint8_t *bytes, size_t num_bytes) {
    for (size_t i = 0; i < num_bytes; i++)
    {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

void test_util_print_hex() {
    printf("util_print_hex 0xdeadbeef:\n");
    uint8_t input[4] = { 0xde,0xad,0xbe,0xef };
    util_print_hex(input, 4);
}

string util_encrypt_repeating_xor_string(const string& input, const string& key) {
    const char* inputC = input.c_str();
    string output(input);
    util_xor_buffer_repeating((const uint8_t*)(inputC), (const uint8_t*)key.c_str(), (uint8_t*)output.c_str(), input.length(), key.length());
    return output;
}


// Given a set of base 64 decoded bytes finds the single-byte XOR
// key that produces the best-looking text (in other words that text)
// that most likely looks like a message.
// If no good character was found (if less than 90% of the 
// characters are not valid), returns 0 (NULL)
uint8_t util_histogram_analyze(uint8_t* data, size_t dataLen)
{
    uint8_t result;
    const size_t COMMON_LETTER_COUNT = 53;
    char* commonLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz ";
    int maxCommon = 0;
    string maxDecoded;
    for (uint8_t possible_char = 1; possible_char != 0; possible_char++)
    {
        uint8_t* decoded = new uint8_t[dataLen];
        util_xor_buffer(data, possible_char, decoded, dataLen);
        string decoded_str((char*)decoded);
        int sumCommon = 0;
        for (int i = 0; i < COMMON_LETTER_COUNT; i++)
        {
            sumCommon += count(decoded_str.begin(), decoded_str.end(), commonLetters[i]);
        }
        if (sumCommon > maxCommon)
        {
            maxCommon = sumCommon;
            result = possible_char;
            maxDecoded = decoded_str;
        }
    }
    if ((float)result / dataLen < 0.2f)
    {
        return 0;
    }
    return result;
}

// Compute the hamming distance (number of differing *bits*) between two strings
// Assumes that str1 and str2 have same length
// Hamming distance between "this is a test" and "wokka wokka!!!" should be 37
int util_compute_edit_distance(const void* s1, const void* s2, const size_t str1_len) {
    const uint8_t* str1 = (uint8_t*)s1;
    const uint8_t* str2 = (uint8_t*)s2;
    int result = 0;
    for (int i = 0; i < str1_len; i++)
    {
        uint8_t diff = str1[i] ^ str2[i];
        for (int j = 0; j < 8; j++)
        {
            if (diff & 0x1) {
                result++;
            }
            diff >>= 1;
        }
    }
    return result;
}

void test_util_compute_edit_distance()
{
    cout << util_compute_edit_distance("this is a test", "wokka wokka!!!", 14) << endl;
}

//
// Challenge 1
//



// 1.1
// The string 
// 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
// should produce 
// SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
void set1_challenge1() {
    char* hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const uint8_t NUM_BYTES = 48;
    uint8_t bytes[NUM_BYTES] = { 0 };
    util_hex_decode(hex, bytes, NUM_BYTES);

    char result[(NUM_BYTES / 3) * 4 + 1] = { 0 };
    for (size_t i = 0; i < NUM_BYTES / 3; i++)
    {
        util_base64_encode(result + (i * 4), bytes + (i * 3));
    }
    printf("%s\n", result);
}

//
// Challenge 2
//

// Write a function that takes two equal-length buffers and produces their XOR combination.
// If your function works properly, then when you feed it the string:
// 1c0111001f010100061a024b53535009181c
// ... after hex decoding, and when XOR'd against:
// 686974207468652062756c6c277320657965
// ... should produce:
// 746865206b696420646f6e277420706c6179
void set1_challenge2() {
    char* hex1 = "1c0111001f010100061a024b53535009181c";
    char* hex2 = "686974207468652062756c6c277320657965";
    const size_t NUM_BYTES = 18;
    uint8_t bytes1[NUM_BYTES];
    util_hex_decode(hex1, bytes1, sizeof(bytes1));
    uint8_t bytes2[NUM_BYTES];
    util_hex_decode(hex2, bytes2, sizeof(bytes2));

    uint8_t bytes3[NUM_BYTES] = { 0 };
    util_xor_buffers(bytes1, bytes2, bytes3, sizeof(bytes3));
    util_print_hex(bytes3, sizeof(bytes3));
}

//
// Challenge 3
//

// The hex encoded string:
// 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
// ... has been XOR'd against a single character. Find the key, decrypt the message.
void set1_challenge3() {
    string hex1 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    const size_t NUM_BYTES = 34;
    uint8_t bytes1[NUM_BYTES];
    util_hex_decode(hex1.c_str(), bytes1, sizeof(bytes1));

    uint8_t key = util_histogram_analyze(bytes1, NUM_BYTES);
    uint8_t result_bytes[NUM_BYTES + 1] = { 0 };
    util_xor_buffer(bytes1, key, result_bytes, NUM_BYTES);
    cout << result_bytes << endl;
}

//
// Challenge 4
//

void set1_challenge4() {
    ifstream infile("data/4.txt");
    string line;
    const size_t NUM_BYTES = 30;
    while (infile >> line) {
        // convert the line into bytes
        // xor against every possible character
        // Look for strings that have a good distribution of characters
        uint8_t encoded[NUM_BYTES] = { 0 };
        util_hex_decode(line.c_str(), encoded, sizeof(encoded));

        for (uint8_t possible_char = 1; possible_char < 256 && possible_char != 0; possible_char++)
        {
            uint8_t decoded[NUM_BYTES + 1] = { 0 };
            util_xor_buffer(encoded, possible_char, decoded, NUM_BYTES);
            string decoded_str((char*)decoded);
            if (count(decoded_str.begin(), decoded_str.end(), ' ') > 4) {
                cout << line << "\t" << decoded_str << endl;
            }
        }
    }
}

//
// Challenge 5
//

// Encrypt under key 'ICE' using repeating-key XOR
// in repeating-key XOR, sequentially apply each byte of the key, first byte of plaintext will
// be XOR'd sgainst I, next C, next E, etc.
void set1_challenge5() {
    string line1 = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal";
    string key = "ICE";
    string line1Encrypted = util_encrypt_repeating_xor_string(line1, key);
    // Should match
    // 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
    // a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
    util_print_hex((uint8_t*)line1Encrypted.c_str(), line1Encrypted.length());

}

//
// Challenge 6
//

// The file data/6.txt has been base64'd after being encrypted with repeating-key XOR. 
// Decrypt it. Here's how:
// 1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40. 
// 2. Write a function to compute the edit distance/Hamming distance between two strings.
//    The Hamming distance is just the number of differing bits. The distance between 
//    "this is a test" and "wokka wokka!!!" is 37. Make sure your code agrees before you proceed
// 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of 
//    bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE. 
// 4. The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed 
//    perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average 
//    the distances. 
// 5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length. 
// 6. Now transpose the blocks: make a block that is the first byte of every block, and a block 
//    that is the second byte of every block, and so on. 
// 7. Solve each block as if it was single-character XOR. You already have code to do this. 
// 8. For each block, the single-byte XOR key that produces the best looking histogram is 
//    the repeating-key XOR key byte for that block. Put them together and you have the key. 
void set1_challenge6() {
    ifstream is("data/6_2.txt", ifstream::binary);
    // Read contents of data/6.txt into char*, also save off length
    is.seekg(0, is.end);
    streamoff dataLength = is.tellg();
    is.seekg(0, is.beg);

    char* data = new char[dataLength];
    is.read(data, dataLength);

    // base64 decode it
    string encryptedStr = util_base64_decode(data, dataLength);
    const char* encrypted = encryptedStr.c_str();
    const int encryptedLength = encryptedStr.length();

    struct info
    {
        float editD;
        int size;
    };

    struct comparator {
        bool operator()(info i, info j) {
            return i.editD > j.editD;
        }
    };
    priority_queue<info, std::vector<info>, comparator> likelyKeys;

    for (int keysize = 2; keysize < 40; keysize++) {
        uint8_t* firstBuf = (uint8_t*) encrypted;
        float averageEditD = 0;
        for (int i = 1; i < 6; i++)
        {
            uint8_t* secondBuf = firstBuf + keysize * i;
            averageEditD += util_compute_edit_distance(firstBuf, secondBuf, keysize) / (float) keysize;
        }
        averageEditD /= 5;
        likelyKeys.push(info{ averageEditD, keysize });
    }

    // Key is probably one of the first few elements
    // Test out a single keysize, let's guess it's the first one for now. If that doesn't
    // work we will build a list of candidates
    for (int t = 0; t < 4; t++)
    {
        const int blockSize = likelyKeys.top().size;
        // 5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length. 
        // 6. Now transpose the blocks: make a block that is the first byte of every block, and a block 
        //    that is the second byte of every block, and so on.  
        //    JULIA: each of these will be called a "chunk"
        // 7. Solve each chunk as if it was single-character XOR. You already have code to do this. 
        // 8. For each chunk, the single-byte XOR key that produces the best looking histogram is 
        //    the repeating-key XOR key byte for that chunk. Put them together and you have the key. 
    
        uint8_t* decryptionKey = new uint8_t[blockSize];

        int chunkLength = encryptedLength / blockSize;

        bool skipBlockSize = false;
        for (int offset = 0; offset < blockSize; offset++)
        {
            // make the chunk
            uint8_t* chunk = new uint8_t[chunkLength];
            for (int i = 0; i < chunkLength; i ++)
            {
                int byteIndex = i * blockSize + offset;
                chunk[i] = encrypted[byteIndex];
            }

            // Solve each chunk as if it was single-character XOR
            uint8_t chunkByte = util_histogram_analyze(chunk, chunkLength);
            if (chunkByte == 0)
            {
                skipBlockSize = true;
                break;
            }
            decryptionKey[offset] = chunkByte;
        }

        // print the result
        if (skipBlockSize)
        {
            cout << "block size " << blockSize << " gave invalid data, skipping..." << endl;
        }
        else
        {
            char* output = new char[encryptedLength];
            util_xor_buffer_repeating((uint8_t*)encrypted, decryptionKey, (uint8_t*)output, encryptedLength, blockSize);
            cout << "block size " << blockSize << ": " << endl << output << endl << endl;
        }

        likelyKeys.pop();
    }

}

//The Base64 - encoded content in the file "7.txt" has been encrypted via AES - 128 in ECB mode under the key
//"YELLOW SUBMARINE".
//(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too). 
//  Decrypt it.You know the key, after all.
////  Easiest way : use OpenSSL::Cipher and give it AES - 128 - ECB as the cipher.
//Do this with code.
//You can obviously decrypt this using the OpenSSL command - line tool, but we're having you get ECB working in code for a reason. You'll need it a lot later on, and not just for attacking ECB.
void set1_challenge7() {
	// Every line is base 64 encoded 
	// use while (infile >> line) to read line by line, then decrypt. 
	// OpenSSL::Cipher
}

int main(int argc, char *argv[], char *envp[]) {
    // test_util_parse_byte_hex();
    // test_util_base64_encode();
    // test_util_print_hex();
    // test_util_base64_decode();
    // test_util_compute_edit_distance();
    // SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
    // set1_challenge1();
    // 746865206b696420646f6e277420706c6179
    // set1_challenge2();
    // set1_challenge3();
    // set1_challenge4();
    // 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
    // a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
    // set1_challenge5();
    set1_challenge6();
    cout << "Press any key to continue...";
    cin.ignore();
}