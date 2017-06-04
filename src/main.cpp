#include <algorithm>
#include <conio.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdio.h>
#include <string>
#include <vector>

using namespace std;

//
// Challenge 1
//

// parse a two-character hex value (for example, f8) into a byte
// for example, f8 will return 248
// assumes pointer passed in is valid.
// If an invalid value is passed in, returns -1;
uint8_t parse_byte_hex(const char* pHex) {
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
void hex_decode(const char* hex, uint8_t* output, size_t output_length) {
    for (size_t i = 0; i < output_length; i++)
    {
        output[i] = parse_byte_hex(hex);
        hex += 2;
    }
}

void test_parse_byte_hex() {
    char* input = "f8";
    printf("parsing %s, returning %d\n", input, parse_byte_hex(input));

    input = "49";  // 73
    printf("parsing %s, returning %d\n", input, parse_byte_hex(input));
}


// Convert 24 bytes from src into four encoded characters
// assumes that dst has space for four more characters
// assumes that src points to at least 24 bytes
// https://en.wikipedia.org/wiki/Base64
void base64_encode(char* dst, uint8_t* src) {
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

void test_base64_encode() {
    uint8_t input[3] = { 0x4d, 0x61, 0x6e };
    char result[5] = { 0 };
    base64_encode(result, input);
    printf("encoding 0x4d626e, returning %s\n", result);
}

// 1.1
// The string 
// 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
// should produce 
// SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
void set1_challenge1() {
    char* hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const uint8_t NUM_BYTES = 48;
    uint8_t bytes[NUM_BYTES] = { 0 };
    hex_decode(hex, bytes, NUM_BYTES);

    char result[(NUM_BYTES / 3) * 4 + 1] = { 0 };
    for (size_t i = 0; i < NUM_BYTES / 3; i++)
    {
        base64_encode(result + (i * 4), bytes + (i * 3));
    }
    printf("%s\n", result);
}

//
// Challenge 2
//

void xor_buffers(const uint8_t *bytes1, const uint8_t *bytes2, uint8_t *output, size_t num_bytes) {
    for (size_t i = 0; i < num_bytes; i++)
    {
        output[i] = bytes1[i] ^ bytes2[i];
    }
}

void xor_buffer(const uint8_t *bytes1, const uint8_t byte2, uint8_t *output, size_t num_bytes) {
    for (size_t i = 0; i < num_bytes; i++)
    {
        output[i] = bytes1[i] ^ byte2;
    }
}

void xor_buffer_repeating(const uint8_t *input, const uint8_t *keys, uint8_t *output, size_t input_size, size_t key_size) {
    int key_index = 0;
    for (size_t i = 0; i < input_size; i++) {
        uint8_t current_key = keys[key_index];
        output[i] = input[i] ^ current_key;
        key_index++;
        key_index %= key_size;
    }
}

void sprint_hex(char* output, size_t output_len, uint8_t *bytes, size_t num_bytes) {
    for (size_t i = 0; i < num_bytes; i++)
    {
        sprintf_s(output + i * 2, output_len - i * 2, "%02x", bytes[i]);
    }
}

void print_hex(uint8_t *bytes, size_t num_bytes) {
    for (size_t i = 0; i < num_bytes; i++)
    {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

void test_print_hex() {
    printf("print_hex 0xdeadbeef:\n");
    uint8_t input[4] = { 0xde,0xad,0xbe,0xef };
    print_hex(input, 4);
}
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
    hex_decode(hex1, bytes1, sizeof(bytes1));
    uint8_t bytes2[NUM_BYTES];
    hex_decode(hex2, bytes2, sizeof(bytes2));

    uint8_t bytes3[NUM_BYTES] = { 0 };
    xor_buffers(bytes1, bytes2, bytes3, sizeof(bytes3));

    print_hex(bytes3, sizeof(bytes3));
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
    hex_decode(hex1.c_str(), bytes1, sizeof(bytes1));

    vector<string> decodings;
    for (uint8_t possible_char = 0; possible_char < 255; possible_char++)
    {
        uint8_t result_bytes[NUM_BYTES + 1] = { 0 };
        xor_buffer(bytes1, possible_char, result_bytes, NUM_BYTES);
        decodings.push_back(string((char*)result_bytes));
    }


    sort(decodings.begin(), decodings.end(), [](string a, string b) {
        return count(a.begin(), a.end(), ' ') > count(b.begin(), b.end(), ' ');
    });

    for (size_t i = 0; i < 10; i++)
    {
        cout << decodings[i] << endl;

    }
}

//
// Challenge 4
//

void set1_challenge4() {
    ifstream infile("data/4.txt");
    string line;
    const size_t NUM_BYTES = 30;
    while (infile >> line) {
        // convert the line into bytes A
        // xor against every possible character
        // if C ^ p == A then print the result
        uint8_t encoded[NUM_BYTES] = { 0 };
        hex_decode(line.c_str(), encoded, sizeof(encoded));

        for (uint8_t possible_char = 1; possible_char < 256 && possible_char != 0; possible_char++)
        {
            uint8_t decoded[NUM_BYTES + 1] = { 0 };
            xor_buffer(encoded, possible_char, decoded, NUM_BYTES);
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

void set1_challenge5() {
    string line1 = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal";
    string key = "ICE";
    // Encrypt under key 'ICE' using repeating-key XOR
    // in repeating-key XOR, sequentially apply each byte of the key, first byte of plaintext will
    // be XOR'd sgainst I, next C, next E, etc.
    auto encrypt = [key](string input)
    {
        const char* inputC = input.c_str();
        string output(input);
        xor_buffer_repeating((const uint8_t*)(inputC), (const uint8_t*)key.c_str(), (uint8_t*)output.c_str(), input.length(), key.length());

        return output;
    };

    string line1Encrypted = encrypt(line1);
    print_hex((uint8_t*)line1Encrypted.c_str(), line1Encrypted.length());
    // Should match
    // 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
    // a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

}

int main(int argc, char *argv[], char *envp[]) {
    // set1_challenge1();
    // test_parse_byte_hex();
    // test_base64_encode();
    // test_print_hex();
    // set1_challenge3();
    //set1_challenge4();
    set1_challenge5();
    cout << "Press any key to continue...";
    cin.ignore();
}