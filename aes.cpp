#include <iostream>
#include <string> 
#include <vector> 
#include <iomanip>
#include <sstream>
using namespace std; 

void banner() {
    cout << "\033[0;34m"  // bright blue
         << R"(
             _    _____ ____        _ ____  ___  
            / \  | ____/ ___|      / |___ \( _ ) 
           / _ \ |  _| \___ \ _____| | __) / _ \ 
          / ___ \| |___ ___) |_____| |/ __/ (_) |
         /_/   \_\_____|____/      |_|_____\___/ 
        )"
         << "\033[0m\n\n"
         << "\033[1;33mAES-128\033[0m Tool "
         << "\033[1;31mintelkumi\033[0m v1.0\n\n";
}

void header() {
    cout << "\033[1;32m"
         << "================== AES-128 ENCRYPTION ==================\n"
         << "          Powered by El Kumi Cipher Labs (v1.0)\n"
         << "===========================================================\n"
         << "\033[0m";
}

void help() {
    cout << "\033[1;33mUsage:\033[0m\n"
         << "  ./aes -e <string_to_encrypt>    Encrypt input string\n";
}

const vector<unsigned char> s_box = {
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

string aes_str = "";

// estep uno
vector<string> split_into_chunks(string* input) { 
    vector<string> chunks; 
    for(int i = 0; i < input->size(); i += 16) 
        chunks.push_back(input->substr(i, min(16, (int)(input->size() - i)))); 

    return chunks; 
} 

string key_check(string* input) { 
    while (input->size() < 16) *input += '\0'; 
    *input = input->substr(0, 16); return *input; 
} 

string message_padding(string input) { 
    int str_size = input.size(); 
    int pad = 16 - (str_size % 16);

    for (int i = 0; i < pad; i++) { 
        input += static_cast<char>(pad); 
    } 
    
    return input; 
} 

void print_hex(const string& s) {
    for (unsigned char c : s)
        cout << hex << setw(2) << setfill('0') << (int)c << " ";

    cout << dec << endl;
}


// estep dos
vector<vector<unsigned char>> build_state_matrix(const string& block) {
    vector<vector<unsigned char>> state(4, vector<unsigned char>(4));

    for(int i = 0; i < 16; i++) {
        int r = i % 4;
        int c = i / 4;

        state[r][c] = static_cast<unsigned char>(block[i]);
    }

    return state;
}

void print_matrix(const vector<vector<unsigned char>>& m) {
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            cout << hex << setw(2) << setfill('0') << (int)m[r][c] << " ";
        }
        cout << endl;
    }
    cout << dec << endl;
}

//estep tres
void sub_bytes(vector<vector<unsigned char>>& state) {
    for(int i = 0; i < 4; i++) {
        for(int j  = 0; j < 4; j++) {
            state[i][j] = s_box[state[i][j]];
        }
    }
}

// estep quadro
void shift_rows(vector<vector<unsigned char>>& state) {
    // Row 1: shift left by 1
    unsigned char temp1 = state[1][0];
    for (int c = 0; c < 3; c++) 
        state[1][c] = state[1][c + 1];

    state[1][3] = temp1;

    // Row 2: shift left by 2
    swap(state[2][0], state[2][2]);
    swap(state[2][1], state[2][3]);

    // Row 3: shift left by 3 (or right by 1)
    unsigned char temp2 = state[3][3];
    for (int c = 3; c > 0; c--) state[3][c] = state[3][c - 1]; // Copies state[3][2] to state[3][3], then state[3][1] to state[3][2], etc.
    state[3][0] = temp2;
}


// estep cinco
/*
​2 1 1 3 
​3 2 1 1 
​1 3 2 1 
​1 1 3 2​
*/
unsigned char gmul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) 
            p ^= a;

        bool hi_bit = (a & 0x80);
        a <<= 1;

        if (hi_bit) 
            a ^= 0x1b;

        b >>= 1;
    }

    return p;
}

void mix_columns(vector<vector<unsigned char>>& state) {
    for (int c = 0; c < 4; c++) {
        unsigned char a0 = state[0][c];
        unsigned char a1 = state[1][c];
        unsigned char a2 = state[2][c];
        unsigned char a3 = state[3][c];

        state[0][c] = gmul(a0,2) ^ gmul(a1,3) ^ gmul(a2,1) ^ gmul(a3,1);
        state[1][c] = gmul(a0,1) ^ gmul(a1,2) ^ gmul(a2,3) ^ gmul(a3,1);
        state[2][c] = gmul(a0,1) ^ gmul(a1,1) ^ gmul(a2,2) ^ gmul(a3,3);
        state[3][c] = gmul(a0,3) ^ gmul(a1,1) ^ gmul(a2,1) ^ gmul(a3,2);
    }
}
// estep seis
void add_round_key(vector<vector<unsigned char>>& state, const vector<vector<unsigned char>>& round_key) {
    for(int r = 0; r < 4; r++) {
        for(int c = 0; c < 4; c++) {
            state[r][c] ^= round_key[r][c];
        }
    }
} 

// estep siete
vector<vector<vector<unsigned char>>> key_expansion(const string& key) {
    const unsigned char Rcon[10] = { 
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    };

    vector<unsigned char> expanded_key(176);
    for (int i = 0; i < 16; i++) expanded_key[i] = key[i];

    int bytes_generated = 16;
    int rcon_iter = 0;
    unsigned char temp[4];

    while (bytes_generated < 176) {
        for (int i = 0; i < 4; i++)
            temp[i] = expanded_key[i + bytes_generated - 4];

        if (bytes_generated % 16 == 0) {
            unsigned char t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            for (int i = 0; i < 4; i++)
                temp[i] = s_box[temp[i]];

            temp[0] ^= Rcon[rcon_iter++];
        }

        for (int i = 0; i < 4; i++) {
            expanded_key[bytes_generated] = expanded_key[bytes_generated - 16] ^ temp[i];
            bytes_generated++;
        }
    }

    vector<vector<vector<unsigned char>>> round_keys(11, vector<vector<unsigned char>>(4, vector<unsigned char>(4)));
    for (int round = 0; round < 11; round++) {
        for (int i = 0; i < 16; i++) {
            round_keys[round][i % 4][i / 4] = expanded_key[round * 16 + i];
        }
    }
    return round_keys;
}

// aes string.. <sstream>
string get_hex_string(const vector<vector<unsigned char>>& state) {
    stringstream ss;
    ss << hex << setfill('0');

    for (int i = 0; i < 16; i++) {
        int r = i % 4;
        int c = i / 4;
        ss << setw(2) << static_cast<int>(state[r][c]);
    }

    return ss.str();
}

int main() { 
    string message = "If you want your son high level wrestling, send him 2-3 years Georgia and forget!"; 
    string key = "CHAMA O NAO CHAMA?!";

    cout << "Key in Hex: ";
    key = key_check(&key);

    print_hex(key);

    string padded_message = message_padding(message);
    vector<string> chunks = split_into_chunks(&padded_message);
    vector<vector<vector<unsigned char>>> round_keys = key_expansion(key);

    for (auto& chunk : chunks) {
        auto state = build_state_matrix(chunk);

        // Step 1: Initial round
        add_round_key(state, round_keys[0]);

        // Step 2: 9 main rounds
        for (int round = 1; round <= 9; round++) {
            sub_bytes(state);
            shift_rows(state);
            mix_columns(state);
            add_round_key(state, round_keys[round]);
        }

        // Step 3: Final round
        sub_bytes(state);
        shift_rows(state);
        add_round_key(state, round_keys[10]);

        cout << "Encrypted block:\n";
        print_matrix(state);
        aes_str += get_hex_string(state);
    }

    cout << "========================\n";
    cout << aes_str << endl;

    banner();
    return 0; 
}