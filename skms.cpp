#include <iostream>
#include <fstream>
#include <ctime>
#include <map>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>
#include "encryption.h"
using namespace std;

map<string, string> passwordDB;
map<string, string> keyStore;
const string userFile = "users.txt";

string simpleHash(string input) {
    hash<string> hasher;
    size_t hashVal = hasher(input);
    stringstream ss;
    ss << hex << hashVal;
    return ss.str();
}

string generateKey(int length = 16) {
    string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    string key = "";
    for (int i = 0; i < length; ++i) {
        key += chars[rand() % chars.length()];
    }
    return key;
}

void saveToFile() {
    ofstream file(userFile);
    for (auto& user : passwordDB) {
        
        file << user.first << " " << passwordDB[user.first] << " " << keyStore[user.first] << endl;
    }
    file.close();
}

void loadFromFile() {
    ifstream file(userFile);
    string user, pass, key;
    while (file >> user >> pass >> key) {
        passwordDB[user] = pass;
        keyStore[user] = key;
    }
    file.close();
}

void logActivity(string username, string action) {
    ofstream log("activity.log", ios::app);
    time_t now = time(0);
    string timeStr = ctime(&now);
    timeStr.pop_back();
    log << "[" << timeStr << "] " << username << " -> " << action << endl;
    log.close();
}

bool userExists(string username) {
    return passwordDB.find(username) != passwordDB.end();
}

bool checkPassword(string username, string password) {
    return userExists(username) && passwordDB[username] == simpleHash(password);
}

void registerUser(string username, string password) {
    if (userExists(username)) {
        cout << "User already exists.\n";
        return;
    }
    string hashedPassword = simpleHash(password);
    passwordDB[username] = hashedPassword;

    string rawKey = generateKey();

    
    string encryptedKey = encrypt(rawKey, hashedPassword);
    keyStore[username] = encryptedKey;

    saveToFile();
    logActivity(username, "Registered and key generated");

    cout << "User registered successfully.\n";
    cout << "Your generated key (please keep it safe): " << rawKey << endl;
}

void loginUser(string username, string password) {
    if (checkPassword(username, password)) {
        cout << "Login successful.\n";
    } else {
        cout << "Invalid username or password.\n";
    }
}

void viewKey(string username, string password) {
    if (!checkPassword(username, password)) {
        cout << "Invalid username or password.\n";
        return;
    }
    if (keyStore.find(username) != keyStore.end()) {
        string hashedPassword = simpleHash(password);
        string decryptedKey = decrypt(keyStore[username], hashedPassword);
        cout << "Your key: " << decryptedKey << endl;
        logActivity(username, "Viewed key");
    } else {
        cout << "No key found for user.\n";
    }
}

void deleteKey(string username, string password) {
    if (!checkPassword(username, password)) {
        cout << "Invalid username or password.\n";
        return;
    }
    if (keyStore.find(username) != keyStore.end()) {
        keyStore.erase(username);
        saveToFile();
        logActivity(username, "Deleted key");
        cout << "Key deleted.\n";
    } else {
        cout << "No key to delete.\n";
    }
}

void changePassword(string username, string oldPass, string newPass) {
    if (!checkPassword(username, oldPass)) {
        cout << "Incorrect current password.\n";
        return;
    }

    string oldHashed = simpleHash(oldPass);
    string newHashed = simpleHash(newPass);

    string decryptedKey = decrypt(keyStore[username], oldHashed);

    
    string reEncryptedKey = encrypt(decryptedKey, newHashed);

    passwordDB[username] = newHashed;
    keyStore[username] = reEncryptedKey;

    saveToFile();
    logActivity(username, "Changed password");

    cout << "Password changed successfully.\n";
}

void resetKey(string username, string password) {
    if (!checkPassword(username, password)) {
        cout << "Invalid username or password.\n";
        return;
    }
    string hashedPassword = simpleHash(password);

    string newKey = generateKey();
    string encryptedNewKey = encrypt(newKey, hashedPassword);
    keyStore[username] = encryptedNewKey;

    saveToFile();
    logActivity(username, "Reset key");
    cout << "New key generated: " << newKey << endl;
}

void rotateKey(string username, string password) {
    if (!checkPassword(username, password)) {
        cout << "Invalid username or password.\n";
        return;
    }
    if (keyStore.find(username) == keyStore.end()) {
        cout << "No key exists to rotate.\n";
        return;
    }
    string hashedPassword = simpleHash(password);

    string oldKey = decrypt(keyStore[username], hashedPassword);
    string newKey = generateKey();
    string encryptedNewKey = encrypt(newKey, hashedPassword);
    keyStore[username] = encryptedNewKey;

    saveToFile();
    logActivity(username, "Rotated key");
    cout << "Old Key: " << oldKey << "\nNew Key: " << newKey << endl;
}

void setCustomKey(string username, string password, string customKey) {
    if (!checkPassword(username, password)) {
        cout << "Invalid username or password.\n";
        return;
    }
    if (customKey.length() < 8) {
        cout << "Key too short. Must be at least 8 characters.\n";
        logActivity(username, "Attempted to set a short custom key");
        return;
    }
    string hashedPassword = simpleHash(password);
    string encryptedCustomKey = encrypt(customKey, hashedPassword);
    keyStore[username] = encryptedCustomKey;

    saveToFile();
    logActivity(username, "Set a custom key");
    cout << "Custom key set successfully.\n";
}

void listAllUsers() {
    cout << "Registered Users:\n";
    for (auto& user : passwordDB) {
        cout << "- " << user.first << endl;
    }
}

void deleteUser(string username, string password) {
    if (!checkPassword(username, password)) {
        cout << "Invalid username or password.\n";
        return;
    }
    passwordDB.erase(username);
    keyStore.erase(username);
    saveToFile();
    logActivity(username, "Deleted account");
    cout << "User account and key deleted successfully.\n";
}

int main(int argc, char* argv[]) {
    srand(time(0));
    loadFromFile();

    if (argc < 2) {
        cout << "Usage: skms.exe <command> [args...]\n";
        cout << "Commands:\n";
        cout << " register username password\n";
        cout << " login username password\n";
        cout << " viewkey username password\n";
        cout << " deletekey username password\n";
        cout << " changepassword username oldpass newpass\n";
        cout << " resetkey username password\n";
        cout << " rotatekey username password\n";
        cout << " setcustomkey username password customkey\n";
        cout << " listusers\n";
        cout << " deleteuser username password\n";
        return 1;
    }

    string cmd = argv[1];

    if (cmd == "register" && argc == 4) {
        registerUser(argv[2], argv[3]);
    } else if (cmd == "login" && argc == 4) {
        loginUser(argv[2], argv[3]);
    } else if (cmd == "viewkey" && argc == 4) {
        viewKey(argv[2], argv[3]);
    } else if (cmd == "deletekey" && argc == 4) {
        deleteKey(argv[2], argv[3]);
    } else if (cmd == "changepassword" && argc == 5) {
        changePassword(argv[2], argv[3], argv[4]);
    } else if (cmd == "resetkey" && argc == 4) {
        resetKey(argv[2], argv[3]);
    } else if (cmd == "rotatekey" && argc == 4) {
        rotateKey(argv[2], argv[3]);
    } else if (cmd == "setcustomkey" && argc == 5) {
        setCustomKey(argv[2], argv[3], argv[4]);
    } else if (cmd == "listusers" && argc == 2) {
        listAllUsers();
    } else if (cmd == "deleteuser" && argc == 4) {
        deleteUser(argv[2], argv[3]);
    } else {
        cout << "Invalid command or wrong number of arguments.\n";
    }

    return 0;
}
