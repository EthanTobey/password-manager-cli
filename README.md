# 🔐 Java Password Manager CLI App

A command-line password manager built in Java, designed to securely store and retrieve login credentials. Features include encrypted storage, basic user authentication, and an intuitive CLI interface for managing credentials.

---

## 📁 Project Structure

```
password-manager-cli/
├── PasswordManager.java # Core logic for password storage and retrieval
├── passwords.txt # Encrypted password store (generated at runtime)
└── README.md
```

---

## 🚀 Features

- Add, retrieve, and delete login credentials
- Store credentials in an encrypted local file
- Basic username-password login system
- User-friendly command-line interface
- AES encryption for secure credential handling

---

## 🛠 Setup and Run

### 1. Clone the Repository

    git clone https://github.com/yourusername/password-manager.git
    cd password-manager

### 2. Compile the Code
Ensure you have Java (JDK 8+) installedd.

    javac src/*.java

### 3. Run the App

    java -cp src PasswordManager

## 🧪 Example Commands

    Welcome to Java Password Manager!
    Enter Password:
    a: Add Password
    r: Read Password
    q: Quit
    Enter choice:

---

## 🔐 Security

All credential data is encrypted using AES before being saved to `passwords.txt`. The encryption key is derived from a user-provided master password (not stored). The app is intended for educational/demo use only—not for production security use.

---

## 📎 Notes

- No external libraries are used—only standard Java libraries.
- Designed to reinforce Java OOP design, CLI handling, and file I/O security.
- Easily extendable with features like password generation, better authentication, or UI.

---

## 🧑‍💻 Author

**Ethan Tobey**  
Case Western Reserve University  
B.S. in Computer Science, Minor in Computer Gaming

