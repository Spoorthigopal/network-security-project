# Enhanced Security Network Coding System for Two-Way Relay Networks

## 📌 Project Overview
The **Enhanced Security Network Coding System** is a Python-based project that demonstrates secure data exchange in a **Two-Way Relay Network (TWRN)**.  
In this system, two users communicate with each other through a relay node while ensuring **data confidentiality, integrity, and efficiency** using **network coding and cryptographic techniques**.

This project focuses on improving security at the relay node, which is often considered vulnerable in wireless and cooperative communication systems.

---

## 🎯 Objectives
- To implement secure communication in a Two-Way Relay Network
- To apply **network coding** for efficient data transmission
- To enhance security using **encryption techniques**
- To simulate relay-based communication using a **GUI application**
- To provide a beginner-friendly demonstration of network security concepts

---



## 🛠️ Technologies Used
- **Programming Language:** Python  
- **GUI Framework:** Tkinter  
- **Security:** Cryptographic algorithms (RSA / Symmetric Encryption)  
- **IDE:** VS Code / PyCharm  
- **Operating System:** Windows / Linux  

---

## ⚙️ System Architecture
1. **User A** sends encrypted data to the relay  
2. **User B** sends encrypted data to the relay  
3. The **relay node performs network coding** without accessing plaintext  
4. Encoded data is securely transmitted back  
5. Users decode and decrypt the received message  

This approach reduces transmission overhead while maintaining strong security.

---

## 🚀 Features
- Secure message exchange using encryption
- Efficient communication using network coding
- Relay node cannot read original messages
- User-friendly GUI for easy interaction
- Modular and easy-to-understand code structure




In modern wireless communication systems, secure and efficient data transmission is very important. Two-Way Relay Networks (TWRN) are widely used communication models where two users exchange information with each other through an intermediate relay node. This method improves network coverage and reduces transmission cost, but it also introduces security challenges because the data passes through a shared relay. If proper security measures are not applied, unauthorized users may intercept or manipulate the transmitted information.

The Enhanced Security Network Coding System for Two-Way Relay Networks project aims to provide a secure and efficient communication mechanism using network coding combined with encryption techniques. Network coding allows multiple data packets to be combined and transmitted together, reducing the number of transmissions and improving bandwidth efficiency. However, since coded data contains information from multiple users, security becomes a major concern. This project focuses on enhancing security while maintaining the advantages of network coding.

Proposed Approach

The proposed system follows a two-way communication model where two users (Node A and Node B) want to exchange messages through a relay. Instead of sending messages separately, the relay uses network coding to combine the messages into a single coded packet. This reduces transmission time and improves overall network performance.

To ensure security, encryption is applied before network coding. Each message is encrypted using a public-key cryptography technique so that even if the coded data is intercepted, the original messages cannot be understood by an attacker. Only the intended receiver, who has the correct private key, can decrypt and retrieve the original message.

The system also includes message validation and controlled access to prevent unauthorized communication. This approach ensures confidentiality, integrity, and efficient data transfer in the two-way relay network.

Algorithm (Simple Explanation)

Node A and Node B enter their messages into the system.

Each message is encrypted using a secure encryption algorithm.

The encrypted messages are sent to the relay node.

The relay performs network coding by combining both encrypted messages.

The coded message is transmitted back to both nodes.

Each node decodes the received message.

The decoded message is decrypted using the private key to obtain the original data.

This algorithm ensures that even the relay cannot read the original messages, providing an additional layer of security.

Technology Stack Used

Python: Used for implementing encryption logic, network coding operations, and overall system flow due to its simplicity and strong library support.

Tkinter: Used to create a user-friendly graphical interface where users can enter messages, send data, and view encrypted and decrypted outputs.

Cryptography Libraries: Used to perform secure encryption and decryption operations.

GitHub: Used for version control and collaborative development.

Conclusion

The Enhanced Security Network Coding System for Two-Way Relay Networks provides a secure and efficient solution for modern wireless communication systems. By combining encryption with network coding, the system ensures data security while improving network performance. The use of Python and Tkinter makes the implementation simple, interactive, and suitable for academic and real-world applications.