Introduction

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