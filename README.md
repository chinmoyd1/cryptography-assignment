# Cryptography assignment

## Technologies
 * Java
 * JUnit
 * Maven

## UML class diagram
![alt text](/UML.png)

## Questions
#### 1. What happens if the symmetric key used in this scenario is compromised?<br/>
>Answer:  If symmetric key is compromised then data can be modified by some other person beacause he can decrypt the data using symmetric key.
#### 2. Describe techniques you would use to securely share a symmetric key with the other party? Improve the security of this process in any other possible ways you can think of.<br/>
>Answer:  Sender hands over secret key personally.

#### 3. List all security measures required for this assignment. Hint: Key storage, Key recovery<br/> 
>Answer:<br/>Hashing(SHA256), <br/>Symmetric Key Cryptography(RSA), <br/>Asymmetric Key Cryptography(AES256), <br/>Diginal Signature

## Steps to run
 - clone the cryptography.assignment-1.0-standalone.jar from "/target/cryptography.assignment-1.0-standalone.jar"
 - run "java -jar cryptography.assignment-1.0-standalone.jar" in terminal/cmd

