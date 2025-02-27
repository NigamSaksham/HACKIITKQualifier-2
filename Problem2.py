'''Problem Statement:
 A blockchain stores transactions in a block. Each block contains a Merkle root, which is a hash value representing all the transactions in that block. The Merkle root is computed recursively by hashing pairs of transactions until only one hash remains.

You are given a list of transactions (represented as strings) and are required to compute the Merkle root for multiple test cases. The hash function to use is SHA-256.
Steps to compute the Merkle root:
 - Transaction Hashing: Each transaction is represented as a string. You need to compute the SHA-256 hash of each pair recursively. SHA-256 is a cryptographic hash function that outputs a 256-bit value, typically represented as a 64-character hexadecimal string.
 - Pairing Transactions: The transactions are paired for hashing. If the number of transactions is odd, the last transaction is duplicated to make the number even before calculating the Merkle root.
 - Recursive Hashing: After pairing, hash each pair and repeat the process with the newly computed hashes until only one hash remains. This final hash is the Merkle root.
Input Format:
The input consists of multiple test cases.
The first line contains an integer T ( 1 <= T <= 10 ), the number of test cases.
For each test case:
The first line contains an integer N ( 1 <= N <= 100 ), the number of transactions.
The next N lines each contain a string S ( 1 <= length(S) <= 100 ), representing a transaction.

Output Format:
 For each test case, output a single line containing the Merkle root for the given transactions.

Constraints:
The transactions are given as strings, and you should compute the SHA-256 hash of each transaction.
If there’s only one transaction in a test case, the Merkle root is simply the SHA-256 hash of that transaction.
'''
