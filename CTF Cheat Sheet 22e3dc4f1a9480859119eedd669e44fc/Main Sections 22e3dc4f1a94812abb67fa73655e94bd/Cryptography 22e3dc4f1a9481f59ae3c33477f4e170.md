# Cryptography

# General Overview

Cryptography is the reason we can use banking apps, transmit sensitive information over the web, and in general protect our privacy. However, a large part of CTFs is breaking widely used encryption schemes which are improperly implemented. The math may seem daunting, but more often than not, a simple understanding of the underlying principles will allow you to find flaws and crack the code.

The word “cryptography” technically means the art of writing codes. When it comes to digital forensics, it’s a method you can use to understand how data is constructed for your analysis.

## **Math in Cryptography**

Most modern cryptography systems rely on one way mathematical algorithms derived from [modular arithmetic](https://en.wikipedia.org/wiki/Modular_arithmetic). It's an ongoing arms race to create and implement better hardware and algorithms.

For example, the [implementation of the first RSA algorithm](https://people.csail.mit.edu/rivest/Rsapaper.pdf) is completely reliant on the "difficulty of factoring large numbers". It's a great example of security by design, and modern application developers still use similar derivatives.

In August 2024, NIST released the first standards for post-quantum encryption to remediate the quantum-computing threat against legacy systems. For more information, check out this [blog post](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)!

## What is cryptography used for?

**Uses in every day software**

- Securing web traffic (passwords, communication, etc.)
- Securing copyrighted software code
- Key exchange algorithms

**Malicious uses**

- Hiding malicious communication
- Hiding malicious code

## XOR

### Data Representation

Data can be represented in different bases, an 'A' needs to be a numerical representation of Base 2 or binary so computers can understand them

![Data Representation](https://ctf101.org/cryptography/images/data-representation.png)

### XOR Basics

An XOR or *eXclusive OR* is a bitwise operation indicated by `^` and shown by the following truth table:

| **A** | **B** | **A ^ B** |
| --- | --- | --- |
| 0 | 0 | 0 |
| 0 | 1 | 1 |
| 1 | 0 | 1 |
| 1 | 1 | 0 |

So what XOR'ing bytes in the action `0xA0 ^ 0x2C` translates to is:

|  |  |  |  |  |  |  |  |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| 0 | 0 | 1 | 0 | 1 | 1 | 0 | 0 |

| **1** | **0** | **0** | **0** | **1** | **1** | **0** | **0** |
| --- | --- | --- | --- | --- | --- | --- | --- |
|  |  |  |  |  |  |  |  |

`0b10001100` is equivelent to `0x8C`, a cool property of XOR is that it is reversable meaning `0x8C ^ 0x2C = 0xA0` and `0x8C ^ 0xA0 = 0x2C`

![XOR Basics](https://ctf101.org/cryptography/images/xor.png)

### What does this have to do with CTF?

XOR is a cheap way to encrypt data with a password. Any data can be encrypted using XOR as shown in this Python example:

`>>> data = 'CAPTURETHEFLAG'
>>> key = 'A'
>>> encrypted = ''.join([chr(ord(x) ^ ord(key)) for x in data])
>>> encrypted
'\x02\x00\x11\x15\x14\x13\x04\x15\t\x04\x07\r\x00\x06'
>>> decrypted = ''.join([chr(ord(x) ^ ord(key)) for x in encrypted])
>>> decrypted
'CAPTURETHEFLAG'`

This can be extended using a multibyte key by iterating in parallel with the data.

### Exploiting XOR Encryption

### Single Byte XOR Encryption

Single Byte XOR Encryption is trivial to bruteforce as there are only 255 key combinations to try.

### Multibyte XOR Encryption

Multibyte XOR gets exponentially harder the longer the key, but if the encrypted text is long enough, character frequency analysis is a viable method to find the key. Character Frequency Analysis means that we split the cipher text into groups based on the number of characters in the key. These groups then are bruteforced using the idea that some letters appear more frequently in the english alphabet than others.

# Hashing Functions

Hashing functions are one way functions which theoretically provide a unique output for every input. MD5, SHA-1, and other hashes which were considered secure are now found to have *collisions* or two different pieces of data which produce the same supposed unique output.

## String Hashing

A string hash is a number or string generated using an algorithm that runs on text or data.

The idea is that each hash should be unique to the text or data (although sometimes it isn’t). For example, the hash for “dog” should be different from other hashes.

You can use command line tools or online resources such as this one. Example: `$ echo -n password | md5 5f4dcc3b5aa765d61d8327deb882cf99` Here, “password” is hashed with different hashing algorithms:

- **SHA-1**: 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
- **SHA-2**: 5E884898DA28047151D0E56F8DC6292773603D0D6AABBDD62A11EF721D1542D8
- **MD5**: 5F4DCC3B5AA765D61D8327DEB882CF99
- **CRC32**: BBEDA74F

Generally, when verifying a hash visually, you can simply look at the first and last four characters of the string.

## File Hashing

A file hash is a number or string generated using an algorithm that is run on text or data. The premise is that it should be unique to the text or data. If the file or text changes in any way, the hash will change.

What is it used for? - File and data identification - Password/certificate storage comparison

How can we determine the hash of a file? You can use the md5sum command (or similar).

`$ md5sum samplefile.txt
3b85ec9ab2984b91070128be6aae25eb samplefile.txt`

## Hash Collisions

A collision is when two pieces of data or text have the same cryptographic hash. This is very rare.

What’s significant about collisions is that they can be used to crack password hashes. Passwords are usually stored as hashes on a computer, since it’s hard to get the passwords from hashes.

![Password to Hash](https://ctf101.org/cryptography/images/hashing-collision-1.png)

If you bruteforce by trying every possible piece of text or data, eventually you’ll find something with the same hash. Enter it, and the computer accepts it as if you entered the actual password.

Two different files on the same hard drive with the same cryptographic hash can be very interesting.

“It’s now well-known that the cryptographic hash function MD5 has been broken,” [said Peter Selinger of Dalhousie University](http://www.mscs.dal.ca/~selinger/md5collision/). “In March 2005, Xiaoyun Wang and Hongbo Yu of Shandong University in China published an article in which they described an algorithm that can find two different sequences of 128 bytes with the same MD5 hash.” [**1**](https://ctf101.org/cryptography/what-are-hashing-functions/#fn:1)

For example, he cited this famous pair:

![Password to Hash](https://ctf101.org/cryptography/images/hashing-collision-2.png)

and

![Password to Hash](https://ctf101.org/cryptography/images/hashing-collision-3.png)

Each of these blocks has MD5 hash 79054025255fb1a26e4bc422aef54eb4.

Selinger said that “the algorithm of Wang and Yu can be used to create files of arbitrary length that have identical MD5 hashes, and that differ only in 128 bytes somewhere in the middle of the file. Several people have used this technique to create pairs of interesting files with identical MD5 hashes.”

Ben Laurie [has a nice website that visualizes this MD5 collision](http://www.links.org/?p=6). For a non-technical, though slightly outdated, introduction to hash functions, see [Steve Friedl’s Illustrated Guide](http://www.unixwiz.net/techtips/iguide-crypto-hashes.html). And [here’s a good article](http://www.forensicmag.com/articles/2008/12/hash-algorithm-dilemma%E2%80%93hash-value-collisions) from DFI News that explores the same topic.

# Ciphers

## Substitution Cipher

Introduction

A Substitution Cipher is system of encryption where different symbols are substituted by a different alphabet. We can take the letter `A` and replace all occurrences with `F`, `B` with `Y`, and so on.

This gives us a key to use with encrypting and decrypting.

**Tip**

We often have to keep track of each individual letter in the alphabet and what they're mapped to. Dictionaries make keeping track of keys in python very easy!

`key = {
    "a": "f",
    "b": "y",
    "c": "a",
    "d": "b",
    "e": "z",
    "f": "c",
    "g": "m",
    "h": "s",
    "i": "n",
    "j": "t",
    "k": "o",
    "l": "h",
    "m": "q",
    "n": "v",
    "o": "r",
    "p": "x",
    "q": "w",
    "r": "i",
    "s": "k",
    "t": "u",
    "u": "l",
    "v": "j",
    "w": "p",
    "x": "g",
    "y": "d",
    "z": "e"
}

secret = "The trouble with having an open mind, of course, is that people will insist on coming along and trying to put things in it.".lower()
secret = filter(str.isalpha, secret)

encrypted = "".join([key[i] for i in secret])
print(encrypted)
#uszuirlyhzpnussfjnvmfvrxzvqnvbrcarlikznkusfuxzrxhzpnhhnvknkurvarqnvmfhrvmfvbuidnvmurxluusnvmknvnu`

### Language Entropy

[xkcd (936)](https://xkcd.com/936/)

Often times, we aren't going to be given a key to the cipher. In these cases, we use a strategy from natural language processing known as language entropy. We're looking to "predict" the occurrence of a certain letter based on it's usage in the language.[**1**](https://ctf101.org/cryptography/what-is-a-substitution-cipher/#fn:1)

For example, knowing "vowels are used in most words" gives you a hint that reduces the computation complexity when we attempt to "guess" the usage of certain letters.

With this in mind, there are algorithms that use these clues to give you a "best estimate" what the original phrase.

**Info**

In 1948, Claude Shannon published the first paper on the entropy of the English language. Modern natural language processing algorithms still cite the original research. Read the paper [here](https://people.math.harvard.edu/~ctm/home/text/others/shannon/entropy/entropy.pdf).

If you're interested in language and information theory, there's a fascinating book on natural language processing in the footnotes!.[**2**](https://ctf101.org/cryptography/what-is-a-substitution-cipher/#fn:2)

### Example

**Substitution cipher without a key**

Without the key used to create the cipher, we can only try bruteforcing the combinations using the English language. Using the sample below, we can use a tool like [quipqiup.com](https://quipqiup.com/) to bruteforce what the original text is.

`Rbo rpktigo vcrb bwucja wj kloj hcjd, km sktpqo, cq rbwr loklgo 
vcgg cjqcqr kj skhcja wgkja wjd rpycja rk ltr rbcjaq cj cr.`

![Cryptogram Example](https://ctf101.org/cryptography/images/quipqiup.gif)

Our best guess at what the original phrase is:

`The trouble with having an open mind, of course, is that people 
will insist on coming along and trying to put things in it.`

## Caesar Cipher/ROT 13

### Caesar Cipher

The Caesar Cipher or Caesar Shift is a cipher which uses the alphabet in order to encode texts. The idea is to encode each letter with another letter in a "fixed" set of shifts.

**Info**

`CAESAR` encoded with a shift of 8 is `KIMAIZ` so `ABCDEFGHIJKLMNOPQRSTUVWXYZ` becomes `IJKLMNOPQRSTUVWXYZABCDEFGH`

Breaking a ciphertext is incredibly easy as there are only 25 possible "shifts" in the English alphabet.

### **Bruteforce?**

We can use a tool like [cyberchef](https://gchq.github.io/CyberChef/#recipe=ROT13(true,true,false,13)) to do this quickly but can also print out all the combinations in Python.

`secret = "iwtgt xh cd gxvwi pcs lgdcv. iwtgth dcan ujc pcs qdgxcv.".lower()
for i in range(0, 26):
    decrypted_string = ""
    for j in range(0, len(secret)):
        letter = ord(secret[j])
        if (letter > 122) or (letter < 97) or secret[j] == " ":
            continue
        else:
            letter += 1
            if letter > 122:
                letter = 97
            letter = chr(letter)
            decrypted_string += str(letter)  
    secret = decrypted_string.strip()  
    print(decrypted_string)

#output
#...
#thereisnorightandwrongtheresonlyfunandboring
#...`

### ROT13

ROT13("Rotate 13") is the same thing but a fixed shift of 13, this is a trivial cipher to bruteforce because there are only 25 shifts.

Generally, Caesar's Cipher and ROT13 are used in conjunction of other encryption methods to make the challenge more difficult!

## Vigenere Cipher

A Vigenere Cipher is an extended [Caesar Cipher](https://ctf101.org/cryptography/what-is-caesar-cipher-rot-13/) where a message is encrypted using various Caesar shifted alphabets. A `key` is used to determine how many shifts each letter receives. It adds an additional layer of complexity that relies on the shared key instead of a predetermined shift length.

**Example**

We'll use the following table can be used to encode a message:

![Vigenere Square](https://ctf101.org/cryptography/images/vigenere-square.png)

### Encryption

Plaintext: `SUPERSECRET`

KEY: `CODE`

1. `CODE` gets padded to the length of `SUPERSECRET` so the key becomes `CODECODECOD`.
2. For each letter in `SUPERSECRET` we use the table to get the Alphabet to use, in this instance row `C` and column `S`.
3. The ciphertext's first letter then becomes `U`.
4. We eventually get `UISITGHGTSW`.

### Decryption

1. Go to the row of the key, in this case `C`
2. Find the letter of the cipher text in this row, in this case `U`
3. The column is the first letter of the decrypted ciphertext, so we get `S`
4. After repeating this process we get back to `SUPERSECRET`

### Cryptanalysis

The key part of breaking a Vigenere Cipher is (not a pun) the key itself. Because it repeats, it's vulnerable to brute forcing the rotation by figuring out what the length of the key is. After, frequency analysis or key elimination is used to reverse the secret. We're not going to cover it here, but check out the footnotes for more![**2**](https://ctf101.org/cryptography/what-is-a-vigenere-cipher/#fn:2)

Online cipher solvers automatically use these steps!

**Info**

For more information on how to determine the key length, check out this video on the [Kasiski Examination](https://www.youtube.com/watch?v=asRbswE2hFY).

Modes of Operation