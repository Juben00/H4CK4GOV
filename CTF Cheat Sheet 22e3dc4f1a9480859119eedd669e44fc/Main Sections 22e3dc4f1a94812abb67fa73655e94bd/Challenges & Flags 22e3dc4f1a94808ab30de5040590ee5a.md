# Challenges & Flags

## **General Overview**

This page serves as the team’s central archive of **CTF challenge writeups**  organized by category, clearly documented, and written for both review and learning.

### Cryptography

### PicoCTF

- **hashcrack (Easy)**
    
    Author: Nana Ama Atombo-Sackey
    
    ### Description
    
    A company stored a secret message on a server which got breached due to 
    the admin using weakly hashed passwords. Can you gain access to the 
    secret stored within the server?
    Access the server using `nc verbal-sleep.picoctf.net 52518`
    
    Solution
    
    After I accessed the site, I was given a hash. Since I was new and didnt really know what type it was just by seeing it. I googled what type of hash was. So the first hash was a MD5 hash. My initial thought was to use cyberchef to solve them but as it turns out. It did not work. So I went to use hashcat, and I dont currently know how the mode operates but I was able to crack the following hashes using hashcat:
    
    1. MD5 - 482c811da5d5b4bc6d497ffa98491e38 = password123
    2. SHA-1 - b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3 = letmein
    3. SHA-256 - 916e8c4f79b25028c9e467f1eb8eee6d6bbdff965f9928310ad30a8d88697745 = qwerty098
    
    and after inputting the following hashed passwords, I was given the flag.
    
    picoCTF{UseStr0nG_h@shEs_&PaSswDs!_70ffa57c}
    
- **EVEN RSA CAN BE BROKEN??? (Easy)**
    
    Author: Michael Crotty
    
    ### Description
    
    This service provides you an encrypted flag. Can you decrypt it with just N & e?
    Connect to the program with netcat:
    `$ nc verbal-sleep.picoctf.net 52407`The program's source code can be downloaded [here](https://challenge-files.picoctf.net/c_verbal_sleep/ef25235cb9efed04bd4c2cd6b848767037def35056180386b48654bfaf6e20e5/encrypt.py).
    
    Solution:
    
    After launching the terminal and accessing the program, I was provided with the key components of an RSA encryption scheme: the modulus `n`, the public exponent `e`, and the ciphertext `c`.
    
    Since all the essential values were already given, I initially considered using a built-in tool on Kali Linux to solve the challenge. However, due to unfamiliarity with the tool’s usage at the time, I opted for a quicker approach and used an **online RSA decryption tool**.
    
    After inputting `n`, `e`, and `c` into the decoder, I was able to successfully recover the plaintext. The decryption revealed the flag without any additional computation or exploitation.
    
    picoCTF{tw0_1$_pr!m3605cd50e}
    
- **interencdec (Easy)**
    
    Author: NGIRIMANA Schadrack
    
    ### Description
    
    Can you get the real meaning from this file.
    Download the file [here](https://artifacts.picoctf.net/c_titan/1/enc_flag).
    
    Solution:
    
    In this challenge, I was given an ASCII file containing a Base64-encoded string: `YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclgyMHdNakV5TnpVNGZRPT0nCg==`. After decoding it using CyberChef, I obtained another Base64-like string: `b'd3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrX2xoNjBsMDBpfQ=='`. I noticed the `b'...'` wrapper, which is typical of a Python byte string, so I removed it to isolate the actual encoded data: `d3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrX2xoNjBsMDBpfQ==`. Decoding this again gave me `wpjvJAM{jhlzhy_k3jy9wa3k_lh60l00i}`, which looked like a Caesar cipher. I then used an online Caesar cipher decoder to try all possible shifts and successfully recovered the flag: `picoCTF{caesar_d3cr9pt3d_f0212758}`.
    
- **Mod 26 (Easy)**
    
    Author: Pandu
    
    ### Description
    
    Cryptography can be easy, do you know what ROT13 is? `cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_jdJBFOXJ}`
    
    Solution:
    
    For this challenge, I simply used an online ROT13 decoder. After pasting the given string into the tool, it immediately returned the decrypted flag: `picoCTF{next_time_I'll_try_2_rounds_of_rot13_wqWOSBKW}`.
    
- **The Numbers (Easy)**
    
    Author: Danny
    
    ### Description
    
    The [numbers](https://jupiter.challenges.picoctf.org/static/f209a32253affb6f547a585649ba4fda/the_numbers.png)... what do they mean?
    
    After clicking the provided link, I received a PNG file that displayed a sequence of numbers. From the format, it appeared to be encoded using the A1Z26 cipher, where each number corresponds to a letter of the alphabet (1 = A, 2 = B, ..., 26 = Z). After manually decoding the sequence, I successfully extracted the flag: `PICOCTF{THENUMBERSMASON}`
    
- **13 (Easy)**
    
    Author: Alex Fulton/Daniel Tunitis
    
    ### Description
    
    Cryptography can be easy, do you know what ROT13 is? `cvpbPGS{abg_gbb_onq_bs_n_ceboyrz}`
    
    Solution:
    
    For this challenge, the flag was already provided but encrypted using ROT13: `cvpbPGS{abg_gbb_onq_bs_n_ceboyrz}`. I used CyberChef to decode it by applying the ROT13 operation, which revealed the plaintext flag: `picoCTF{not_too_bad_of_a_problem}`
    
- **Guess My Cheese (Part 2) (Medium)**
    
    Author: aditin
    
    ### Description
    
    The imposter was able to fool us last time, so we've strengthened our defenses!
    Here's our [list](https://challenge-files.picoctf.net/c_verbal_sleep/051e587a3f7f180d6de145a9e01035c125cd6a1ad25872ebb5ada6e09a2f3f91/cheese_list.txt) of cheeses.
    Connect to the program on our server: `nc verbal-sleep.picoctf.net 49770`
    
    Solution:
    
    After connecting to the server, I was given a SHA-256 hash and a list of cheese names. It looked like the hash was generated using one of the cheese names plus a salt, but I wasn’t told how the salt was used — could be appended, prepended, inserted, raw byte or hex string, different encodings, different casing — so brute-forcing manually was out of the question. To speed things up, I wrote a Python script that looped through each cheese name, tried different case versions (original, lower, upper), encoded them in various formats (`utf-8`, `utf-16`, etc.), and combined them with every possible single-byte salt (0x00 to 0xFF). I tested different salt placements like appending, prepending, or inserting it anywhere in the string, both as raw bytes and as hex-encoded strings. Eventually, the script found the right combination — cheese + salt — that produced the target hash. I submitted both values to the server, and it gave me the flag: `picoCTF{cHeEsYebdfa2be}`.
    
- **Guess My Cheese (Part 1) (Medium)**
    
    Author: aditin
    
    ### Description
    
    Try to decrypt the secret cheese password to prove you're not the imposter!
    Connect to the program on our server: `nc verbal-sleep.picoctf.net 53407`
    
    Solution:
    
    After connecting to the server, I was greeted by a rat that gave me a hash and two options: "guess the cheese" or "encrypt first." I checked the hash and noticed it looked like it came from an Affine cipher, which meant I could probably solve it using an online tool. I chose the "encrypt first" option and decided to try the word `cheddar` as my guess. After playing around with Affine cipher calculators and finding the right encryption formula (same structure as the given hash), I matched the result and submitted my guess using the "guess" option. It worked — the server accepted it and gave me the flag: `picoCTF{ChEeSy696d4adc}`.
    
- **rsa_oracle (Medium)**
    
    Author: Geoffrey Njogu
    
    ### Description
    
    Can you abuse the oracle?
    An attacker was able to intercept communications between a bank and a fintech company. They managed to get the [message](https://artifacts.picoctf.net/c_titan/150/secret.enc) (ciphertext) and the [password](https://artifacts.picoctf.net/c_titan/150/password.enc) that was used to encrypt the message.
    
    Additional details will be available after launching your challenge instance.
    
    Solution:
    
    Since the rsa oracle was able to encrypt and decrypt any plaintext that was sent to their server, that made the idea of checking to see what was missing. Since the formula to get the password is m ^ e mod n. And when we encrypt we get the m. The only issue we would need is finding the n. Now I first encrypted 2 to test if it would work with small numbers. And then I realized that it did. Now since it gave me its hex. We would be able to solve it. Now to find the n. I encrypted 1, since the 2 would be greater. We could think of n as 1. So after we got the n. We now just had to do the formula of m ^ e mod n. After getting it we would then multiply it by 2 and after that we would be able to decrpyt this into the server. Since the password is hidden inside another hex, the machine would not be able to detect it and would give me the hex. After that, since it gave me the hex of the combined encryption. I would just need to divide the it by 2 to remove the hidden hex. After that we would decode it using asc and we would then get the password being.
    
    password:60f50
    
    after that we would just need to open the secret.enc file using the key we got from decoding the password
    so doi
    
    This challenge was an RSA oracle — it let me encrypt and decrypt any plaintext I sent to the server. That immediately suggested a potential vulnerability: if I could interact with the encryption and decryption endpoints freely, I might be able to reverse-engineer or manipulate values to leak sensitive information.
    
    The formula for RSA encryption is `c = m^e mod n`, where `m` is the message, `e` is the public exponent, and `n` is the modulus. The tricky part was that `n` wasn’t given — but I could send small integers to the encrypt endpoint and observe the outputs to gather clues.
    
    I started by encrypting `2`, just to confirm the oracle worked and returned a valid ciphertext. It did. Then I tried encrypting `1`, and from the result I noticed something interesting: since `1^e mod n` is always `1` for any `e` and `n`, if I got a ciphertext of `1`, I could deduce something about `n` based on the comparison between ciphertexts of `1` and `2`. This gave me a starting point to estimate or work around the unknown modulus `n`.
    
    The core trick was this: I encrypted a small message (like `m = 2`) and later used the decryption oracle to decrypt a manipulated ciphertext that was derived from multiplying the target ciphertext by an encrypted value of `1/2 mod n`. Since the password was hidden inside another hex-encoded structure, this manipulation allowed me to bypass the basic filtering and retrieve the decrypted content as hex.
    
    Once I had the result, I simply divided the decrypted hex value by `2` to strip out the padding/manipulation and get the clean result. After converting it from hex to ASCII, I got the password: `60f50`.
    
    With that password, I used OpenSSL to decrypt the provided file:
    
    `openssl enc -aes-256-cbc -d -in secret.enc -k 60f50`
    
    It threw a warning about deprecated key derivation, but it worked — and finally gave me the flag:
    
    `picoCTF{su((3ss_(r@ck1ng_r3@_60f50766}`
    
- **Custom encryption (Medium)**
    
    Author: NGIRIMANA Schadrack
    
    ### Description
    
    Can you get sense of this code file  and write the function that will decode the given encrypted file content.
    Find the encrypted file here [flag_info](https://artifacts.picoctf.net/c_titan/94/enc_flag) and  [code file](https://artifacts.picoctf.net/c_titan/94/custom_encryption.py) might be good to analyze and get the flag.
    
    Solution:
    
    This challenge was all about understanding how the custom encryption algorithm worked. The key to solving it was analyzing the provided Python file, which contained the encryption logic, along with a cipher data file that gave me the `a`, `b`, and the ciphertext. The idea was simple: if I could fully understand how the data was encrypted, I could reverse the process and decrypt it manually.
    
    So I started by digging into the encryption code. Once I figured out how the original message was transformed—step by step—I wrote my own decryption script that essentially reversed each operation. By applying the inverse logic using the same `a` and `b` values, I was able to reconstruct the original plaintext from the ciphertext.
    
    The result was the flag:
    
    `picoCTF{custom_d2cr0pt6d_66778b34}`
    
- **Mr-Worldwide (Medium)**
    
    Author: Danny
    
    ### Description
    
    A musician left us a [message](https://jupiter.challenges.picoctf.org/static/d5570d48262dbba2a31f2a940409ad9d/message.txt). What's it mean?
    
    Solution:
    
    After receiving the text file, I noticed the flag was encrypted using GPS coordinates. When I pasted them into Google Maps, I got locations corresponding to different cities and countries. The flag looked like this:
    
    `picoCTF{(35.028309, 135.753082)(46.469391, 30.740883)(39.758949, -84.191605)(41.015137, 28.979530)(24.466667, 54.366669)(3.140853, 101.693207)_(9.005401, 38.763611)(-3.989038, -79.203560)(52.377956, 4.897070)(41.085651, -73.858467)(57.790001, -152.407227)(31.205753, 29.924526)}`
    
    At first, I couldn’t figure out what to do with the locations and spent a few minutes stuck. After checking a writeup by another solver, I realized the trick: I needed to identify the **countries** for each coordinate and then take the **first letter of each country** to spell out the hidden message. Doing that revealed the final flag:
    
    `picoCTF{KODIAK_ALASKA}`
    
- **Rotation (Medium)**
    
    Author: Loic Shema
    
    ### Description
    
    You will find the flag after decrypting this file
    Download the encrypted flag [here](https://artifacts.picoctf.net/c/387/encrypted.txt).
    
    Solution:
    
    For this challenge, I just simply used a ceasar cipher decoder
    
    picoCTF{r0tat1on_d3crypt3d_949af1a1}
    
- **ReadMyCert (Medium)**
    
    Author: Sunday Jacob Nwanyim
    
    ### Description
    
    How about we take you on an adventure on exploring certificate signing requests
    Take a look at this CSR file [here](https://artifacts.picoctf.net/c/424/readmycert.csr).
    
    Solution:
    
    So for this challenge, I just opened the file and it displayed the flag immediately 
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image.png)
    
    picoCTF{read_mycert_5aeb0d4f}
    
- **HideToSee (Medium)**
    
    Author: Sunday Jacob Nwanyim
    
    ### Description
    
    How about some hide and seek heh?
    Look at this image [here](https://artifacts.picoctf.net/c/241/atbash.jpg).
    
    Solution:
    
    I was given a .jpg file. Now looking at the file resulted in nothing. Even using the following tools file, exiftool, binwalk, and zsteg gave me nothing. But then I used steghide 
    
    “steghide extract -sf atbash.jpg”
    
    and it gave me a text file that contained a encrypted flag. knowing that it is related to the atbash cipher I used cyberchef to decrypt it.
    
    krxlXGU{zgyzhs_xizxp_7142uwv9}
    
    and becomes 
    
    picoCTF{atbash_crack_7142fde9}
    
    ![atbash.jpg](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/atbash.jpg)
    
- **Vigenere (Medium)**
    
    Author: Mubarak Mikail
    
    ### Description
    
    Can you decrypt this message?
    Decrypt this [message](https://artifacts.picoctf.net/c/160/cipher.txt) using this key "CYLAB".
    
    Solution:
    
    So for this challenge, it gave me a text file that contains the encrypted flag. Now to decode this, we needed to use the vignere cipher and since the description gave me the key to use being “CYLAB”. I was able to decrypt it from.
    
    rgnoDVD{O0NU_WQ3_G1G3O3T3_A1AH3S_2951c89f}
    
    to
    
    picoCTF{D0NT_US3_V1G3N3R3_C1PH3R_2951a89h}
    
- **transposition-trial (Medium)**
    
    Author: Will Hong
    
    ### Description
    
    Our
     data got corrupted on the way here. Luckily, nothing got replaced, but 
    every block of 3 got scrambled around! The first word seems to be three 
    letters long, maybe you can use that to recover the rest of the message.
    Download the corrupted message [here](https://artifacts.picoctf.net/c/192/message.txt).
    
    Solution:
    
    Every block of 3 in the message got scrambled around. From the first three letters (and the following words like `flag`, `is`,`pico`), we can tell that the plain text should be printed in the order of 2,3,1.
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%201.png)
    
    Write a Python script to print the flag
    
    flag="heTfl g as iicpCTo{7F4NRP051N5_16_35P3X51N3_V091B0AE}2"
    for i in range(0,len(flag),3):
    print(flag[i+2],flag[i],flag[i+1], sep="",end="")
    
    after using the python code we get the decoded flag of .
    
    picoCTF{7R4N5P051N6_15_3XP3N51V3_109AB02E}
    
- **substitution2 (Medium)**
    
    Author: Will Hong
    
    ### Description
    
    It seems that another encrypted message has been intercepted. The encryptor
    seems to have learned their lesson though and now there isn't any punctuation!
    Can you still crack the cipher?
    Download the message [here](https://artifacts.picoctf.net/c/113/message.txt).
    
    Solution:
    
    So for this, I just used a online tool to solve this seems like it used monoalphabets for it to be ciphered
    
    PICOCTF{N6R4M_4N41Y515_15_73D10U5_702F03FC}
    
- **substitution1 (Medium)**
    
    Author: Will Hong
    
    ### Description
    
    A second message has come in the mail, and it seems almost identical to the first one. Maybe the same thing will work again.
    Download the message [here](https://artifacts.picoctf.net/c/181/message.txt).
    
    Solution:
    
    i used another online tool for this seems like it uses substitution
    
    PICOCTF{FR3QU3NCY_4774CK5_4R3_C001_4871E6FB}
    
- **C3 (Medium)**
    
    Author: Matt Superdock
    
    ### Description
    
    This is the Custom Cyclical Cipher!
    Download the ciphertext [here](https://artifacts.picoctf.net/c_titan/47/ciphertext).
    Download the encoder [here](https://artifacts.picoctf.net/c_titan/47/convert.py).
    Enclose the flag in our wrapper for submission. If the flag was "example" you
    would submit "picoCTF{example}".
    
    Solution:
    
    Let’s see the contents of the convert.py to see what is going on
    
    Zoom image will be displayed
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*WydmlnW97Jp8al6FYgLN9A.png)
    
    After reading the code it feels like the script is trying to cipher some characters from the given input. Hmmm, let’s try to decipher it and see  what happens. Here is my decipher script which tries to get back the character which was ciphered:
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*pG0Q-aa5RJDW0XUIx4lb1w.png)
    
    Let’s use this script and try to get the original data back:
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*uo6WEMghraeKt3YbA7uaaw.png)
    
    This is interseting, a python script?!. Now lets try to run this python script on itself, meaning this time the ciphertext will be the script itself. The reason behind this is that the question itself says that this is a custom cyclical cipher, so it can be the case that the flag is the deciphered output of the python script on itself. Let’s pipe the 
    output into a file and we will use that file as a ciphered file.
    
    Here I made some modification to the output which we got above and used that as a new python script and ran it on the original output from the given ciphertext:
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*xnXJKvYdiuQoq5NAsksn_w.png)
    
    We finally got the flag. The flag is: picoCTF{adlibs}
    
    `picoCTF{adlibs}`
    
- **substitution0 (Medium)**
    
    Author: Will Hong
    
    ### Description
    
    A message has come in but it seems to be all scrambled. Luckily it seems to
    have the key at the beginning. Can you crack this substitution cipher?
    Download the message [here](https://artifacts.picoctf.net/c/152/message.txt).
    
    Solution:
    
    So for this challenge, we are given a encrypted message along side its key. Since we area already given the key. We just use the key alongside the ciphertext to be able to decode the problem.
    
    PICOCTF{5UB5717U710N_3V0LU710N_59533A2E}
    
- **rail-fence (Medium)**
    
    Author: Will Hong
    
    ### Description
    
    A type of transposition cipher is the rail fence cipher, which is described
    [here](https://en.wikipedia.org/wiki/Rail_fence_cipher). Here is one such
    cipher encrypted using the rail fence with 4 rails. Can you decrypt it?
    Download the message [here](https://artifacts.picoctf.net/c/189/message.txt).
    Put the decoded message in the picoCTF flag format, `picoCTF{decoded_message}`.
    
    Solution:
    
    So to solve this challenge, I opened cyberchef and since we already know what type of cipher this is we can safely decode it slowly(bruteforce lol)
    
    The decoded flag we got is 
    
    The flag is: WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_83F6D8D7
    
    now to wrap it with the flag format of picoCTF{}
    
    picoCTF{WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_83F6D8D7}
    
- **morse-code (Medium)**
    
    Author: Will Hong
    
    ### Description
    
    Morse code is well known. Can you decrypt this?
    Download the file [here](https://artifacts.picoctf.net/c/79/morse_chal.wav).
    Wrap your answer with picoCTF{}, put underscores in place of pauses, and use
    all lowercase.
    
    Solution:
    
    Instead of Audacity, I used to upload the provided morse-code audio file to the [Morse Audio Decoder](https://morsecode.world/international/decoder/audio-decoder-expert.html).
    
    picoCTF{wh47_h47h_90d_w20u9h7}
    
- **credstuff (Medium)**
    
    Author: Will Hong / LT 'syreal' Jones
    
    ### Description
    
    We found a leak of a blackmarket website's login credentials. Can you find the
    password of the user `cultiris` and successfully decrypt it?
    Download the leak [here](https://artifacts.picoctf.net/c/151/leak.tar).
    The first user in `usernames.txt` corresponds to the first password in
    `passwords.txt`. The second user corresponds to the second password, and so on.
    
    Solution:
    
    In this one, I was given two files: `usernames.txt` and `passwords.txt`. Right off the bat, I figured it’s one of those challenges where each line in both files correspond — meaning `usernames[0]` matches with `passwords[0]`, `usernames[1]` with `passwords[1]`, and so on.
    
    So the first step was to locate the specific user mentioned in the challenge: **cultiris**.
    
    I used `grep` to find which line the user was on:
    
    `grep -n cultiris usernames.txt`
    
    That gave me the line number — let’s say line **X**. Since the usernames and passwords align by line, I just had to check **line X** in `passwords.txt`.
    
    Sure enough, I found this string: `cvpbPGS{P7e1S_54I35_71Z3}`
    
    It looked like a flag but was clearly obfuscated. Based on the structure and letter shifting, I recognized it as **ROT13** (a simple Caesar cipher that shifts letters by 13 positions).
    
    I tossed it into CyberChef with the ROT13 operation, and got:
    
    `picoCTF{C7r1F_54V35_71M3}`
    
- **basic-mod2 (Medium)**
    
    Author: Will Hong
    
    ### Description
    
    A new modular challenge!
    Download the message [here](https://artifacts.picoctf.net/c/178/message.txt).
    Take each number mod 41 and find the modular inverse for the result. Then map
    to the following character set: 1-26 are the alphabet, 27-36 are the decimal
    digits, and 37 is an underscore.
    Wrap your decrypted message in the picoCTF flag format
    (i.e. `picoCTF{decrypted_message}`)
    
    Solution:
    
    For this challenge, we were given a list of numbers that looked pretty random at first, but the title hinted at something involving modular arithmetic. With a bit of experimenting, I figured the trick was to take each number, reduce it modulo 41, then compute its **modular inverse** mod 41 — that is, finding the number `x` such that `(x * inv_x) % 41 == 1`.
    
    I wrote a quick Python script to do this. Each inverse was then mapped to a character using a custom scheme:
    
    - `1–26` → `'a'` to `'z'`
    - `27–36` → `'0'` to `'9'`
    - `37` → `'_'`
    
    Once the inverses were mapped back to characters, they spelled out the flag. Here's the script I used:
    
    flag = [432, 331, 192, 108, 180, 50, 231, 188, 105, 51, 364, 168, 344, 195, 297, 342, 292, 198, 448, 62, 236, 342, 63]
    
    def modinv(x, m):
    try:
    return pow(x, -1, m)
    except ValueError:
    return None
    
    def inverse_to_char(inv):
    if inv is None:
    return '?'
    if 1 <= inv <= 26:
    return chr(ord('a') + inv - 1)
    elif 27 <= inv <= 36:
    return chr(ord('0') + inv - 27)
    elif inv == 37:
    return '_'
    else:
    return '?'
    
    mod_vals = [x % 41 for x in flag]
    inverses = [modinv(x, 41) for x in mod_vals]
    decoded_chars = [inverse_to_char(inv) for inv in inverses]
    
    print("".join(decoded_chars))
    
    And the output? The cleanly decrypted flag:
    
    **`picoCTF{1nv3r53ly_h4rd_c680bdc1}`**
    
- **basic-mod1 (Medium)**
    
    Author: Will Hong
    
    ### Description
    
    We found this weird message being passed around on the servers, we think we
    have a working decryption scheme.
    Download the message [here](https://artifacts.picoctf.net/c/127/message.txt).
    Take each number mod 37 and map it to the following character set: 0-25 is the
    alphabet (uppercase), 26-35 are the decimal digits, and 36 is an underscore.
    Wrap your decrypted message in the picoCTF flag format
    (i.e. `picoCTF{decrypted_message}`)
    
    Solution:
    
    In this challenge, we were given a list of numerical values and needed to decode them into readable characters to reveal the flag. The hint was in the structure of the values and the name "round" — which suggested using modular arithmetic.
    
    ### Step-by-Step Breakdown:
    
    1. **Modulus Operation**: Each number was reduced modulo 37 — meaning we calculated `x % 37` for every number in the list.
    2. **Character Mapping Rule**:
        - **0 to 25** → Uppercase letters `A–Z`
        - **26 to 35** → Digits `0–9`
        - **36** → Underscore `_`
    
    This mapping scheme is common in CTFs, especially when flags use uppercase characters, digits, and underscores.
    
    ## **mod_solver.py**
    
    flag = [128 ,322 ,353 ,235 ,336 ,73 ,198 ,332 ,202 ,285 ,57 ,87 ,262 ,221 ,218 ,405 ,335 ,101 ,256 ,227 ,112 ,140]
    
    # Mapping function for mod to character
    
    def mod_to_char(mod_vals):
    if mod_vals is None:
    return '?'  # Placeholder for undefined inverse
    if 0 <= mod_vals <= 25:
    return chr(ord('a') + mod_vals)
    elif 26 <= mod_vals <= 35:
    return chr(ord('0') + mod_vals - 26)
    elif mod_vals == 36:
    return '_'
    else:
    return '?'  # Out-of-range inverse
    
    # Main processing
    
    mod_vals = [x % 37 for x in flag]
    decoded_chars = [mod_to_char(mod_vals) for mod_vals in mod_vals]
    
    # Print results
    
    print("Mod 37 values:     ", mod_vals)
    print("Decoded characters:", ''.join(decoded_chars))
    
    picoCTF{r0und_n_r0und_79c18fb3}
    
- **spelling-quiz (Medium)**
    
    Author: BrownieInMotion
    
    ### Description
    
    I found the flag, but my brother wrote a program to encrypt all his text 
    files. He has a spelling quiz study guide too, but I don't know if that 
    helps.
    
    Solution:
    
    From the source code we see that the script encrypted both the flag and the study guide with a simple substitution cipher using a random key. So, we just need to find a key which decrypts the study guide to a sensible result.
    
    [subbreaker](https://gitlab.com/guballa/SubstitutionBreaker) can easily break the substitution cipher with just a subset of the words:
    
    ```
    ┌──(user@kali)-[/media/sf_CTFs/pico/spelling-quiz]
    └─$ subbreaker break --lang EN --ciphertext <(cat public/study-guide.txt | head -n 50)
    Alphabet: abcdefghijklmnopqrstuvwxyz
    Key:      xunmrydfwhglstibjcavopezqk
    Fitness: 92.78
    Nbr keys tried: 6175
    Keys per second: 3418
    Execution time (seconds): 1.807
    Plaintext:
    kurchicine
    malfeasor
    greenheart
    baptistry
    litorinoid
    vindicatory
    ```
    
    Let's use the key to decipher the flag:
    `└─$ subbreaker decode --key xunmrydfwhglstibjcavopezqk --ciphertext public/flag.txt
    perhaps_the_dog_jumped_over_was_just_tired`
    
    `picoCTF{perhaps_the_dog_jumped_over_was_just_tired}`
    
- **la cifra de (Medium)**
    
    Author: Alex Fulton/Daniel Tunitis
    
    ### Description
    
    I found this cipher in an old book. Can you figure out what it says? Connect with `nc jupiter.challenges.picoctf.org 5726`.
    
    Solution:
    
    for this challenge, to be able to solve it. We would have to use the vignere cypher and using the key as flag
    
    picoCTF{b311a50_0r_v1gn3r3_c1ph3r6fe60eaa}
    
- **Flags (Medium)**
    
    Author: Danny
    
    ### Description
    
    What do the [flags](https://jupiter.challenges.picoctf.org/static/fbeb5f9040d62b18878d199cdda2d253/flag.png) mean?
    
    Solution:
    
    To solve this we have to use the signal flags to decrypt this flags.
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%202.png)
    
    PICOCTF{F1AG5AND5TUFF}
    
- **Mini RSA (Medium)**
    
    Author: Sara
    
    ### Description
    
    What happens if you have a small exponent? There is a twist though, we 
    padded the plaintext so that (M ** e) is just barely larger than N. 
    Let's decrypt this: [ciphertext](https://mercury.picoctf.net/static/387dc6431820338cc74324cc5cc9550f/ciphertext)
    
    Solution:
    
    So to solve this, we must consider the **Low Exponent Attack (No Padding), this means that e has a smaller value that will result in a more vulnerable security.** And that the plaintext is small enough that with the exploit we can figure this within 4000 range
    
    # TAKE NOTE
    
    **This kind of attack works only when:**
    
    - **RSA exponent `e` is very small (typically 3).**
    - **The plaintext is small.**
    - **No padding scheme (like OAEP or PKCS#1) is used.**
    - **`m^e` is just slightly larger than `N`.**
    
    For the script we simply did 
    
    """This code will only work if e is small. Only use this with small valued e """"
    from Crypto.Util.number import *
    n = 1615765684321463054078226051959887884233678317734892901740763321135213636796075462401950274602405095138589898087428337758445013281488966866073355710771864671726991918706558071231266976427184673800225254531695928541272546385146495736420261815693810544589811104967829354461491178200126099661909654163542661541699404839644035177445092988952614918424317082380174383819025585076206641993479326576180793544321194357018916215113009742654408597083724508169216182008449693917227497813165444372201517541788989925461711067825681947947471001390843774746442699739386923285801022685451221261010798837646928092277556198145662924691803032880040492762442561497760689933601781401617086600593482127465655390841361154025890679757514060456103104199255917164678161972735858939464790960448345988941481499050248673128656508055285037090026439683847266536283160142071643015434813473463469733112182328678706702116054036618277506997666534567846763938692335069955755244438415377933440029498378955355877502743215305768814857864433151287
    c = 1220012318588871886132524757898884422174534558055593713309088304910273991073554732659977133980685370899257850121970812405700793710546674062154237544840177616746805668666317481140872605653768484867292138139949076102907399831998827567645230986345455915692863094364797526497302082734955903755050638155202890599808146956044568639690002921620304969196755223769438221859424275683828638207433071955615349052424040706261639770492033970498727183446507482899334169592311953247661557664109356372049286283480939368007035616954029177541731719684026988849403756133033533171081378815289443019437298879607294287249591634702823432448559878065453908423094452047188125358790554039587941488937855941604809869090304206028751113018999782990033393577325766685647733181521675994939066814158759362046052998582186178682593597175186539419118605277037256659707217066953121398700583644564201414551200278389319378027058801216150663695102005048597466358061508725332471930736629781191567057009302022382219283560795941554288119544255055962
    
    def find_invpow(x, n):
    """Finds the integer component of the n-th root of x."""
    high = 1
    while high ** n < x:
    high *= 2
    low = high // 2
    while low < high:
    mid = (low + high) // 2
    if low < mid and mid ** n < x:
    low = mid
    elif high > mid and mid ** n > x:
    high = mid
    else:
    return mid
    return mid + 1
    
    # You need to define N and c before this
    
    # Example: N = 123456789, c = 987654321
    
    for i in range(4000):
    candidate = find_invpow(i * n + c, 3)
    flag = long_to_bytes(candidate)
    if b'pico' in flag:
    f = flag.decode(errors='ignore').strip()
    print(f)
    break
    
    picoCTF{e_sh0u1d_b3_lArg3r_6e2e6bda}
    
- **caesar (Medium)**
    
    Author: Sanjay C/Daniel Tunitis
    
    ### Description
    
    Decrypt this [message](https://jupiter.challenges.picoctf.org/static/6385b895dcb30c74dbd1f0ea271e3563/ciphertext).
    
    Solution:
    
    Just use caesar shift cipher to decode the flag inside the brackets.
    
    from 
    
    {dspttjohuifsvcjdpoabrkttds}                                                                                          
    
    to
    
    {crossingtherubiconzaqjsscr}  
    
- **john_pollard (Medium)**
    
    Author: Samuel S
    
    ### Description
    
    Sometimes RSA [certificates](https://jupiter.challenges.picoctf.org/static/c882787a19ed5d627eea50f318d87ac5/cert) are breakable
    
    Solution:
    
    To solve this, we just need to figure out the p and q of the cert. so to find out modulus of the cert, we do the following
    
    openssl x509 -in cert -text -noout
    and it gives us 
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%203.png)
    
    With the modulus given, we can either create a script to figure out the p and q or just use a online tool. (I used the online tool lol)
    
    so with the modulus being **Modulus: 4966306421059967 (0x11a4d45212b17f)**
    
    we can get the p and q being 
    
    4966 306421 059967 = 67 867967 × 73 176001 
    
    now to just figure out if its p,q or q,p. so we got the flag being q,p
    
    picoCTF{73176001,67867967}
    
- **Mind your Ps and Qs (Medium)**
    
    Author: Sara
    
    ### Description
    
    In RSA, a small `e` value can be problematic, but what about `N`? Can you decrypt this? [values](https://mercury.picoctf.net/static/51d68e61bb41207a55f24e753f07c5a3/values)
    
    Solution:
    
    To solve this, we used the tool RSACtfTool, using this tool we gave the following key components being. n,e and c(ciphertext). so to decode this. e
    
    RsaCtfTool -n 1280678415822214057864524798453297819181910621573945477544758171055968245116423923 -e 65537 --decrypt 62324783949134119159408816513334912534343517300880137691662780895409992760262021
    
    and with this line of command we were able to get the flag being.
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%204.png)
    
    picoCTF{sma11_N_n0_g0od_05012767}
    
- **Tapping (Medium)**
    
    Author: Danny
    
    ### Description
    
    Theres tapping coming in from the wires. What's it saying 
    
    `nc jupiter.challenges.picoctf.org 9422`.
    
    Solution:
    
    To solve this, we just have to decode the morse code using CYBERCHEF
    
    PICOCTF{M0RS3C0D31SFUN2683824610}
    
- **waves over lambda (Medium)**
    
    Author: invisibility/danny
    
    ### Description
    
    We made a lot of substitutions to encrypt this. Can you decrypt it? Connect with `nc jupiter.challenges.picoctf.org 43522`.
    
    Solution:
    
    To solve this, we simply decoded the substitution cipher using our tool being subbreaker.
    
    subbreaker break --lang EN --ciphertext flag
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%205.png)
    
    so the flag is (did not need the picoCTF format lol)
    
    frequency_is_c_over_lambda_ogfmaunraf
    
- **Pixelated (Medium)**
    
    Author: Sara
    
    ### Description
    
    I have these 2 images, can you make a flag out of them? [scrambled1.png](https://mercury.picoctf.net/static/49743139fb7c10765dbf462d40987d2a/scrambled1.png) [scrambled2.png](https://mercury.picoctf.net/static/49743139fb7c10765dbf462d40987d2a/scrambled2.png)
    
    Solution:
    
    To solve this we had to stack the 2 images and form a new image from the stacked images.
    
    ## this is the script
    
    from PIL import Image
    import numpy as np
    import os
    
    file_names = ["scrambled1.png", "scrambled2.png"]
    img_data = [np.asarray(Image.open(f'{name}')) for name in file_names]
    
    data = img_data[0].copy() + img_data[1].copy()
    
    new_image = Image.fromarray(data)
    new_image.save("out.png", "PNG")
    
    and this gave us a img file that had the flag 
    
    ![out.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/out.png)
    
    picoCTF{2a4d45c7}
    
- **New Caesar (Medium)**
    
    Author: madStacks
    
    ### Description
    
    We found a brand new type of encryption, can you break the secret code? (Wrap with picoCTF{}) `lkmjkemjmkiekeijiiigljlhilihliikiliginliljimiklligljiflhiniiiniiihlhilimlhijil` [new_caesar.py](https://mercury.picoctf.net/static/c9043977604318594ab73d126a01d0b1/new_caesar.py)
    
    Solution:
    
    This encryption scheme first encodes the plaintext as `base16` (which essentially encodes each nibble of the plaintext as a character) and then applies a shift cipher to it.
    
    So, in order to reverse the operation, let's start by implementing the opposite operations:
    
    LOWERCASE_OFFSET = ord("a")
    ALPHABET = string.ascii_lowercase[:16]
    
    def b16_decode(enc):
    plain = ""
    for c1, c2 in zip(enc[0::2], enc[1::2]):
    n1 = "{0:04b}".format(ALPHABET.index(c1))
    n2 = "{0:04b}".format(ALPHABET.index(c2))
    binary = int(n1 + n2, 2)
    plain += chr(binary)
    return plain
    
    def unshift(c, k):
    t1 = ord(c) - LOWERCASE_OFFSET
    t2 = ord(k) - LOWERCASE_OFFSET
    return ALPHABET[(t1 - t2) % len(ALPHABET)]
    
    def decrypt(enc, key):
    dec = ""
    for i, c in enumerate(enc):
    dec += unshift(c, key[i % len(key)])
    return dec
    
    ciphertext = "lkmjkemjmkiekeijiiigljlhilihliikiliginliljimiklligljiflhiniiiniiihlhilimlhijil"
    
    for k in ALPHABET:
    decrypted = decrypt(ciphertext, k)
    if all([c in ALPHABET for c in decrypted]):
    decoded = b16_decode(decrypted)
    if all([c in string.printable for c in decoded]):
    print(f"Key: {k}, Plaintext: {decoded}")
    
    Now we can iterate all the possible keys (which are all the letters in the alphabet), try to decrypt the ciphertext and if the result is a legal base16 string, try to decrypt that as well. We'll ignore anything that doesn't result in a printable plaintext.
    
    picoCTF{et_tu?_431db62c5618cd75f1d0b83832b67b46}
    
- **Dachshund Attacks (Medium)**
    
    Author: Sara
    
    ### Description
    
    What if `d` is too small? Connect with `nc mercury.picoctf.net 58978`.
    
    Solution:
    
    When entering the server it gave use the following.
    
    Welcome to my RSA challenge!
    e: 10464899274398245649171577454522617172532048988610043806852018389744591049548220470632903456879705696376761089657582808426350716991971555341358183624361321784170944498242538949196688446186873186523091273191405862135919791299591557304718513545922289651612273612238946162813191008903755425623735575987692440225
    n: 76636254760273011623111133084740826646896374310657041335487714481312810239331277479989731800967312352366870520086316936996687931282561506480337702825968228260709848728875923676789257093570586046994982283113374373592116806587961258447548603857087343752713998912385817319067504903981594798084183007148179094399
    c: 46988099678740963756626698441284844416221289712096247996282556092547988540917837430987427850096872176359359629684298500420264445859627056131550943460091787811276844446001324159737969408521612593432821252696251209786085605098447416091426428422229214140269153416597786772116244886704795004570800738350843901222
    
    To solve this challenge, I used RSATool and used the following commands.
    
    RsaCtfTool -n (copied from the server) -e (copied from the server) --decrypt (the c/ciphertext copied from the server)
    
    after it used every possible attack type, it was able to solve the flag using the wiener method.
    
    Giving us the flag of 
    
    picoCTF{proving_wiener_6907362}
    
- **WMSUCCS-CTF**
    - **Binary Deception**
        
        **Category** : Cryptography
        **Points** : 25
        
        Zeros and ones whisper in another tongue. Listen carefully.
        
        ## Files :
        
        - [mars.txt](https://www.notion.so/mars.txt)
        
        Solution:
        I was given a txt file named "mars.txt", which contained the following:
        11 11111 010 000 00011...1010 111 100 00011
        -- ----- .-. ... ...-- / -.-. --- -.. ...--
        
        1 = -
        0 = .
        . = /
        
        Since the description said that it "whisper" in another language. I thought of morse code so after doing some refining
        1111111010000000111010111110000011
        and adding spaces between 1's and 0's
        I would get a morse code of
        Morse: -- .- .-. ... / -.-. --- -.. .
        
        that would translate to
        M0RS3COD3
        
        so Im guessing the flag is
        CCS{M0RS3_COD3}
        
    - **Fast Food Cipher**
        
        **Category** : Cryptography
        **Points** : 50
        
        Some secrets come with a side of crypto. Mind the special sauce.
        
        ## Files :
        
        - [fries.pdf](https://www.notion.so/fries.pdf)
        - [mcdo.jpg](https://www.notion.so/mcdo.jpg)
        
        Solution:
        
        So, I was given 2 files a password protected pdf file, and a jpg file.
        Now looking at the jpg file. It had some suspicious wording that were used
        so I was able to figure out a few meanings behind the words.
        
        McDonald5 = MD5
        Salt container with a CCS Text = Salt(hashing)/CCS could be the salt
        Mcdonald Fries with a Fries Text = Could be the password for the salt and hash combination
        
        So after creating a python script that would generate the hashed md5.
        import hashlib
        
        salt = "CCS"
        password = "Fries"
        
        # salt + password
        
        hash1 = hashlib.md5((salt + password).encode()).hexdigest()
        
        # password + salt
        
        hash2 = hashlib.md5((password + salt).encode()).hexdigest()
        
        print("MD5(salt + password):", hash1)
        print("MD5(password + salt):", hash2)
        
        I was able to come up with 2 possible passwords
        MD5(salt + password): d6983c39d73a7efd21f3dcc80e7ae3fb
        MD5(password + salt): 0286a69781f785c2395256aa5473ecaa
        
        now with the given password I tried it on the pdf and was able to open it with the second option getting the flag
        
        Flag: CCS{@Md5S4lt#}
        
    - **Obfuscated_Whispers**
        
        **Category** : Cryptography
        **Points** : 50
        
        A cryptic message awaits. Can you interpret its chaotic script?
        
        **Files :**
        
        - [ugh.txt](https://github.com/OwPor/WMSU-CCS-CTF-2025/blob/main/Cryptography/Obfuscated_Whispers/ugh.txt)
        
        Solution:
        
        inside the ugh.txt contained a js functions but since I didnt know what it meant I tried googling what type it was.
        
        So it was JSFuck
        after decoding it gave me the key
        CCS{H4h4_Y0u_G0+_M3}
        
- **CTFLearn**
    - **Character Encoding (Easy)**
        
        In the computing industry, standards are established to facilitate information interchanges among American coders. Unfortunately, I've made communication a little bit more difficult. Can you figure this one out? 41 42 43 54 46 7B 34 35 43 31 31 5F 31 35 5F 55 35 33 46 55 4C 7D
        
        Solution:
        
        Decode from hex
        
        ABCTF{45C11_15_U53FUL}
        
    - **Base 2 2 the 6 (Easy)**
        
        There are so many different ways of encoding and decoding information nowadays... One of them will work! Q1RGe0ZsYWdneVdhZ2d5UmFnZ3l9
        
        Solution:
        
        Decode the base64 string to get the flag
        
        CTF{FlaggyWaggyRaggy}
        
    - **Morse Code (Easy)**
        
        ..-. .-.. .- --. ... .- -- ..- . .-.. -- --- .-. ... . .. ... -.-. --- --- .-.. -... -.-- - .... . .-- .- -.-- .. .-.. .. -.- . -.-. .... . . ...
        
        Solution:
        
        just decode the morse code, bad challenge
        
        FLAGSAMUELMORSEISCOOLBYTHEWAYILIKECHEES 
        
    - **Reverse Polarity (Easy)**
        
        I got a new hard drive just to hold my flag, but I'm afraid that it rotted. What do I do? The only thing I could get off of it was this: 01000011010101000100011001111011010000100110100101110100010111110100011001101100011010010111000001110000011010010110111001111101
        
        Solution:
        
        Decode binary
        
        CTF{Bit_Flippin}
        
    - **Hextroadinary (Easy)**
        
        Meet ROXy, a coder obsessed with being exclusively the worlds best hacker. She specializes in short cryptic hard to decipher secret codes. The below hex values for example, she did something with them to generate a secret code, can you figure out what? Your answer should start with 0x.
        
        0xc4115 0x4cf8
        
        Solution:
        
        Easy to solve with Python code
        
        The `^` operator in Python represents the bitwise XOR 
        operation. When applied to two numbers, it performs the XOR operation on
         each corresponding pair of bits. Here's how it works:
        
        0xc4115     ->  11000001000100010101 (binary)
        
        0x4cf8      ->  0100110011111000     (binary)
        
        # XOR ( ^ )
        
        Result      ->  10001101111010010101 (binary)
        
        When you use the `hex()` function to print the result in hexadecimal format, it converts the binary result to its hexadecimal representation:
        
        10001101111010010101 (binary) -> The Flag (hexadecimal)
        
        So, `print(hex(0xc4115 ^ 0x4cf8))` will output The Flag.
        
        `0xc0ded`
        
    - **Vigenere Cipher (Easy)**
        
        The vignere cipher is a method of encrypting alphabetic text by using a series of interwoven Caesar ciphers based on the letters of a keyword.<br />
        
        I’m not sure what this means, but it was left lying around: blorpy
        
        gwox{RgqssihYspOntqpxs}
        
        Solution:
        
        Key is blorpy and we can decode it
        
        flag{CiphersAreAwesome}
        
    - **BruXOR (Easy)**
        
        There is a technique called bruteforce. Message: q{vpln'bH_varHuebcrqxetrHOXEj No key! Just brute .. brute .. brute ... :D
        
        Solution:
        
        bruteforce xorx
        
        flag{y0u_Have_bruteforce_XOR}7
        
    - **HyperStream Test #2 (Easy)**
        
        I love the smell of bacon in the morning! ABAAAABABAABBABBAABBAABAAAAAABAAAAAAAABAABBABABBAAAAABBABBABABBAABAABABABBAABBABBAABB
        
        Solution:
        
        bacon cipher decode
        
        ILOUEBACONDONTYOU
        
    - **Substitution Cipher (Medium)**
        
        Someone gave me this, but I haven't the slightest idea as to what it says! [https://mega.nz/#!iCBz2IIL!B7292dJSx1PGXoWhd9oFLk2g0NFqGApBaItI_2Gsp9w](https://mega.nz/#!iCBz2IIL!B7292dJSx1PGXoWhd9oFLk2g0NFqGApBaItI_2Gsp9w) Figure it out for me, will ya?
        
        Solution:
        
        Used a online bruteforce decoder for this
        
        [https://quipqiup.com/](https://quipqiup.com/)
        
        IFONLYMODERNCRYPTOWASLIKETHIS
        
    - **Modern Gaius Julius Caesar (Easy)**
        
        One of the easiest and earliest known ciphers but with XXI century twist! Nobody uses Alphabet nowadays right? Why should you when you have your keyboard?
        
        BUH'tdy,|Bim5y~Bdt76yQ
        
        Solution:
        
        Decode the message using a keyboard shift cipher
        
        [https://www.dcode.fr/keyboard-shift-cipher](https://www.dcode.fr/keyboard-shift-cipher)
        
        CTFlearn{Cyb3r_Cae54r}
        
    - **RSA Noob (Medium)**
        
        These numbers were scratched out on a prison wall. Can you help me decode them? [https://mega.nz/#!al8iDSYB!s5olEDK5zZmYdx1LZU8s4CmYqnynvU_aOUvdQojJPJQ](https://mega.nz/#!al8iDSYB!s5olEDK5zZmYdx1LZU8s4CmYqnynvU_aOUvdQojJPJQ)
        
        Solution:
        
        To solve this we needed to solve the RSA formula. I used a python script to solve it
        
        abctf{b3tter_up_y0ur_e}
        
    - **5x5 Crypto (Medium)**
        
        Ever heard of the 5x5 secret message system? If not, basically it's a 5x5 grid with all letters of the alphabet in order, without k because c is represented to make the k sound only. Google it if you need to. A letter is identified by Row-Column. All values are in caps. Try: 1-3,4-4,2-1,{,4-4,2-3,4-5,3-2,1-2,4-3,_,4-5,3-5,}
        
        Solution:
        
        We used a **Polybius Cipher using a 5x5 grip without using k**
        
        [https://www.dcode.fr/polybius-cipher](https://www.dcode.fr/polybius-cipher)
        
        CTFTHUMBS_UP
        
    - **Suspecious message (Easy)**
        
        Hello! My friend Fari send me this suspecious message: 'MQDzqdor{Ix4Oa41W_1F_B00h_m1YlqPpPP}' and photo.png. Help me decrypt this!
        
        [https://ctflearn.com/challenge/download/887](https://ctflearn.com/challenge/download/887)
        
        Solution:
        
        It was a playfair cipher, to decode this. I used a online tool
        
        [https://www.boxentriq.com/code-breaking/playfair-cipher](https://www.boxentriq.com/code-breaking/playfair-cipher)
        
        and the encryption key I used was from the image
        
        ![photo.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/photo.png)
        
        CTFLEARN{PL4YF41R_1S_C00L_C1PHERRRR}
        
    - **So many 64s (Hard)**
        
        Help! My friend stole my flashdrive that had the flag on it. When he gave it back the flag was changed! Can you help me decrypt it? [https://mega.nz/#!OHhUyIqA!H9WxSdG1O7eVcCm0dffggNB0-dBemSpBAXiZ0OXJnLk](https://mega.nz/#!OHhUyIqA!H9WxSdG1O7eVcCm0dffggNB0-dBemSpBAXiZ0OXJnLk)
        
        Solution:
        
        To solve this we have a text file that contains a lot of base64, we need to repeatedly decode it until it gives us the flag. So I made a python script to automate it.
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%206.png)
        
        ABCTF{pr3tty_b4s1c_r1ght?}
        
    - **RSA Beginner (Medium)**
        
        I found this scribbled on a piece of paper. Can you make sense of it? [https://mega.nz/#!zD4wDYiC!iLB3pMJElgWZy6Bv97FF8SJz1KEk9lWsgBSw62mtxQg](https://mega.nz/#!zD4wDYiC!iLB3pMJElgWZy6Bv97FF8SJz1KEk9lWsgBSw62mtxQg)
        
        Solution:
        
        I used RsaCtfTool to decode with the given ciphertext,n, and e
        
        RsaCtfTool -n 245841236512478852752909734912575581815967630033049838269083 -e 3 --decrypt 219878849218803628752496734037301843801487889344508611639028
        
        abctf{rs4_is_aw3s0m3}
        
    - **Encryption Master (Hard)**
        
        Alright. Serious talk. You need to work pretty hard for this one (unless you are an encryption god.) Well, good luck. [https://mega.nz/#!iPgzXIiD!Pkza_S8YUxIXrZ7gdwMcIoufMzi_FjSio3Vx9GuL0ok](https://mega.nz/#!iPgzXIiD!Pkza_S8YUxIXrZ7gdwMcIoufMzi_FjSio3Vx9GuL0ok)
        
        Solution:
        Just decode each using CybeChef
        
        CTF{I_AM_PROUD_OF_YOU}
        
    - **Tone dialing (Easy)**
        
        At 1pm I called my uncle who was 64 years old 10 months ago, but I heard only that. Later I started thinking about the 24 hour clock.
        
        I hope you will help me solve this problem
        
        [https://ctflearn.com/challenge/download/889](https://ctflearn.com/challenge/download/889)
        
        Solution:
        
        Use the dtmf command to decode the audio file and we get
        
        67847010810197110123678289808479718265807289125
        
        after listening and properly arranging it we can get 
        
        67 84 70 108 101 97 110 123 67 82 89 80 84 79 71 82 65 80 72 89 125
        
        now we just need to decode it using cyberchef binary
        CTFlean{CRYPTOGRAPHY}
        

### Forensics

### PicoCTF

- **DISKO 1 (Easy)**
    
    Author: Darkraicg492
    
    ### Description
    
    Can you find the flag in this disk image?
    Download the disk image [here](https://artifacts.picoctf.net/c/538/disko-1.dd.gz).
    
    Solution:
    
    After downloading the file `disko-1.dd.gz`, I noticed it was a compressed archive, so I extracted it first. The extracted file was clearly a disk image, so my initial thought was to run `binwalk` to look for embedded files or partitions. Unfortunately, `binwalk` didn’t return anything useful beyond some disk metadata — and part of the image seemed encrypted, so that route was a dead end.
    
    After thinking for a few minutes without much progress, I checked the hint provided: *"Maybe Strings could help? If only there was a way to do that?"* That pointed me toward the `strings` utility. I ran a basic `strings disko-1.dd | grep -i flag`, which printed out a massive amount of data — including multiple hits with the word "flag," but it was too noisy to sift through manually.
    
    To narrow it down, I tried searching for grep commands to craft a better `grep` pattern that would match common flag formats. I ended up using:
    
    `strings disko-1.dd | grep -E 'flag\{|FLAG-|CTF\{'`
    
    That immediately gave me a clean sequence of outputs:
    
    FLAG-5
    
    FLAG-4
    
    FLAG-3
    
    FLAG-2
    
    FLAG-1
    
    picoCTF{1t5_ju5t_4_5tr1n9_e3408eef}
    
    The actual flag was right there at the end:
    
    `picoCTF{1t5_ju5t_4_5tr1n9_e3408eef}`
    
- **RED (Easy)**
    
    Author: Shuailin Pan (LeConjuror)
    
    ### Description
    
    RED, RED, RED, RED
    Download the image: [red.png](https://challenge-files.picoctf.net/c_verbal_sleep/831307718b34193b288dde31e557484876fb84978b5818e2627e453a54aa9ba6/red.png)
    
    Solution:
    
    After downloading the image file, I suspected there might be some steganography involved, so I ran `zsteg` to scan for any hidden data encoded in the image. The tool returned a bunch of info, mostly metadata — but one section caught my attention: the RGBA channel contained a suspicious-looking Base64 string.
    
    At first, I wasn’t sure what to do with it, and after spending about 5 minutes stuck, I decided to check the hint. The hint confirmed my suspicion — the Base64 string was the key, and I needed to decode it.
    
    I copied the full string, which was a repeated pattern of:
    
    `cGljb0NURntyM2RfMXNfdGgzX3VsdDFtNHQzX2N1cjNfZjByXzU0ZG4zNTVffQ==`
    
    After decoding it with any basic Base64 tool (I used CyberChef), it gave me:
    
    `picoCTF{r3d_1s_th3_ult1m4t3_cur3_f0r_54dn355_}`
    
- **Ph4nt0m 1ntrud3r (Easy)**
    
    Author: Prince Niyonshuti N.
    
    ### Description
    
    A digital ghost has breached my defenses, and my sensitive data has been 
    stolen! 😱💻 Your mission is to uncover how this phantom intruder 
    infiltrated my system and retrieve the hidden flag.
    To solve this challenge, you'll need to analyze 
    the provided PCAP file and track down the attack method. The attacker 
    has cleverly concealed his moves in well timely manner. Dive into the 
    network traffic, apply the right filters and show off your forensic 
    prowess and unmask the digital intruder!
    Find the PCAP file here [Network Traffic PCAP file](https://challenge-files.picoctf.net/c_verbal_sleep/b6fbb3a5560749f838cdc6db4950985767c4691db3a7b34a220e5654ee39e700/myNetworkTraffic.pcap) and try to get the flag.
    
    Solution:
    
    I was given a pcap file and I noticied that it wasnt properly arranged in the time order meaning it was purposedly scrambled, however after you sorted it by time it would seem that the bytes was in base64. After I decoded it by showing the bytes one by one and decoding it using cyberchef. I was able to get the flag
    
    picoCTF{1t_w4snt_th4t_34sy_tbh_4r_36f4a666}
    
- **Verify (Easy)**
    
    Author: Jeffery John
    
    ### Description
    
    People keep trying to trick my players with imitation flags. I want to make 
    sure they get the real thing! I'm going to provide the SHA-256 hash and a
     decrypt script to help you know that my flags are legitimate.
    
    Additional details will be available after launching your challenge instance.
    
    Solution:
    
    Open PowerShell and connect to the a remote computer (server) using SSH.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*tbDrm75BpRMHfNhUyAl_mA.png)
    
    ```
    ssh -p 59633 ctf-player@rhea.picoctf.net
    ```
    
    - If you see a message asking to confirm the connection, type `**yes**` and press Enter.
    - This step allows us to access the server where the challenge files are stored.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*EuTujxR7uCZ4YrMkSZkgMQ.png)
    
    ```
    yes
    ```
    
    When asked for a password, enter:
    
    ![](https://miro.medium.com/v2/resize:fit:1146/1*iBGITE0gVTmOMP4iIihxcw.png)
    
    ```
    6dd28e9b
    ```
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*1wY7Fas-egw4h2I02RJfog.png)
    
    We successfully connected to the challenge server using SSH.
    
    Once connected, we need to list the available files
    
    ![](https://miro.medium.com/v2/resize:fit:804/1*6aWUhEx6XTeBOul5zIo8hA.png)
    
    ```
    ls
    ```
    
    We can see the following files in the current directory:
    
    **checksum.txt** (probably contains the reference SHA-256 hash)
    
    **decrypt.sh** (a script to decrypt the correct file)
    
    **files/** (a directory containing possible flag files)
    
    Let’s see the contents of **checksum.txt** to confirm the reference SHA-256 hash:
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*7AsZY-XLglWRxecoo40olg.png)
    
    ```
    cat checksum.txt
    ```
    
    We have successfully retrieved the SHA-256 hash from **checksum.txt**
    
    ```
    03b52eabed517324828b9e09cbbf8a7b0911f348f76cf989ba6d51acede6d5d8
    ```
    
    Listing Files Inside **files/ Directory**
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*CcMcEe4CH7FeDkkHh7UxIA.png)
    
    ```
    ls files/
    ```
    
    We see all the files inside the **files/ directory.** Since there are many files, we need to find the correct one by comparing their **SHA-256 hashes**.
    
    Running the Hash Check with Filtering
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*o5UkiW8ULBu33nRva77Ksw.png)
    
    ```
    sha256sum files/* | grep 03b52eabed517324828b9e09cbbf8a7b0911f348f76cf989ba6d51acede6d5d8
    ```
    
    We found the correct file: **files/00011a60**
    
    Now we will run the Decryption Script
    
    ![](https://miro.medium.com/v2/resize:fit:1340/1*1ARB-8Pn4JTTk8_SHJkVMQ.png)
    
    ```
    ./decrypt.sh files/00011a60
    ```
    
    # **flag:** **picoCTF{trust_but_verify_00011a60}**
    
- **Scan Surprise (Easy)**
    
    Author: Jeffery John
    
    ### Description
    
    I've gotten bored of handing out flags as text. Wouldn't it be cool if they were an image instead?
    You can download the challenge files here:
    
    - [challenge.zip](https://artifacts.picoctf.net/c_atlas/16/challenge.zip)
    
    Additional details will be available after launching your challenge instance.
    
    Solution:
    
    So for this challenge we are given a zip file. After extracting it we are able to see a qrcode. Now using zbarimg, we can scan the qr code in our terminal. After it scans we are given the flag.
    
    zbarimg flag.png
    QR-Code:picoCTF{p33k_@_b00_7843f77c}
    scanned 1 barcode symbols from 1 images in 0.02 seconds
    
- **Secret of the Polyglot (Easy)**
    
    Author: syreal
    
    ### Description
    
    The Network Operations Center (NOC) of your local institution picked up a
    suspicious file, they're getting conflicting information on what type of file
    it is. They've brought you in as an external expert to examine the file. Can
    you extract all the information from this strange file?
    Download the suspicious file [here](https://artifacts.picoctf.net/c_titan/96/flag2of2-final.pdf).
    
    Solution:
    
    So for this challenge we are given a zip file. After extracting it we are able to see a qrcode. Now using zbarimg, we can scan the qr code in our terminal. After it scans we are given the flag.
    
    zbarimg flag.png
    QR-Code:picoCTF{p33k_@_b00_7843f77c}
    scanned 1 barcode symbols from 1 images in 0.02 seconds
    
    For this challenge, I was given a PDF file. After opening it normally, I saw a partial flag inside:
    
    `1n_pn9_&_pdf_90974127}`
    
    Something about the string caught my eye — specifically the part that said `pn9_&_pdf`. That looked suspiciously like a hint. I guessed that "pn9" might actually be a play on "PNG", as in an image file. So I tried renaming the file extension from `.pdf` to `.png` and opened it as an image instead.
    
    Sure enough, that worked. Viewing the file as a PNG revealed the **first part** of the flag:
    
    `picoCTF{f1u3n7_`
    
    Combining both parts gave me the full flag:
    
    picoCTF{f1u3n7_1n_pn9_&_pdf_90974127}
    
- **CanYouSee (Easy)**
    
    Author: Mubarak Mikail
    
    ### Description
    
    How about some hide and seek?
    Download this file [here](https://artifacts.picoctf.net/c_titan/5/unknown.zip).
    
    Solution:
    
    For this challenge, I was given a `.jpg` image file. At first glance, the image looked totally normal — nothing obviously suspicious. So I ran `binwalk` on it to check for any hidden files or embedded data. Interestingly, it detected a TROC filesystem, which hinted that something might be hidden inside.
    
    Naturally, I tried extracting it with `steghide`, using no password (just hitting enter). It worked — it gave me a file named `flag`. But opening it revealed a message saying:
    
    **"The flag is not here maybe think in simpler terms. Data that explains data."**
    
    That line immediately made me think about **metadata** — data about data. So I ran `exiftool` on the original image file, which is great for digging into metadata across all sorts of formats. Sure enough, buried in the **Attribution URL** field, I found a suspicious Base64 string: `cGljb0NURntNRTc0RDQ3QV9ISUREM05fNGRhYmRkY2J9Cg==`
    
    Decoding it gave me the flag:
    
    `picoCTF{ME74D47A_HIDD3N_4dabddcb}`
    
- **information (Easy)**
    
    Author: susie
    
    ### Description
    
    Files can always be changed in a secret way. Can you find the flag? [cat.jpg](https://mercury.picoctf.net/static/149ab4b27d16922142a1e8381677d76f/cat.jpg)
    
    Solution:
    
    Since the challenge was titled **“information”**, my first instinct was to check the file’s metadata. I ran `exiftool` on it and quickly found a suspicious Base64 string hidden in the **License** field. After decoding it using CyberChef, it revealed the flag:
    
    Decoding it gave me the flag:
    
    `picoCTF{the_m3tadata_1s_modified}`
    
- **Glory of the Garden (Easy)**
    
    Author: jedavis/Danny
    
    ### Description
    
    This [garden](https://jupiter.challenges.picoctf.org/static/43c4743b3946f427e883f6b286f47467/garden.jpg) contains more than it seems.
    
    Solution:
    
    I used the hint after checking on the jpg file. It seems to be asking if I knew what is a hex editor. After realizing that the flag might be inside the hex. I began to use HxD and used the search function to look for any strings that may contain the word "pico" and after searching it was able to find one. At the bottom. so the flag is
    
    picoCTF{more_than_m33ts_the_3y3657BaB2C}
    
- **DISKO 2 (Medium)**
    
    Author: Darkraicg492
    
    ### Description
    
    Can you find the flag in this disk image?
    The right one is Linux! One wrong step and its all gone!
    Download the disk image [here](https://artifacts.picoctf.net/c/541/disko-2.dd.gz).
    
    Solution:
    
    So the challenge was to scan a disk file and find the flag inside. Now there are a lot of particitioners inside the disk. What I did was use mmls to first check how many particioners were inside the disk. I found 4. I then tried this command before actually doing any indepth scanning
    
    strings disko-2.dd | grep "picoC"
    
    after doing this it gave me a lot of flags but since it scanned every particioner. It would take a lot of time to just manually checking if it was the correct one. So I separated the Linux Particitioner that was made so that I could scan that file specifically. So I did the following command to isolate the particioner
    
    dd if=disko-2.dd of=LinuxPart.img bs=512 skip=2048 count=51200
    
    After we did the isolation, we then did another strings scan to see how many flags are in this specific one. And it displayed only one flag. So after pasting it. It was the correct one
    
    picoCTF{4_P4Rt_1t_i5_055dd175}
    
- **flags are stepic (Medium)**
    
    Author: Ricky
    
    ### Description
    
    A group of underground hackers might be using this legit site to 
    communicate. Use your forensic techniques to uncover their message
    
    Additional details will be available after launching your challenge instance.
    
    Solution:
    
    So this challenge was a really hard one, it took me 2 hours to figure out and needed the help from other people. So to solve this basically, there is a fake country that doesnt exist and this country is the only one that has a different style(ccs) within it. After downloading the image. the title of the challenge was actually a steganography tool being stepic. so I did the following command
    
    stepic -d -i upz.img
    
    doing this will give you a error but it will also give you the flag.
    
    /usr/lib/python3/dist-packages/PIL/Image.py:3402: DecompressionBombWarning: Image size (150658990 pixels) exceeds limit of 89478485 pixels, could be decompression bomb DOS attack.
    warnings.warn(
    picoCTF{fl4g_h45_fl4g3e22f365}
    
- **Event-Viewing (Medium)**
    
    Author: Venax
    
    ### Description
    
    One of the employees at your company has their computer infected by 
    malware! Turns out every time they try to switch on the computer, it 
    shuts down right after they log in. The story given by the employee is 
    as follows:
    
    1. They installed software using an installer they downloaded online
    2. They ran the installed software but it seemed to do nothing
    3. Now every time they bootup and login to their computer, a black 
    command prompt screen quickly opens and closes and their computer shuts 
    down instantly.
    
    See if you can find evidence for the each of these events and retrieve the flag (split into 3 pieces) from the correct logs!
    Download the Windows Log file [here](https://challenge-files.picoctf.net/c_verbal_sleep/123d9b79cadb6b44ab6ae912f25bf9cc18498e8addee851e7d349416c7ffc1e1/Windows_Logs.evtx)
    
    Solution:
    
    So for this challenge, we needed to be using the Windows OS for the Event Viewer Application. Now for this challenge we had to look for 3 separate flag parts. So to begin we need to first figure out which specific event ID's we needed to fubd so from the employee's statement. We need to look for any changes in the registry, shutdown, and login. So we need to first use the filter and implmenet the specific EventID for each. So I noticed that there were small bits of base64 in either comments or edited parts within the registry. So after gathering them all. I just used cyberchef to merge them and give me the whole flag
    
    picoCTF{Ev3nt_vi3wv3r_1s_a_pr3tty_us3ful_t00l_81ba3fe9}
    
- **WebNet1 (Hard)**
    
    Author: Jason
    
    ### Description
    
    We found this [packet capture](https://jupiter.challenges.picoctf.org/static/fbf98e695555a2a48fe42c9a245de376/capture.pcap) and [key](https://jupiter.challenges.picoctf.org/static/fbf98e695555a2a48fe42c9a245de376/picopico.key). Recover the flag.
    
    Solution:
    
    After downloading the `.pcap` (packet capture) file and a `.key` file, I opened the capture in **Wireshark** to start analyzing it. Right away, I noticed a ton of **TLS traffic**, which made sense for encrypted communications. Some of the packets clearly contained encrypted data, so I figured the provided key file would help decrypt it.
    
    Since I wasn’t sure how to use the `.key` file in Wireshark, I asked ChatGPT for help. After reading the steps, I edited the **TLS protocol settings** under **Wireshark Preferences > Protocols > TLS**, added the key file under (Pre)-Master-Secret log filename, and then reloaded the capture. That worked — I could now see **HTTP traffic** that had previously been encrypted, including requests to image, CSS, and HTML files.
    
    At first, I tried copying the HTTP links and opening them in a browser, but that didn’t work since the data was local to the capture and not hosted on a live server. After getting stuck for a couple more minutes, I again turned to ChatGPT, which suggested using **“Follow HTTPS Stream”** inside Wireshark. That did the trick — I followed one of the HTTP streams and saw the contents of the redirected web files, and hidden among them was the flag:
    
    `picoCTF{honey.roasted.peanuts}`
    
- **Bitlocker-2 (Medium)**
    
    Author: Venax
    
    This problem cannot be solved in the webshell.
    
    ### Description
    
    Jacky has learnt about the importance of strong passwords and made sure to 
    encrypt the BitLocker drive with a very long and complex password. We 
    managed to capture the RAM while this drive was opened however. See if 
    you can break through the encryption!
    Download the disk image [here](https://challenge-files.picoctf.net/c_verbal_sleep/b22e1ca13c0b82bb85afe5ae162f6ecbdf5b651e364e6a2b57c9ad44ae0b3bfd/bitlocker-2.dd) and the RAM dump [here](https://challenge-files.picoctf.net/c_verbal_sleep/b22e1ca13c0b82bb85afe5ae162f6ecbdf5b651e364e6a2b57c9ad44ae0b3bfd/memdump.mem.gz)
    
    Solution:
    
    So we are given a Disk Image and a Ram Dump file, technically we are supposed to find the password and use it to break free from the encryption. But since we are already given the ram dump. We can just do a shortcut and use strings to find the flag inside the ram dump.
    First I unzipped it, I did
    mv memdump.7qm34z2O.mem.gz.part memdump.mem.gz
    gunzip memdump.mem.gz
    
    So basically it renamed the file and then I decompressed it so that I could view the file itself.
    After that we just did a case sensitive strings + grep command so
    strings memdump.mem | grep -i "picoctf{"
    and yeah we got the flag that being.
    
    picoCTF{B1tl0ck3r_dr1v3_d3crypt3d_9029ae5b}
    
- **Bitlocker-1 (Medium)**
    
    Author: Venax
    
    This problem cannot be solved in the webshell.
    
    ### Description
    
    Jacky is not very knowledgable about the best security passwords and used a 
    simple password to encrypt their BitLocker drive. See if you can break 
    through the encryption!
    Download the disk image [here](https://challenge-files.picoctf.net/c_verbal_sleep/9e934e4d78276b12e27224dac16e50e6bbeae810367732eee4d5e38e6b2bb868/bitlocker-1.dd)
    
    Solution:
    
    Just by reading off the challenge description, it is pretty obvious that we have to approach this challenge by **incorporating brute-forcing techniques** in order to **crack the bitlocker encryption.**
    
    I installed the challenge files provided inside my Kali Linux VM. You can do this by running the command:
    
    *wget  (file link)*
    
    ![](https://miro.medium.com/v2/resize:fit:1100/1*dkkuh4VfgkiPCII8XX3v7Q.png)
    
    > bitlocker2john -i bitlocker-1.dd > bitlocker_hash.txt
    > 
    
    The command that got executed shown in the figure above is used to **extract the Bitlocker hash from the disk image**. This hash allows us to crack the password, as it will be used to **validate** password guesses. the *-i*
     argument is to specify that “bitlocker-1.dd” is an image file. The 
    output will be then stored in a new file called “bitlocker.txt”
    
    After the command has been executed, read the contents of the text file. You should be able to spot this particular hash:
    
    > User Password hash:
    > 
    > 
    > $bitlocker$0$16$cb4809fe9628471a411f8380e0f668db$1048576$12$d04d9c58eed6da010a000000$60$68156e51e53f0a01c076a32ba2b2999afffce8530fbe5d84b4c19ac71f6c79375b87d40c2d871ed2b7b5559d71ba31b6779c6f41412fd6869442d66d
    > 
    
    We will use this hash in particular as the other hashes that we have 
    received from the extraction involves recovery keys which is far harder 
    to brute-force giving its length of 48 characters
    
    ![](https://miro.medium.com/v2/resize:fit:1118/1*WT5PlbZg32u_n_PAeX1lzQ.png)
    
    > head -n 10000 /usr/share/wordlists/rockyou.txt > dictionary.txt
    > 
    
    Next, we need a wordlist to perform a dictionary-based brute-force attack. One of the most commonly used wordlists is **rockyou.txt**, which contains **14,341,564 unique passwords**. Since trying all possible combinations would take an extremely long time, I started with the first **10,000 words** from the **rockyou.txt**
     file and worked my way down if the initial set didn’t yield any 
    results. As shown in the figure above, I saved the output as a text file
     called **“dictionary.txt”** for the attack
    
    ![](https://miro.medium.com/v2/resize:fit:980/1*mzPGaaSmHrNMlBBWBGvtjw.png)
    
    > hashcat -m 22100 -a 0 bitlocker_hash.txt top2k.txt -w 3
    > 
    
    We will be utilizing hashcat as our bruteforcing tool. the *-m 22100* argument **specifies the hash mode for the haschat to distinguish it as a bitlocker hash**, *-a 0* sets the attack mode to **dictionary attack** as we have the wordlist available (dictionary.txt), and *-w 3* essentially **puts more workload** so that the hashing process is more efficient and faster though, this argument is optional.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*AEzdjn1Iqf-yI9DSDfeVNQ.png)
    
    Upon a couple of minutes, hashcat has successfully found the password! It was “*jacqueline”* our next step is to decrypt the bitlocker file with the password and see its contents
    
    > $bitlocker$0$16$cb4809fe9628471a411f8380e0f668db$1048576$12$d04d9c58eed6da010a000000$60$68156e51e53f0a01c076a32ba2b2999afffce8530fbe5d84b4c19ac71f6c79375b87d40c2d871ed2b7b5559d71ba31b6779c6f41412fd6869442d66d:jacqueline
    > 
    
    ![](https://miro.medium.com/v2/resize:fit:526/1*28tv2oa9_mFGgy3i7avWEw.png)
    
    Make a directory to store the **dislocker-file** located inside the bitlocker.dd, a virtual file that **represents the decrypted contents of the bitlocker encrypted volume.**
    
    ![](https://miro.medium.com/v2/resize:fit:978/1*ueO4T_XXIJ8ESs7_c_Q6Og.png)
    
    > sudo dislocker bitlocker-1.dd -ujacqueline dislocker
    > 
    
    Afterwards, use the dislocker tool to unlock the bitlocker encrypted drive. The password *“jacqueline”* is specified with -u argument. The output is then, saved to the “dislocker” directory.
    
    ![](https://miro.medium.com/v2/resize:fit:1016/1*8ANHudXA9a8YtMCbpS9wWg.png)
    
    Upon unlocking the bitlocker drive we can see that the dislocker-file is present. We now need to mount this file in our machine.
    
    ![](https://miro.medium.com/v2/resize:fit:530/1*LpOx9KXTluqjYMQLDAtjDA.png)
    
    Create a directory which we will use as a mount point.
    
    ![](https://miro.medium.com/v2/resize:fit:1180/1*MqF2YTNC2y-PGmqQGHY67w.png)
    
    > sudo mount -o loop dislocker/dislocker-file mounted
    > 
    
    The command above mounts the unencrypted/unlocked bitlocker file to the “mounted” directory. The *-o loop* is used to tell the computer to treat the regular file (dislocker-file) **as if it were a physical disk drive**. This allows us to **access all the folders and files inside it, just like a USB drive or HDD.** The concept is similar to inserting a CD into your laptop.
    
    ![](https://miro.medium.com/v2/resize:fit:914/1*n4PvOU33sHVFaGuNtC3hUw.png)
    
    flag: picoCTF{us3_b3tt3r_p4ssw0rd5_pl5!_3242adb1}
    
- **Blast from the Past (Medium)**
    
    Author: syreal
    
    As of March 13th, the last check now accepts more formats.
    
    ### Description
    
    The judge for these pictures is a real fan of antiques. Can you age this photo
    to the specifications?
    Set the timestamps on this picture to `1970:01:01 00:00:00.001+00:00` with as
    much precision as possible for each timestamp. In this example, `+00:00` is a
    timezone adjustment. Any timezone is acceptable as long as the time is
    equivalent. As an example, this timestamp is acceptable as well: `1969:12:31 19:00:00.001-05:00`. For timestamps without a timezone adjustment, put them in
    GMT time (+00:00). The checker program provides the timestamp needed for each.
    Use this [picture](https://artifacts.picoctf.net/c_mimas/90/original.jpg).
    
    Solution:
    
    i checked first with exiftool, and i notice this
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*83jYg9XXJam0AdJldn1LCg.png)
    
    Modify Date
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*XcQLM8VZevD3vkunW9E-iA.png)
    
    Timestamp
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*PY_PmUC1Oz4AJ8XlC0c20w.png)
    
    some date agian
    
    as we can see on the information
    
    “The judge for these pictures is a real fan of antiques. Can you age this 
    photo to the specifications?Set the timestamps on this picture to `1970:01:01 00:00:00.001+00:00` with as much precision as possible for each timestamp. In this example, `+00:00`
     is a timezone adjustment. Any timezone is acceptable as long as the 
    time is equivalent. As an example, this timestamp is acceptable as well:
     `1969:12:31 19:00:00.001-05:00`. 
    For timestamps without a timezone adjustment, put them in GMT time 
    (+00:00). The checker program provides the timestamp needed for each.”
    
    we need to change those all date (metadata)
    
    im using exiftool for this one
    
    exiftool \
    -ModifyDate="1970:01:01 00:00:00" \
    -DateTimeOriginal="1970:01:01 00:00:00" \
    -CreateDate="1970:01:01 00:00:00" \
    -SubSecTime="001" \
    -SubSecTimeOriginal="001" \
    -SubSecTimeDigitized="001" \
    -OffsetTime="+00:00" \
    -OffsetTimeOriginal="+00:00" \
    -OffsetTimeDigitized="+00:00" \
    original.jpg -o original_fixed.jpg
    
    and send it
    
    # **nc -w 2 mimas.picoctf.net 55107 < original.jpgnc mimas.picoctf.net 59807**
    
    we didnt got same with the Timestamp, and i try for like 6 times with diff metadata changes, still didnt.
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%207.png)
    
    and i got this (string)
    
    ![](https://miro.medium.com/v2/resize:fit:1284/1*fHDLohva_U5Jae0rByVDzA.png)
    
    1700513181420 looks sus, let me check it
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*Dlos0bfpeBhz56Wt20hjQA.png)
    
    and yea, it same as Timestamp
    
    so i think we need to modify the hex to get diff string (i guess)
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*NZG-QmgCL2HcfErPZ3tTSQ.png)
    
    im modify the image_utc_data to
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*gdpjrcTfdi9wQaBFcXCjTw.png)
    
    not 0, cus we need to put it in milisecs not in seconds so it will be 00001
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%208.png)
    
    picoCTF{71m3_7r4v311ng_p1c7ur3_83ecb41c}
    
- **Mob Psycho (Medium)**
    
    Author: NGIRIMANA Schadrack
    
    ### Description
    
    Can you handle APKs?
    Download the android apk [here](https://artifacts.picoctf.net/c_titan/51/mobpsycho.apk).
    
    Solution:
    
    For this challenge, I was given an `.apk` file. My first instinct was to open it using Android Studio, but when I checked the file type, it turned out to be a **ZIP archive** in disguise. So instead of dealing with an emulator, I just extracted it with:
    
    `unzip mobpsycho.apk -d .`
    
    After extraction, I browsed through the directory and decided to simply search for any files that might contain the flag. Sure enough, I found a file named `flag.txt`.
    
    Opening `flag.txt`, I found this string of numbers:
    
    `7069636f4354467b6178386d433052553676655f4e5838356c346178386d436c5f35326135653264657d`
    
    At first, I assumed it was Base64, but decoding it gave garbage. Then I realized it was **hex-encoded**, not Base64. Once I converted it from hex to ASCII, I got the actual flag:
    `picoCTF{ax8mC0RU6ve_NX85l4ax8mCl_52a5e2de}`
    
- **endianness-v2** **(Medium)**
    
    Solution:
    
    i have downloaded the file and my first step i used exiftool
    
    ![Screenshot From 2025-07-13 21-55-03.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/Screenshot_From_2025-07-13_21-55-03.png)
    
    umm so it’s an JPEG file..so i opened hexeditor and that’s what i found
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*5vD58cp4_EMe6KwWAuC2Ww.png)
    
    all the bytes are not in there right places so lets go back and read the 
    challenge again…oh the file came from 32bit system so it’s little 
    endianness
    
    let me explain for you
    
    imagine you have a number like 0x12345678. In a little-endian system, it’s 
    stored in memory like this: 78 56 34 12. The “little” part means the 
    little end (the least significant part) comes first.
    
    In contrast, in a big-endian system, the same number would be stored like 
    this: 12 34 56 78. The “big” part means the big end (the most 
    significant part) comes first.
    
    Here is a image to explain too
    
    ![](https://miro.medium.com/v2/resize:fit:1400/0*4P_y7JlU_FkRXUPr.png)
    
    Big Endian vs Little Endian
    
    so now 32 bit is a little endian that’s why our file is not working now we
     want to convert our file from little endian to big endian so after some
     search and asking friends one of my friends sent me this code
    
    ```
    hexdump -v -e '1/4 "%08x"' -e '"\n"' input_file | xxd -r -p > output_file
    ```
    
    so after i ran it..it worked and now we have an image and if we opened it you will see the flag
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*jPJWRrtnMBw88nAdveTkFw.png)
    
    hex of the big endian
    
    ![flag.jpg](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/flag.jpg)
    
    picoCTF{cert!f1Ed_iNd!4n_s0rrY_3nDian_b039bc14}
    
- **Dear Diary** **(Medium)**
    
    Author: syreal
    
    ### Description
    
    If you can find the flag on this disk image, we can close the case for good!
    Download the disk image [here](https://artifacts.picoctf.net/c_titan/63/disk.flag.img.gz).
    
    Solution:
    
    The given file is disk.flag.img, so I use autopsy to analyze it.
    
    ![](https://miro.medium.com/v2/resize:fit:1248/1*aDIRNN6_4-v3WDKbZhiWQg.png)
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*AE-3FYakJx5QXXtT7Iki6A.png)
    
    Create a new case and name it whatever you want, then add the path to the img file downloaded.
    
    ![](https://miro.medium.com/v2/resize:fit:1258/1*XPlyY6togdFqRmIT6HjnsQ.png)
    
    I use all the default settings and analyze the raw disk file.
    
    ![](https://miro.medium.com/v2/resize:fit:1332/1*Ep7vMbEvGXAAhouLTb9XwQ.png)
    
    I then used **keyword search** with **ASCII** option to search for raw data. My first search is “.txt” to find if there’s a flag file. Although there’s no file named flag directly, I saw parts of the flag distributed around **/img_disk.flag.img/vol_vol4/root/secret-secrets/innocuous-file.txt**
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*LRrSGhpNVRUJNnXMc2eEAg.png)
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*umWw0Mir8Yn9EBmQeb70Vg.png)
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*MZuoLashyynpU1vr8PXqjQ.png)
    
    Just like that, we can continue to view some more files, assemble all the parts found, and then send them in smoothly.
    
    flag
    
    picoCTF{1_533_n4m35_80d24b30}
    
- **PcapPoisoning (Medium)**
    
    Author: Mubarak Mikail
    
    ### Description
    
    How about some hide and seek heh?
    Download this [file](https://artifacts.picoctf.net/c/377/trace.pcap) and find the flag.
    
    Solution:
    
    For this challenge, I was given just a `.pcap` file. Normally, I’d load it up in **Wireshark**, since that’s the go-to tool for anything packet-related. But before that, I ran my usual quick check — a simple `strings` + `grep` combo — just to see if anything obvious popped out.
    
    Sure enough, it worked:
    
    strings trace.pcap | grep -i "picoCTF{”
    
    Boom — there it was, right in the output:
    
    `picoCTF{P64P_4N4L7S1S_SU55355FUL_31010c46}`
    
    Sometimes the low-tech methods really pay off.
    
- **MSB (Medium)**
    
    Author: LT 'syreal' Jones
    
    ### Description
    
    This image passes LSB statistical analysis, but we can't help but think there
    must be something to the visual artifacts present in this image...
    Download the image [here](https://artifacts.picoctf.net/c/307/Ninja-and-Prince-Genji-Ukiyoe-Utagawa-Kunisada.flag.png)
    
    Solution:
    
    download the challenge file.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*iSn2Tlin1LQRYQqlLmUa4g.png)
    
    First I used, **[StegOnline](https://stegonline.georgeom.net/upload)** tool — A web-based, enhanced and open-source port of StegSolve. Upload any image file, and the relevant options will be displayed.
    
    However, there’s nothing interesting results discovered. Then I tried to research on different steganography tools available in the wild that fits the **Most Significant Bit (MSB)** challenge.
    
    I found a git repository and tried to clone it: `git clone [https://github.com/Pulho/sigBits](https://github.com/Pulho/sigBits)`
    
    Take time to read the `README.md.` — to get an overview about the tool and how to use it. I also installed pillow: `pip install pillow`
    
    changed the permission of `sigBits.py` : `chmod +x sigBits.py`
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*_XCzrGXSZMO-Tv_ifkpj7Q.png)
    
    Trying the sigBits tool
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*VXol9tLLYFE_vNfxHgc8CQ.png)
    
    sigBits manual
    
    - I then run the command:
    
    ```
    python3 sigBits.py -t=msb ../../Desktop/Ninja-and-Prince-Genji-Ukiyoe-Utagawa-Kinisada.flag.png
    ```
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*dr5ihUTDiqmGAxe-MFr5Cw.png)
    
    running the command
    
    After running the command, there’s a file `outputSB.txt`
    
    I then tried to read the contents of the file 
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%209.png)
    
    flag:
    
    picoCTF{15_y0ur_que57_qu1x071c_0r_h3r01c_b5e03bc5}
    
- **hideme (Medium)**
    
    Author: Geoffrey Njogu
    
    ### Description
    
    Every file gets a flag.
    The SOC analyst saw one image been sent back and forth between two people. They decided to investigate and found out that there was more than what meets the eye [here](https://artifacts.picoctf.net/c/259/flag.png).
    
    Solution:
    
    So for this challenge, it gave me a png file. Now I first tried to check for the file type 
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2010.png)
    
    After that I did a exiftool to examine the files metadata
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2011.png)
    
    Since no luck, I did a binwalk to see if there was any hidden files that were embedded within it, and to my surprise there was a zip file.
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2012.png)
    
    And now we just need to extract the zip file and find a flag inside it. 
    
    ![flag.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/flag.png)
    
    picoCTF{Hiddinng_An_imag3_within_@n_ima9e_cda72af0}
    
- **FindAndOpen** **(Medium)**
    
    Author: Mubarak Mikail
    
    ### Description
    
    Someone might have hidden the password in the trace file.
    Find the key to unlock [this file](https://artifacts.picoctf.net/c/495/flag.zip). [This tracefile](https://artifacts.picoctf.net/c/495/dump.pcap) might be good to analyze.
    
    Solution:
    
    Used [WireShark](https://www.wireshark.org/) to open the provided `dump.pcap`, visually inspecting the packet payloads the following packet was found of interest, payload size stood out as unique in this capture also) :
    
    ```
    Packet #48 @ Timestamp: 24.240874
    Packet Type: Ethernet II
    
    Data = VGhpcyBpcyB0aGUgc2VjcmV0OiBwaWNvQ1RGe1IzNERJTkdfTE9LZF8=
    
    ```
    
    Payload looked very reminiscent of a base64 encoded string, so I used cyberchef to decode it.
    
    from VGhpcyBpcyB0aGUgc2VjcmV0OiBwaWNvQ1RGe1IzNERJTkdfTE9LZF8=
    
    to
    
    picoCTF{R34DING_LOKd_
    
    Well thats a fragment of our flag, before continuing to search for additional payloads in the packet capture file I decided to  try this as the password to unzip the supplied encrypted
    
    ```
    flag.zip
    ```
    
    doing
    
    unzip flag.zip
    
    asked for the password, in which I gave it th
    
    picoCTF{R34DING_LOKd_
    
    which yields a
    
    ```
    flag
    ```
    
    file containing the full flag
    
    picoCTF{R34DING_LOKd_fil56_succ3ss_0f2afb1a}
    
- **Torrent Analyze (Medium)**
    
    Author: Mubarak Mikail
    
    ### Description
    
    SOS, someone is torrenting on our network. One of your colleagues has been using torrent to download some files on the company’s network. Can you identify the file(s) that were downloaded? The file name will be the flag, like `picoCTF{filename}`. [Captured traffic](https://artifacts.picoctf.net/c/165/torrent.pcap).
    
    Solution:
    
    We will use Wireshark to analyze *torrent.pcap* file. To start this job, enable one protocol, that was disabled by default:
    
    > Analyze -> Enabled protocols and select BT-DHT (Bittorrent DHT Protocol)
    > 
    
    Now stop for a moment, read the challenge instruction carefully: we need to find **filename**, not file contents. That's really important, because you can spend hours
    there, trying to recover the file itself, but that's just waste of time in this case. Keep in mind also, that we are looking for a file, that has been **downloaded**, not shared, by someone in our network.
    
    Another thing: we won't find the filename inside this *pcap* file. It will be a bit harder. Reading about torrents will sooner or later direct you to the term of *info_hash*, which is the SHA1 sum of the torrent file. Let's investigate that!
    
    ![Wireshark 1](https://raw.githubusercontent.com/pmateja/picoCTF_2022_writeups/main/Torrent_Analyze/ws1.png)
    
    Just press Ctrl-F and type the term *info_hash* in the searching field. There are more than a few packets containing this term. Nice, but to be honest, there are too many of them. We have to filter it out more, because the value of *info_hash* differs between  packets. BUT, do you remember, that we are looking for a file, that was downloaded? So let's only include packets where the source address is 
    from our local network and info_hash string exists. This query will do:
    
    > bt-dht.bencoded.string contains info_hash and ip.src == 192.168.73.132
    > 
    
    ![Wireshark 2](https://raw.githubusercontent.com/pmateja/picoCTF_2022_writeups/main/Torrent_Analyze/ws2.png)
    
    Now *info_hash* in all filtered packets is the same: **e2467cbf021192c241367b892230dc1e05c0580e**. But that's a hash, not a filename, that we crave so much. What can we do now? Yeah, just google it:
    
    ![Google](https://raw.githubusercontent.com/pmateja/picoCTF_2022_writeups/main/Torrent_Analyze/google.png)
    
    Out job is done here, the flag is 
    
    *picoCTF{ubuntu-19.10-desktop-amd64.iso}*
    
- **St3g0 (Medium)**
    
    Author: LT 'syreal' Jones (ft. djrobin17)
    
    ### Description
    
    Download this image and find the flag.
    
    - [Download image](https://artifacts.picoctf.net/c/216/pico.flag.png)
    
    Solution:
    
    I went to [Steganography Online](https://stylesuxx.github.io/steganography/) to decode the image, but decoding the image did not reveal anything.
    
    I decided to use [zsteg](https://github.com/zed-0xff/zsteg) instead, with the `-a` option to try all known methods, and the `-v` option to run verbosely,
    
    `zsteg -a -v pico.flag.png`
    
    This revealed the flag at `b1,rgb,lsb,xy`, where `rgb` means it uses RGB channel, `lsb` means least significant bit comes first, and `xy` means the pixel iteration order is from left to right.
    
    ![Figure 1](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/Screenshot_From_2025-07-14_14-55-36.png)
    
    Therefore, the flag is,
    
    `picoCTF{7h3r3_15_n0_5p00n_1b8d71db}`
    
- **Sleuthkit Intro (Medium)**
    
    Author: LT 'syreal' Jones
    
    ### Description
    
    Download the disk image and use `mmls` on it to find the size of the Linux
    partition. Connect to the remote checker service to check your answer and get
    the flag.
    Note: if you are using the webshell, download and extract the disk image into
    `/tmp` not your home directory.
    [Download disk image](https://artifacts.picoctf.net/c/164/disk.img.gz)
    
    Solution:
    
    For this challenge, I was given a disk. And to get the flag I just needed to connect to the server and answer its question. After opening the server. I was asked 
    
    What is the size of the Linux partition in the given disk image?
    Length in sectors:
    
    So for this, I just needed to know the file size. So what I did was use fdisk since it shows all the available info inside the disk.
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2013.png)
    
    So the sectors are 202752. So we just need to answer that.
    
    ![Screenshot From 2025-07-14 15-08-11.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/Screenshot_From_2025-07-14_15-08-11.png)
    
    picoCTF{mm15_f7w!}
    
- **Sleuthkit Apprentice (Medium**
    
    Author: LT 'syreal' Jones
    
    ### Description
    
    Download this disk image and find the flag.
    Note: if you are using the webshell, download and extract the disk image into
    
    ```
    /tmp
    ```
    
    not your home directory.
    
    - [Download compressed disk image](https://artifacts.picoctf.net/c/137/disk.flag.img.gz)
    
    Solution:
    
    As you can see, this challenge comes with an image that we need to download. We can do this with `wget` and then extracted the compressed file with `gzip -d disk.flag.img.gz`. Once the file is downloaded and extracted, 
    
    we need to determine the layout of the partition table with `mmls`. This will provide us with the offset address for each partition on the image. NOTE: think of an offset as a starting address.
    
    ![Screenshot From 2025-07-14 15-31-14.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/Screenshot_From_2025-07-14_15-31-14.png)
    
    Now that we have the partition information, we can determine what kind of file system is used on the image. To do this we use `fsstat -o 2048 disk.flag.img`.
    
    ![Screenshot From 2025-07-14 15-32-05.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/Screenshot_From_2025-07-14_15-32-05.png)
    
    Next we use `fls` to list the file and directory names in each partition. We will skip the swap partition for now. NOTE: `-i` is the image type, `-f` is the file system type, and `-r` is to recursively display directories.
    
    ![Screenshot From 2025-07-14 15-33-09.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/Screenshot_From_2025-07-14_15-33-09.png)
    
    There wasn’t much that seemed of interest on the first partition, but when we run `fls`
     on the third one, we get a lot of content back. Because we know that 
    picoCTF answers are usually stored in a file called “flag.txt,” lets use
     `grep` to filter anything that has the word “flag.”
    
    ![Screenshot From 2025-07-14 15-33-40.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/Screenshot_From_2025-07-14_15-33-40.png)
    
    The first result is interesting, because it found a file in unallocated space called “flag.txt” and we know this because of the asterisk next to the inode number (r/r *). NOTE: the *r* stands for regular file and realloc means that the metadata structure is in an allocated state still, but the file is deleted.
    
    We can use `icat`to print the contents of these files to the terminal. NOTE: the digits 
    at the in end of the command are the inode numbers associated with the 
    files.
    
    ![Screenshot From 2025-07-14 15-34-44.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/Screenshot_From_2025-07-14_15-34-44.png)
    
    The deleted “flag.txt” returned random pieces of metadata and nothing of value; the “flag.uni.txt” will print the answer.
    
    ![Screenshot From 2025-07-14 15-35-02.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/Screenshot_From_2025-07-14_15-35-02.png)
    
    picoCTF{by73_5urf3r_adac6cb4}
    
- **Redaction gone wrong (Medium)**
    
    Author: Mubarak Mikail
    
    ### Description
    
    Now you DON’T see me.
    This [report](https://artifacts.picoctf.net/c/84/Financial_Report_for_ABC_Labs.pdf) has some
    critical data in it, some of which have been redacted correctly, while some
    were not. Can you find an important key that was not redacted properly?
    
    Solution:
    
    For this challenge, I was given a pdf file that seems to contain files that were redacted. Meaning it was previously edited. So what I did was, use pdftohtml to see any previously edited parts.
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2014.png)
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2015.png)
    
    opening the flag.html will give me the full pdf without any redaction.
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2016.png)
    
    picoCTF{C4n_Y0u_S33_m3_fully} 
    
- **Packets Primer (Medium)**
    
    Author: LT 'syreal' Jones
    
    ### Description
    
    Download the packet capture file and use packet analysis software to find the
    flag.
    
    - [Download packet capture](https://artifacts.picoctf.net/c/195/network-dump.flag.pcap)
    
    Solution:
    
    So for this challenge, I was given a pcap file. Now I just opened Wireshark. To see if there are any visible strings. And there was a flag that was vision within the tcp
    
    ![Screenshot From 2025-07-14 15-42-21.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/Screenshot_From_2025-07-14_15-42-21.png)
    
    picoCTF{p4ck37_5h4rk_b9d53765}
    
- **Operation Orchid (Medium)**
    
    Author: LT 'syreal' Jones
    
    ### Description
    
    Download this disk image and find the flag.
    Note: if you are using the webshell, download and extract the disk image into
    
    ```
    /tmp
    ```
    
    not your home directory.
    
    - [Download compressed disk image](https://artifacts.picoctf.net/c/213/disk.flag.img.gz)
    
    Solution:
    
    So we download the file as given by the challenge using the `wget` command.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*Q2I8uKTjUx6CaWiuzCiqHw.png)
    
    We’ll find out what the file is from the metadata using the `file <file_name>` command.
    
    ```
    file disk.flag.img.gz
    ```
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*DBO5G2gcxlcmapeOfnG90Q.png)
    
    It’s a disk image, so we’ll unzip it using the `gunzip <file_name>` command. It’ll take a while, but once it’s done, type in `ls` to check the file contents in the directory you’re in. There will be the `disk.flag.img` file we just unzipped.
    
    ![](https://miro.medium.com/v2/resize:fit:1088/1*CMxKpPxalzFETE-iytQr0w.png)
    
    Next, we will use the `mmls` command to find out the contents of a disk. From the SleuthWiki’s page:
    
    > mmls
     displays the contents of a volume system (media management). In 
    general, this is used to list the partition table contents so that you 
    can determine where each partition starts. The output identifies the 
    type of partition and its length, which makes it easy to use ‘dd’ to 
    extract the partitions. The output is sorted based on the starting 
    sector so it is easy to identify gaps in the layout.
    > 
    
    Basically,
     it shows the offset or the starting point of a partition in byte unites
     (if my Computer Architecture knowledge is still correct). We will use 
    the command with our disk image.
    
    ```
    mmls disk.flag.img
    ```
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*QMekobSnYdEh1RZzlPaPTw.png)
    
    We’ll find out that there’s **two** Linux (0x83) partitions. My guess is that it’s in the fifth partition (index 004) since it has the **largest** length, but we’ll find out what’s in the third partition (index 002).
    
    Now, we’ll find out the contents of a partition using the `fls -o <starting offset>` command.
    
    ```
    fls -o 2048
    ```
    
    ![](https://miro.medium.com/v2/resize:fit:1124/1*FAM5W0Xm3UvlAIQ9GDQG4w.png)
    
    This looks like OS mumbo-jumbo that I don’t understand, so I’ll just check out the other partition which starts at 411648.
    
    ![](https://miro.medium.com/v2/resize:fit:1158/1*6UX5mF9n8W8AFrwzgHsmGw.png)
    
    Inode number 472 has the folder `root` , which looks like a promising start. Hence, seek what’s inside there using the `fls` command once more, but now, we’re using the inode number as well, so the command looks like `fls -o <offset> <disk_name> <inode number>` .
    
    ![](https://miro.medium.com/v2/resize:fit:1236/1*GistVa9-_szsP2WjbtXL0Q.png)
    
    Woo,
     we’ve found flag.txt.enc on inode 1782! On inode 1876, there’s also a 
    flag.txt, but since it has an asterisk, it’s already deleted. Now, since
     the `.enc` extension file means 
    that the file is encrypted, we must find a way to decrypt it as well. 
    But first, we have to know what the encryption method that is used and 
    what the key is to decrypt it.
    
    Let’s see what the `flag.txt.enc` file looks like inside using the `icat` command, to extract the data inside.
    
    ![](https://miro.medium.com/v2/resize:fit:1264/1*ZWLMuJF0BCDBZvS9izgXaQ.png)
    
    Salted__… hmm, looks like an AES encryption to me.
    
    To find the key, we will find it using `strings -t d disk.flag.img | grep flag.txt` . Let’s break the command down:
    
    1. `strings` is used to see the text or binary data inside a file. The `t d` argument prints the offset of every string in the file.
    2. The pipe operator `|` passes the output of `strings -t d` to `grep flag.txt` .
    3. `grep` finds the line `flag.txt` so we can see what encryption method is used.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*l1fHqV471T9yIpca5s34wQ.png)
    
    We get a bunch of output in some lines which look like `<number> <string>`
     . The numbers represent the byte offsets (in decimal) within the disk 
    image where the strings were found. The strings show actions performed 
    on a file named flag.txt.
    
    We find that an OpenSSL AES-256 encryption was used (as we thought), with salt options, with the key `unbreakablepassword1234567` . All that’s left is to decrypt it. But first, we’re going to extract what’s inside using the `icat` method so we can decrypt the contents to the `/tmp` folder.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*VtgQU81q1mmViXD_R4dkrA.png)
    
    Now the `flag.txt.enc` is in our `/tmp` folder so that we can do some commands to it. Here, we’re going to decrypt it using the `unbreakablepassword1234567` .
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*H8Cnt3Hz4Ttb-3lm3ToR7Q.png)
    
    picoCTF{h4un71ng_p457_5113beab}
    
- **Operation Oni (Medium)**
    
    Author: LT 'syreal' Jones
    
    Note: you must launch a challenge instance in order to view your disk image download link.
    
    ### Description
    
    Download this disk image, find the key and log into the remote machine.
    Note: if you are using the webshell, download and extract the disk image into
    
    ```
    /tmp
    ```
    
    not your home directory.
    
    - [Download disk image](https://artifacts.picoctf.net/c/71/disk.img.gz)
    - Remote machine: `ssh -i key_file -p 55822 ctf-player@saturn.picoctf.net`
    
    Solution:
    
    After downloading the file using **wget** decompressed the file using **gunzip** and then checked the file type
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*kwJZWiC-7X61wGT66hfujA.png)
    
    Then checked for file partitions using **mmls** command found three partitions out of one is unallocated.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*I9xvFgj5WLgouPHbkDR4gQ.png)
    
    Then looked for file system of the partition number 2 **(Linux 0x83)** using **fsstat** command
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*pz7CA3Au0byt7Vrs1VCNjA.png)
    
    The first partitions is linux based partition so then I looked for files and directories of this partition using **fls** command..
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*_WQpU2Iwe2TQa0Yna-iQ5g.png)
    
    Some info about the partition
    
    Nothing interesting here.
    
    Then I checked for the file system of partition number 3 (**Linux 0x83**)using **fsstat** command then found that this is also a Linux partition
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*iSVFO-NQdRPXROG174JQng.png)
    
    Some info about the partition
    
    Then looked for the directores and files using **fls** command
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*B7-Y1TsLaL2IhFEDAmxyMw.png)
    
    Found some interesting directories in this partition here
    
    Then after searching in root directory I found…
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*IssplDaTgzf82mFJ4S_oXw.png)
    
    Then after looking in ssh directory..
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*ejQAVCBErBlIQWog0SLtQQ.png)
    
    Found public and private key
    
    Reading every file one by one
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*8enLWtZrHTs8cqfUgy73hg.png)
    
    Found the private key for login into ssh
    
    Then I exported the file to my local machine using **icat**
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*Apz4MH94tvUeaLKXHMBtpg.png)
    
    Checked the permission of the private key using **ls -l**
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*6kfMwHJMmCkJ1bht0lomlA.png)
    
    Then changing the permissions of the private key.
    
    ```
    NOTE: If the permissions are too open, SSH will refuse to use the key and instead prompt for a password or another form of authentication.
    ```
    
    So after changing the permission of the private key using **chmod** command
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*NQpIzY5GN2BQkIuFB_BZCQ.png)
    
    Permissions Changed
    
    Now login to ssh using private key through `ssh -i keyfile -p portnumber username@ipofmachine.`
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*sSkBVu-PBe8ZJxPlDajMXQ.png)
    
    Login Successful
    
    Then after looking in the directories found the flag
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*d0ItQWjg7EWNvxIQXsxmaQ.png)
    
    picoCTF{k3y_5l3u7h_af277f77}
    
- **Lookey here (Medium)**
    
    Author: LT 'syreal' Jones / Mubarak Mikail
    
    ### Description
    
    Attackers have hidden information in a very large mass of data in the past,
    maybe they are still doing it.
    Download the data [here](https://artifacts.picoctf.net/c/125/anthem.flag.txt).
    
    Solution:
    
    For this challenge, I was given a `.txt` file. First thing I did was verify whether it was actually a plain text file or if it was something else disguised with a `.txt` extension. Once I confirmed it was legit, I opened it — but the contents were pretty overwhelming and noisy.
    
    Rather than scrolling through it manually, I used a simple `grep` command to search for any line that looked like a flag. Something like:
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2017.png)
    
    strings anthem.flag.txt | grep -i "picoCTF{"   
    
- **File types (Medium) I hate this**
    
    Author: Geoffrey Njogu
    
    ### Description
    
    This file was found among some files marked confidential but my pdf reader
    cannot read it, maybe yours can.
    You can download the file from [here](https://artifacts.picoctf.net/c/80/Flag.pdf).
    
    Solution:
    
    We are also given the file [Flag.pdf](https://ctftime.org/writeup/files/Flag.pdf). I tried to open this up in my PDF reader, but it said that it cannot be opened.
    
    So I checked the file type using,
    
    `$ file Flag.pdf`
    
    And this revealed that it was a `shell archive text`
    
    The contents inside were,
    
    ```bash
    #!/bin/sh# This is a shell archive (produced by GNU sharutils 4.15.2).# To extract the files from this archive, save it to some FILE, remove# everything before the '#!/bin/sh' line above, then type 'sh FILE'.#
    lock_dir=_sh00048
    # Made on 2022-03-15 06:50 UTC by <root@ffe9b79d238c>.# Source directory was '/app'.## Existing files will *not* be overwritten, unless '-c' is specified.## This shar contains:# length mode       name# ------ ---------- ------------------------------------------#   1092 -rw-r--r-- flag#
    MD5SUM=${MD5SUM-md5sum}
    f=`${MD5SUM} --version | egrep '^md5sum .*(core|text)utils'`
    test -n "${f}" && md5check=true || md5check=false${md5check} || \
      echo 'Note: not verifying md5sums.  Consider installing GNU coreutils.'if test "X$1" = "X-c"then keep_file=''else keep_file=truefiecho=echo
    save_IFS="${IFS}"
    IFS="${IFS}:"
    gettext_dir=
    locale_dir=
    set_echo=falsefor dir in $PATHdoif test -f $dir/gettext \
         && ($dir/gettext --version >/dev/null 2>&1)
      thencase `$dir/gettext --version 2>&1 | sed 1q` in
          *GNU*) gettext_dir=$dirset_echo=truebreak ;;
        esacfidoneif ${set_echo}thenset_echo=falsefor dir in $PATHdoif test -f $dir/shar \
           && ($dir/shar --print-text-domain-dir >/dev/null 2>&1)
        then
          locale_dir=`$dir/shar --print-text-domain-dir`
          set_echo=truebreakfidoneif ${set_echo}then
        TEXTDOMAINDIR=$locale_direxport TEXTDOMAINDIR
        TEXTDOMAIN=sharutils
        export TEXTDOMAIN
        echo="$gettext_dir/gettext -s"fifi
    IFS="$save_IFS"if (echo "testing\c"; echo 1,2,3) | grep c >/dev/null
    then if (echo -n test; echo 1,2,3) | grep n >/dev/null
         then shar_n= shar_c='
    'else shar_n=-n shar_c= ; fielse shar_n= shar_c='\c' ; fi
    f=shar-touch.$$
    st1=200112312359.59
    st2=123123592001.59
    st2tr=123123592001.5 # old SysV 14-char limit
    st3=1231235901
    
    if   touch -am -t ${st1} ${f} >/dev/null 2>&1 && \
         test ! -f ${st1} && test -f ${f}; then
      shar_touch='touch -am -t $1$2$3$4$5$6.$7 "$8"'elif touch -am ${st2} ${f} >/dev/null 2>&1 && \
         test ! -f ${st2} && test ! -f ${st2tr} && test -f ${f}; then
      shar_touch='touch -am $3$4$5$6$1$2.$7 "$8"'elif touch -am ${st3} ${f} >/dev/null 2>&1 && \
         test ! -f ${st3} && test -f ${f}; then
      shar_touch='touch -am $3$4$5$6$2 "$8"'else
      shar_touch=:
      echo${echo} 'WARNING: not restoring timestamps.  Consider getting and
    installing GNU '\''touch'\'', distributed in GNU coreutils...'echofi
    rm -f ${st1} ${st2} ${st2tr} ${st3} ${f}#if test ! -d ${lock_dir} ; then :
    else ${echo} "lock directory ${lock_dir} exists"exit 1
    fiif mkdir ${lock_dir}then ${echo} "x - created lock directory ${lock_dir}."else ${echo} "x - failed to create lock directory ${lock_dir}."exit 1
    fi# ============= flag ==============if test -n "${keep_file}" && test -f 'flag'then${echo} "x - SKIPPING flag (file already exists)"else${echo} "x - extracting flag (text)"
      sed 's/^X//' << 'SHAR_EOF' | uudecode &&
    begin 600 flag
    M(3QA<F-H/@IF;&%G+R`@("`@("`@("`@,"`@("`@("`@("`@,"`@("`@,"`@
    M("`@-C0T("`@("`Q,#(T("`@("`@8`K'<6D`)KRD@0`````!````,&)$-P4`
    M``#\`69L86<``$)::#DQ05DF4UF)`)#/```E___[?]^QG];K^__EPW7_K?]K
    MR^OIUNY_^^3__(Y?_\=GM3`!&U8(!D#0:/4``````T`:`!ZF@```&GJ#(`!Z
    M0`#(/4::#T@8RCTF@>33U1`&F@Q`T#1D&@9&@TTT&C(&30!Z30&@R:-&(TPF
    MC$R-J#0&$,0>D`:::``T`53U-1H``/4#33U``--`#R@]30T`T&@`T-#3U&@#
    M$]0``T`#0-&@`#33$-`"`(`!IFX0%$'>=+$A\#.&I40R`'VYC>1:(E,*]\(N
    M&BGDKO2X!L:.03&MTW`4?.<8(]E4^+TO1G_XNWE81>^<$IH`#?.>TVA>/FPA
    MU9RVP</7\$0:081U`?'(\']7N#&U7?2=C!,S)6)_66H1$_%^#R#-`P**+(HQ
    M3.IA'+51?)3G!=:!,4MM4+8+!)-`:C;`92&>ONSRN]Z%`GWPQC#7O/MV)YZ=
    M4#0;KG6KOAA^.NURH^D[%4D"M%0M&I#+%4&J!(,3;/_)XZ&]^Q#[Q.':.0E*
    M?VA'QCIAD^+7#>15$D098CQ8K.6I+_D:4DB(V`9ZM9JAGE/<0M70!PP=>%?L
    M$Q,L-<YP$7B:0O`%,?"O'F42&HLUI2XPQ@Y,C=/]MN^MA*I"='%M6)=`6@)&
    M-D0'Y4UL93^^#\.?XNY(IPH2$2`2&>#'<0`````````````!``````````L`
    M`````%1204E,15(A(2$`````````````````````````````````````````
    M````````````````````````````````````````````````````````````
    M````````````````````````````````````````````````````````````
    M````````````````````````````````````````````````````````````
    M````````````````````````````````````````````````````````````
    M````````````````````````````````````````````````````````````
    M````````````````````````````````````````````````````````````
    M````````````````````````````````````````````````````````````
    M````````````````````````````````````````````````````````````
    M````````````````````````````````````````````````````````````
    ,````````````````
    `
    end
    SHAR_EOF
      (set 20 22 03 15 06 50 44 'flag'
       eval "${shar_touch}") && \
      chmod 0644 'flag'
    if test $? -ne 0
    then ${echo} "restore of flag failed"
    fi
      if ${md5check}
      then (
           ${MD5SUM} -c >/dev/null 2>&1 || ${echo} 'flag': 'MD5 check failed'
           ) << \SHAR_EOF
    eb0e2b4641ff5c18c9602a8528bccf5c  flag
    SHAR_EOF
    
    else
    test `LC_ALL=C wc -c < 'flag'` -ne 1092 && \
      ${echo} "restoration warning:  size of 'flag' is not 1092"
      fi
    fi
    if rm -fr ${lock_dir}
    then ${echo} "x - removed lock directory ${lock_dir}."
    else ${echo} "x - failed to remove lock directory ${lock_dir}."
         exit 1
    fi
    exit 0
    
    ```
    
    So I copied this file into a file with a .sh extension,
    
    `$ cp Flag.pdf Flag.sh`
    
    And added the execution permission,
    
    `$ chmod +x Flag.sh`
    
    And executed this script,
    
    `$ ./Flag.sh`
    
    After executing, a file called `flag` was generated, and checking the file type revealed that it was a `current ar archive`.
    
    Then I used the `binwalk` to extract the ar archive,
    
    `$ binwalk -e flag`
    
    Which created a new folder called `_flag.extracted`, and inside was a file called `64`.
    
    I checked the file type of `64`, and revealed that it was a `gzip compressed data`
    
    I used `binwalk` to extract the gzip,
    
    `$ binwalk -e 64`
    
    The extracted folder contained a file called `flag`,
    
    I checked the file type of `flag`, and revealed that it was a `lzip compressed data`. Using `binwalk` did not extract it, so I extracted this using,
    
    `$ lzip -d -k flag`
    
    This created a file called `flag.out`, and revealed that it was a `LZ4 compressed data`. So I extracted it using,
    
    `$ lz4 -d flag.out flag2.out`
    
    This created a file called `flag2.out`, and revealed that it was a `LZMA compressed data`. So I extracted it using,
    
    `$ lzma -d -k flag2.out`
    
    However, there this returned `Filename has an unknown suffix, skipping`, so I renamed it to flag2.lzma and I extracted it using,
    
    `$ lzma -d -k flag2.lzma`
    
    This created a file called `flag2`, and revealed that it was a `LZOP compressed data`. Like last time, it gave `unknown suffix`, so I renamed it to `flag2.lzop`, and I extracted it using,
    
    `$ lzop -d -k flag2.lzop -o flag3`
    
    This created a file called `flag3`, and revealed that it was a `LZIP compressed data`. So I extracted it using,
    
    `$ lzip -d -k flag3`
    
    This created a file called `flag3.out`, and revealed that it was a `XZ compressed data`. I renamed it to `flag4.xz` and I extracted it using,
    
    `$ xz -d -k flag4.xz`
    
    This created a file called `flag4`, and revealed that it was a `ASCII text` and contained the following,
    
    ```
    7069636f4354467b66316c656e406d335f6d406e3170756c407431306e5f
    6630725f3062326375723137795f33343765616536357d0a
    
    ```
    
    I went ahead to CyberChef and converted this from hex,
    
    Therefore, the flag is,
    
    `picoCTF{f1len@m3_m@n1pul@t10n_f0r_0b2cur17y_347eae65}`
    
    ---
    
- **Enhance! (Medium)**
    
    Author: LT 'syreal' Jones
    
    ### Description
    
    Download this image file and find the flag.
    
    - [Download image file](https://artifacts.picoctf.net/c/101/drawing.flag.svg)
    
    Solution:
    
    In this challenge we have a downloaded file “drawing.flag.svg”
    
    If we open this in a normal image viewer is not useful:
    
    we use text editor or browser and view the source code of the image.
    
    as we analysis the code and directly to see at the last CTF is given in code and merge all the valid lines. After the complete the this we have flag: 
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2018.png)
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2019.png)
    
    picoCTF{3nh4nc3d_24374675}
    
- **Eavesdrop (Medium)**
    
    Author: LT 'syreal' Jones
    
    ### Description
    
    Download this packet capture and find the flag.
    
    - [Download packet capture](https://artifacts.picoctf.net/c/133/capture.flag.pcap)
    
    Solution:
    
    I’ve already downloaded the file with the name capture.flag.pcap, while 
    solving several forensic categories, especially .pcap files, we can 
    sometimes have a clue by reading the string found in the file and 
    determining our next move and how to search within the .pcap with 
    Wireshark. So first let us extract the string
    
    ```
    $ strings capture.flag.pcap
    ```
    
    [](https://miro.medium.com/v2/resize:fit:1346/0*KsjV9YQi4AHVmaN-)
    
    I found a conversation within the file, it seems they talk about 
    transferring a file between machines and the file was encrypted. From 
    the command in the conversation above, the encryption method used is **Triple DES (3DES)** with a **salt.**
    
    **3DES** is an encryption standard using DES (Data Encryption Standard) is one 
    of the old encryption methods, a symmetric-key algorithm both for 
    encryption and decryption. Nowadays DES encryption has been replaced by 
    AES (Advanced Encryption Standard). 3DES itself applies the DES 
    algorithm three times to each data block, more secure than a single DES.
    
    Back to the topic, I found something interesting in the conversation. One of
     the people doing the conversation stated that he needed the file to be 
    transferred again and the other said that the file would be transferred 
    via port 9002.
    
    [](https://miro.medium.com/v2/resize:fit:782/0*-6etEy4FXjyeWygh)
    
    From there we just need to follow the TCP stream from port 9002, first we need to find port 9002.
    
    [](https://miro.medium.com/v2/resize:fit:1400/0*og-YOt8XqtpG9Rek)
    
    We got the data from port 9002, then let’s inspect it further with follow TCP stream.
    
    [](https://miro.medium.com/v2/resize:fit:1400/0*5pnQK6SeSdj3PBBD)
    
    We found the encrypted file, next we need to save it as .3des extension with the name **file.3des**
    and decrypt it with the command found in the conversations. At first, I tried to save the file as it is with the .3des extension, but when I tried to decrypt it, it showed a **“bad decrypt”** message
    
    ```
    $ openssl des3 -d -salt -in file.des3 -out file.txt -k supersecretpassword123
    ```
    
    [](https://miro.medium.com/v2/resize:fit:1400/0*o1bCgQGpRhdVqdk7)
    
    After hours of troubleshooting trying to find when and where I did wrong, I finally found my mistake. When saving the data into the **file.3des**, I view the data as ASCII so the data is saved directly as ASCII, saving the characters themselves, not the actual binary bytes, so the decryption will fail because it expects the raw binary data when encrypted. Encryption algorithms operate on binary data, so I will repeat the step and try to save it as a raw binary file.
    
    [](https://miro.medium.com/v2/resize:fit:1400/0*Qx9cVP9rlnweVDik)
    
    This is the encrypted data when viewed as raw binary data, then saved into **file.3des.** Next, decrypt it using the command from the conversation
    
    ```
    $ openssl des3 -d -salt -in file.des3 -out file.txt -k supersecretpassword123
    ```
    
    [](https://miro.medium.com/v2/resize:fit:1400/0*lUZAGSnntI_z3MgT)
    
    The decryption was a success and a new file was generated after decrypting the **file.3des** named file.txt, Let’s read the file
    
    ```
    $ cat file.txt
    ```
    
    Okay we got the flag after reading the file: 
    
    picoCTF{nc_73115_411_5786acc3}
    
- **WPA-ing Out (Medium)M**
    
    Author: MistressVampy
    
    ### Description
    
    I thought that my password was super-secret, but it turns out that 
    passwords passed over the AIR can be CRACKED, especially if I used the 
    same wireless network password as one in the rockyou.txt credential 
    dump.
    Use this '[pcap file](https://artifacts.picoctf.net/c/41/wpa-ing_out.pcap)' and the rockyou wordlist. The flag should be entered in the picoCTF{XXXXXX} format.
    
    Solution:
    
    I looked at this hint:
    
    "Aircrack-ng can make a pcap file catch big air...and crack a password."
    
    Along with the description mentioning rockyou.txt made this challenge quite straightforward.
    
    `wget https://artifacts.picoctf.net/c/41/wpa-ing_out.pcap`
    
    Then I just ran aircrack-ng with the rockyou word list and the pcap.
    
    `aircrack-ng -w /usr/share/wordlists/rockyou.txt wpa-ing_out.pcap`
    
    This gave the key/password. I then put it in the picoCTF{} format as described in the description and it was the correct flag.
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/c10dabe1-0281-4e01-b822-b235595a1999.png)
    
    picoCTF{mickeymouse}
    
- **advanced-potion-making (Medium)**
    
    Author: bigC
    
    ### Description
    
    Ron just found his own copy of advanced potion making, but its been corrupted by some kind of spell. Help him recover it!
    
    Solution:
    
    Checking what file type this file is
    
    ![](https://miro.medium.com/v2/resize:fit:838/1*SJTBOuQ-r1e1yjLLWRYCUw.png)
    
    Doesn't give me any hint.
    
    I tried to execute it, open it, read it and lastly I checked the hex.
    
    ![](https://miro.medium.com/v2/resize:fit:836/1*bCZWYcLu5NQZo14nZs_DQA.png)
    
    ![](https://miro.medium.com/v2/resize:fit:1246/1*qFrVT0uiFoExhLT_Ik6cIA.png)
    
    Which I supposed as corrupted image file. I was looking for hint which image type this is. [Here](https://en.wikipedia.org/wiki/List_of_file_signatures) once I recognize it is a .png file I looked here for example png file headers ([here](https://asecuritysite.com/forensics/png?file=%2Flog%2Fbasn0g01.png)).
    
    With help of hexeditor.
    
    ![](https://miro.medium.com/v2/resize:fit:866/1*vtbXS21l_vAC0l3sdCMckg.png)
    
    But you can use whatever hex editor you like. I fixed the header, it was similar but not same.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*v6D3eRWk3uv3uybQ70DIgw.png)
    
    With this fix I could open the image.
    
    ![](https://miro.medium.com/v2/resize:fit:1202/1*ZjPqIHu_OZ5S0mcb6sQYJw.png)
    
    Oh
     it can’t be easy right? I then used tools as binwalk, exiftool, … 
    nothing give me a hint. Then I tried with online tool to play with it. I
     used this online [tool](https://www.online-image-editor.com/).
    
    With option to color change and B&W option I could read the flag.
    
    picoCTF{w1z4rdry}
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2020.png)
    
- **Milkslap (Medium)**
    
    Solution:
    
    Interesting, there is no file to download!? But there is a link in description if you click on the image.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*BrPYyuIEzNz9X9tN0J_IIg.png)
    
    There is a PNG file, which works as a “GIF” when you move your mouse. Basically you give a milkslap to the person on the image.
    
    Using curl to get more info, returns me nothing usefull.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*Ks-ikUMZFIZohqgy8_hLSw.png)
    
    Then I copied the image link from the website and downloaded the only image there is.
    
    ![](https://miro.medium.com/v2/resize:fit:1090/1*pUefBQf10n_IkN3KsNRFsA.png)
    
    And runned few most common tools for steganography. As it is a PNG file, I used the **zsteg** command (steghide = only JPG, zsteg = only PNG) to try and find the flag.
    
    Note: If you never used zsteg you can install it with command
    
    > gem install zsteg
    > 
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*zf-qvyfu2HI_Y0gfkTscGg.png)
    
    Now I can read the flag, which is embedded inside the png file. Of course without ‘\n’. Which is new line feed.
    
    picoCTF{imag3_m4n1pul4t10n_sl4p5}
    
- **Disk, disk, sleuth! II (Medium)**
    
    Author: syreal
    
    ### Description
    
    All we know is the file with the flag is named `down-at-the-bottom.txt`... Disk image: [dds2-alpine.flag.img.gz](https://mercury.picoctf.net/static/b369e0ba3b6ffd2be8164cd3c99c294b/dds2-alpine.flag.img.gz)
    
    Solution:
    
    Using the [TSK Tool Overview](http://wiki.sleuthkit.org/index.php?title=TSK_Tool_Overview) website we can find that the `fls` command can list all files in a directory. We specify the `r`, which means recursive so it will scan the entire disk image, and `p`, so it prints the full path, flags. The `o` flag is the offset of the partition we want to use, which can be dounf by running `mmls dds2-alpine.flag.img`. Finally, we search the output using `grep` for the name of the file given in the challenge description. So, the resulting command looks as follows: `fls -r -p -o 2048 dds2-alpine.flag.img | grep down-at-the-bottom.txt`. The output is: `r/r 18291: root/down-at-the-bottom.txt`
    
    - `18291` is the inode number of the file. We can use `icat` to list the contents of that inode like so: `icat -o 2048 dds2-alpine.flag.img 18291`
        
        The flag is shown in the output (inside of a unique pattern so we couldn't simply search for it):
        
        `picoCTF{f0r3ns1c4t0r_n0v1c3_0ba8d02d}`
        
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2021.png)
    
- **MacroHard WeakEdge (Medium)**
    
    Author: madStacks
    
    ### Description
    
    I've hidden a flag in this file. Can you find it? [Forensics is fun.pptm](https://mercury.picoctf.net/static/52da699e0f203321c7c90ab56ea912d8/Forensics%20is%20fun.pptm)
    
    Solution:
    
    So, what is it?
    
    > file ./Forensics\ is\ fun.pptm
    > 
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*7GlNSaNOlr1X-WXHGhCFYA.png)
    
    Running File command to inspect the file
    
    Let’s google what a .pptm file is?
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*aJ4IUiVa-NoudT7NKEu-dg.png)
    
    Aha, it’s simply a PowerPoint file with Macro-Enabled, in case you don’t 
    know what macro is, it is a feature which let you write code to automate tasks. And that’s also a “Aha” moment for me, i thought it must be the 
    key here since the title also contains the phrase “macro”. So, let’s 
    open the file using LibreOffice7.2 and see what the file’s macro 
    contains.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*Xsalfo9OF267fbvuRiya6w.png)
    
    Inspecting file’s macro using LibreOffice 7.2
    
    Yup, i was so naive and thought that the flag should be in the macro 
    Content, but nothing was there, it’s just the author tricking us into 
    thinking the flag is in the macro content. Ok, we got to an end, where 
    the flag could be?
    
    Then i search on Google about “hidden macro” of pptm file format but 
    couldn’t find what we need, so i research again on the pptm file format 
    itself, not the “hidden flag” it could contains but the file format 
    itself.
    
    I got luck and found this link about [pptm file format,](https://docs.fileformat.com/presentation/pptm/)
     in short either the ppt or pptm file is able to be decompressed by 
    changing the extension to .zip and use tools to unzip the file.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*Qnis9gfALdbK45Qq-lNwDw.png)
    
    pptm file format
    
    Let’s unzip it
    
    > unzip ./Forensics\ is\ fun.pptm
    > 
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*LN_Ebw9FUU1yZ7qGmvIY5w.png)
    
    We
     get a bunch of file, our PowerPoint file contains mostly .xml and .rel 
    file. So let’s find all the file which is not .xlm and .rel
    
    Here i use the tool fuzzy finder to search file
    
    ![](https://miro.medium.com/v2/resize:fit:1188/1*xISs-8R-uc61s9fzIsDmqg.png)
    
    We’ve got the ppt/vbaProject.bin and ppt/slideMasters/hidden look really suspicious, let’s see what they contains.
    
    > cat ./ppt/vbaProject.bin
    > 
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*Xfbgfdp2KhCgQGUWbZuvXw.png)
    
    Hm… the .vba is actually the macro on which we inspected earlier, we can 
    see the “not_flag” which showed earlier. It’s doesn’t contain the flag.
    
    What about the ppt/slideMasters/hidden file?
    
    > cat ./ppt/slideMasters/hidden
    > 
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*YPQdwksmLBs-dSDuSEDaXw.png)
    
    This is our last hope, but what is this? a bunch of random character? Maybe 
    it’s the flag but it’s encoded. So i tried to decoded it in base64 and 
    got the flag.
    
    picoCTF{D1d_u_kn0w_ppts_r_z1p5}
    
- **Matryoshka doll (Medium)**
    
    Author: Susie/Pandu
    
    ### Description
    
    Matryoshka dolls are a set of wooden dolls of decreasing size placed one inside another. What's the final one? Image: [this](https://mercury.picoctf.net/static/5ef2e9103d55972d975437f68175b9ab/dolls.jpg)
    
    Solution:
    
    After downloading, we get this image:
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*iikzMyZdFVC8RPfsCScyXA.png)
    
    Inspecting the image we downloaded
    
    # 2. Extract Information
    
    I used binwalk to try and extract any files/folders from the image and I got this:
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*eK78um1Lu4YF8hjdvFn8jA.png)
    
    Using binwalk to extract information
    
    We get this particular directory from extracting:
    
    ![](https://miro.medium.com/v2/resize:fit:812/1*VXWuJBGrgq3TpATNYo95qw.png)
    
    Let’s move into this directory to see what the contents of it are:
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*RyUqATrXMuP_2lZ2gZcrrQ.png)
    
    Contents after extracting the image
    
    Here we have a zip file and another folder called “base_images”. First let’s unzip the file to see if we get anything valuable.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*JLrHdXo49OATleUwO4Jz6A.png)
    
    Unzipping the file
    
    Looks
     like it had some images, and made a directory called “base_images” 
    which already exists. Let’s move into that directory now.
    
    ![](https://miro.medium.com/v2/resize:fit:952/1*nQbB-a-3OLoO-iUL6syFHg.png)
    
    Here we have another file.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*48f8LVNvDrE78HW7QRsstQ.png)
    
    Looks exactly like the previous one, maybe binwalking this image will give us more details?
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*ons8iy3lIkhhzWtlKJxGHw.png)
    
    We seem to have gotten another directory called “_2_c.jpg.extracted”. Let’s move into this directory.
    
    ![](https://miro.medium.com/v2/resize:fit:1204/1*E73ZihhYxEEZI22R4xA8nQ.png)
    
    The same method we used earlier, would probably help us with enumerating further.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*vNv5pAXXHegBX2dRm4UYDQ.png)
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*oRQf9KBeYh_wP72IDKoLbQ.png)
    
    And we get this image:
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*7Dgg2oh0T03Q5A5mS6mWow.png)
    
    We use the same steps again, binwalking, unzipping, and changing directories.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*5ooevfxPN-kQU2nw9edQ_Q.png)
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*eWrCtCEHrY_qBTIl7BomcA.png)
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*IyiusrWC0dQRPCVUziWUQw.png)
    
    And finally after enumerating further, we get this:
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*0_I-fCt8fSAYdUtagd3JKQ.png)
    
    Opening the file, we get the contents of flag.txt
    
    picoCTF{e3f378fe6c1ea7f6bc5ac2c3d6801c1f}
    
- **Wireshark doo dooo do doo... (Medium)**
    
    Author: Dylan
    
    ### Description
    
    Can you find the flag? [shark1.pcapng](https://mercury.picoctf.net/static/d6f9aa16d2a2c51d2e431e658d87af9e/shark1.pcapng).
    
    Solution:
    
    Wireshark is a network analyzer tool.
    
    Here
     we are given a file which has dump of data captured over the network. 
    From this dump we need to find something useful and in this case the 
    flag.
    
    After a bit of searching around, using filters etc tried to follow TCP stream
     and tried finding something useful and after a bit of scrolling then in
     stream 5 we have something useful finally :D
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*LGCH6wmBiGyFsFb-iqvu_A.png)
    
    The last line is something kind of like the flag but its encrypted version.
    
    Trying it in [https://www.dcode.fr/cipher-identifier,](https://www.dcode.fr/cipher-identifier) it comes out to be ROT13 cipher and on decrypting it we have our flag Yay!!!!
    
    picoCTF{p33kab00_1_s33_u_deadbeef}
    
- **Disk, disk, sleuth! (Medium)**
    
    Author: syreal
    
    ### Description
    
    Use `srch_strings` from the sleuthkit and some terminal-fu to find a flag in this disk image: [dds1-alpine.flag.img.gz](https://mercury.picoctf.net/static/f63e4eba644c99e92324b65cbd875db6/dds1-alpine.flag.img.gz)
    
    Solution:
    
    Extract the disk by running `gunzip dds1-alpine.flag.img.gz`.
    
    Make sure `autopsy` is installed (`sudo apt install autopsy`).
    
    Use the `srch_strings` command as suggested by the challenge and then search for `picoCTF`: `srch_strings dds1-alpine.flag.img | grep picoCTF`
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2022.png)
    
    picoCTF{f0r3ns1c4t0r_n30phyt3_ad5c96c0}
    
- **tunn3l v1s10n (Medium)**
    
    Author: Danny
    
    ### Description
    
    We found this [file](https://mercury.picoctf.net/static/7b2d7c26630e977197022d0af09e3aeb/tunn3l_v1s10n). Recover the flag.
    
    Solution:
    
    I have downloaded the file. Running ‘file’ command gave the type ‘data’. Nothing specific.
    
    So, I have tried ‘exiftool’ on the file.
    
    > exiftool tunn3l_v1s10n
    > 
    
    ![](https://miro.medium.com/v2/resize:fit:910/1*1R05nvSzhVhANCG3U_jOlg.png)
    
    The output gave away that the file type is ‘bmp’ i.e., a Bitmap image.
    
    I renamed it with ‘.bmp’ as extension and tried opening it. But, it gave the error below.
    
    ![](https://miro.medium.com/v2/resize:fit:1082/1*VhUXypMfHnm1Eqja7eRXUg.png)
    
    So, this has something to do with the headers, which I’m not at all familiar with.
    
    But,
     to take a look, I used ‘hexedit’ to view the data of the file in hex 
    format. (hexedit displays both hex values and their ASCII 
    representation).
    
    > hexedit tunn3l_v1s10n
    > 
    
    ![](https://miro.medium.com/v2/resize:fit:1122/1*52qnkWoPVfetUBREBmr4Tg.png)
    
    So much that I don’t understand. So, I googled to make some sense about ‘bitmap’ headers and stumbled upon [this](http://www.ece.ualberta.ca/~elliott/ee552/studentAppNotes/2003_w/misc/bmp_file_format/bmp_file_format.htm) website, which is great. It has all the details about bitmap headers and a newbie like me was able to understand some of it.
    
    I
     took a ‘normal’ bitmap image and compared its hex with the hex of the 
    provided file. I noticed something and then, it seemed strange.
    
    ![](https://miro.medium.com/v2/resize:fit:1156/1*rY-1245CrZYEqXn7h2clHQ.png)
    
    At
     an offset of 14 bytes, the ‘InfoHeader’ begins, with the first 4 bytes 
    specifying the ‘Size’ of the ‘InfoHeader’. It should generally look like
     “28 00 00 00”, which means 0x28=40 bytes (bytes are displayed in 
    little-endian order — least significant bit first). But, in this file, 
    it looked like “BA D0 00 00”, which means 0xD0BA=53434 bytes. 
    ‘InfoHeader’ should be of 40 bytes, so I changed those bytes to “28 00 
    00 00” and saved it.
    
    Now,
     I tried to open it and it gave me a decoy flag, “notaflag{sorry}”. 
    Well, we’re making progress and are treading the way they paved.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*o49cLzZKiT56dLRhJ-lNhw.png)
    
    I tried to convert this ‘.bmp’ image to ‘.jpg’ images online, but wasn’t making progress.
    
    So, I got back to inspecting the hex bytes of the image again. Something else caught my eye this time.
    
    At
     an offset of 10 bytes from the beginning, 4 bytes are reserved to 
    indicate the ‘DataOffset’. In Layman terms, it tells the image parser 
    softwares, ‘an offset’ from which the actual image data (pixels which 
    contain different colors) begin. Those softwares parse the values from 
    the specified offset and render the values to display the image.
    
    ![](https://miro.medium.com/v2/resize:fit:1148/1*Ilpic1QeOK3XCQ1qTmA4iw.png)
    
    For
     a normal bitmap image, the ‘DataOffset’ looks like “36 00 00 00”, which
     means 0x36=54 bytes. But, for this image, it was “ BA D0 00 00”, which 
    means (yeah, you know it) 0xD0BA=53434 bytes. This, in general, should 
    mean that the metadata of the image extends from the beginning of the 
    file, upto 53434 bytes, which is ridiculously large. It might means that
     there is a lot more actual ‘image data’ but, the offset is preventing 
    it from being displayed. (Meaning, the image is being displayed 
    somewhere from the middle and not from its actual beginning. It is in 
    some way, similar to cropping out some portion of the image).
    
    The
     dimensions of the image were 1134x306. But, I think there’s more to 
    this because of the above theory. So, I thought of messing with the 
    width and height parameters of the image to reveal something. At an 
    offset of 18 bytes, 4 bytes are specified for indicating the ‘Width’ of 
    the image. I tried changing it. On changing this, the image got 
    distorted but, nothing new was being revealed so, changed it back to the
     original value.
    
    ![](https://miro.medium.com/v2/resize:fit:1142/1*d_LZgX3CNmq9viRHNvpmqw.png)
    
    Those bytes signify the perceived width of the image (little-endian order)
    
    Now,
     its time to mess with ‘height’. At an offset of 22 bytes, 4 bytes are 
    reserved for indicating the ‘height’ parameter of the image. It was “32 
    01 00 00”, which means 0x132=306 pixels.
    
    ![](https://miro.medium.com/v2/resize:fit:1142/1*c19oE_hC9fMmAt4CAGNTZg.png)
    
    Highlighted bytes signify the perceived height of the image
    
    So, I tried changing it to “32 03 00 00”, which means 0x332=818 pixels.
    
    ![](https://miro.medium.com/v2/resize:fit:1140/1*cJmXuUihqHtSf9HOCtIgFg.png)
    
    Changed height parameter
    
    Opening this gave out the flag. (Check the top right corner of the image).
    
    picoCTF(qu1te3_a_v13w_2020}
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*WcR0qE1EbgJg13MS01zHDg.png)
    
- **Wireshark twoo twooo two twoo... (Medium)**
    
    Author: Dylan
    
    ### Description
    
    Can you find the flag? [shark2.pcapng](https://mercury.picoctf.net/static/7b8e53329b34946177a9b5f2860a0292/shark2.pcapng).
    
    Solution:
    
    ***Follow (tcp stream)***
    
    Obviously, DNS exfiltration, so let open up one of the sites requested by http
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*-YcLaOS7t-g7mHRbW1-HhQ.jpeg)
    
    fake flag
    
    YUb, I found the flag but I doubt that this is correct, Let’s look further.
    
    let’s check another request, oops I found another flag I still doubt that is correct.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*NWJ9syNy8UqAY8Wo63azyw.jpeg)
    
    oops found another flag
    
    ***Strings command***
    
    there seem to be a lot of requests to a `/flag` endpoint. Each request shows a different flag so these must be a distraction let’s check by another way.
    
    You’ll find tons of fake flag. Obviously, it’s a trap to distract you.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*BCACyPbP-eOw2nLbToSrYw.jpeg)
    
    Stings command with grep ‘pico’
    
    ***Intruder letters***
    
    After searching through the file, I noticed many DNS requests for various subdomains of < intruder letters>`reddshrimpandherring.com`
    
    I found subset of DNS queries have destination of 18.217.1.75, apply this destination as a filter.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*fILgmLXJJ-0jCEEM0HBylw.jpeg)
    
    If we take the intruder letter of `reddshrimpandherring.com` and append them in order we get: `cGljb0NURntkbnNfM3hmMWxfZnR3X2RlYWRiZWVmfQ==`
    
    ***flag***
    
    Decoding the above string as base64 gives us the flag.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*m5iwe9hsdpYGPqpIZTaM3A.jpeg)
    
    picoCTF{dns_3xf1l_ftw_deadbeef}
    
- **Trivial Flag Transfer Protocol (Medium)**
    
    Author: Danny
    
    ### Description
    
    Figure out how they moved the [flag](https://mercury.picoctf.net/static/88553d672efbccbc5868002f4c6eb737/tftp.pcapng).
    
    Solution:
    
    And we get the file, it’s a network capture file, i will use WireShark to see what it contains
    
    > wireshark tftp.pcapng
    > 
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*XOFjqXXTBoYecqgEXum3BQ.png)
    
    View pcapng file by Wireshark
    
    There’s a lot of stuff going on here, isn’t it? But most of the network traffic
     here are TFTP. I gotta be honest that i’ve never used TFTP before, so 
    why don’t we take a brief look on Google to see what TFTP really is? can
     we pet it?
    
    After a while of researching, i found out that in a nutshell TFTP is a file 
    transfer protocol using UDP without the need of authentication and data 
    encryption. Though UDP is not reliable but the protocol itself is 
    reliable due to implementing ACK packet and it quite simple. Indeed, it 
    works like this:
    
    [](https://miro.medium.com/v2/resize:fit:1024/0*yETV38Vot7gtQZGS)
    
    TFTP flow illustration
    
    Simple, isn’t it?
    
    Then i did some filter on the capture frame to see what were sent and received
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*hJCFFNTVB0DTXJz-LY5W9g.png)
    
    Filter wireshark frame
    
    > tftp.type
    > 
    
    We can see the files were sent in this order “instructions.txt”, “plan”, 
    “picture1.bmp”, “picture2.bmp”, “picture3.bmp”. Now let’s export all of 
    them to see what they contains by clicking File -> Export Object 
    -> …TFTP
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*QlUv4896nak3WSgYULqLew.png)
    
    Then we can click Save All → Choose Folder to save → Click OK. Now we have 
    got all the files we need, let’s dig in the same order all the files 
    were sent. The first one is “instruction.txt”.
    
    > cat ./instructions.txt
    > 
    
    And we get
    
    > GSGCQBRFAGRAPELCGBHEGENSSVPFBJRZHFGQVFTHVFRBHESYNTGENAFSRE.SVTHERBHGNJNLGBUVQRGURSYNTNAQVJVYYPURPXONPXSBEGURCYNA
    > 
    
    What is this? those text are just none sense. Maybe it’s encoded? Let’s me introduce you to the ROT13 “**rotate by 13 places”.** Why Rot13? i gotta be honest that i don’t know, it’s just my intuitive when
    it comes to CTF, it should be base64 decode or Rot13 decoding.
    
    ![](https://miro.medium.com/v2/resize:fit:1400/0*VEwCahWmSD0KGxXE.png)
    
    How Rot13 works
    
    After doing a Rot13 decode (you can go to [https://rot13.com](https://rot13.com/) to decode it), we get
    
    > TFTPDOESNTENCRYPTOURTRAFFICSOWEMUSTDISGUISEOURFLAGTRANSFER.FIGUREOUTAWAYTOHIDETHEFLAGANDIWILLCHECKBACKFORTHEPLAN
    > 
    
    Now it makes sense isn’t it? let’s add some space into the decoded text, now we have
    
    > TFTP
     DOESNT ENCRYPT OUR TRAFFIC SO WE MUST DISGUISE OUR FLAG TRANSFER. 
    FIGURE OUT A WAY TO HIDE THE FLAG AND I WILL CHECK BACK FOR THE PLAN
    > 
    
    Ok, it says what it means, “I will check back for the plan” and we have the “plan” file which we got earlier from the pcapng file, remember? Then let’s dig in that file
    
    > cat ./plan
    > 
    
    And once again we get some nonsense text
    
    > VHFRQGURCEBTENZNAQUVQVGJVGU-QHRQVYVTRAPR.PURPXBHGGURCUBGBF
    > 
    
    Yep, i did Rot13 decoding again, and we got
    
    > IUSEDTHEPROGRAMANDHIDITWITH-DUEDILIGENCE.CHECKOUTTHEPHOTOS
    > 
    
    With some spaces added, it just make sense :)
    
    > I USED THE PROGRAM AND HID IT WITH-DUE DILIGENCE. CHECKOUT THE PHOTOS
    > 
    
    “The program”? we also get a program which is “program.deb” from the traffic
     file, i know it’s a bad idea but i’m gonna install the program
    
    > sudo apt-get install ./program.deb
    > 
    
    If you pay attention to the log on your screen while installing the file 
    says “Note, selecting ‘steghide’ instead of ‘./program.deb’” which tell 
    you the actual program name is steghide. Now we gotta check out what 
    steghide is and how to use it :((. [http://steghide.sourceforge.net/](http://steghide.sourceforge.net/)
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*APUujclQhzTVJlVkdnzNRw.png)
    
    Steghide description
    
    Hmmm… it supports hiding data in bmp file, no doubt the flag must be in the 
    .bmp file which we got earlier. Well, if you also don’t know what bmp 
    file is (as i am at that point :V ). It’s a picture file format, and bmp
     stands for “**Bitmap Image format”.** Alright,
     let’s go back to the steghide program, as the documentation says, we 
    can reverse our flag by using this command, but it requires a password:
    
    > steghide extract -sf <fiflename> -p <password>
    > 
    
    Do you remember the decoded text in the “plan” file which we got earlier? 
    It says “WITH-DUEDILIGENCE”. What if “DUEDILIGENCE” is our password? 
    There’s only one way to know
    
    > steghide extract -sf ./picture1.bmp -p “DUEDILIGENCE”
    > 
    
    We got “steghide: could not extract any data with that passphrase!”. Let’s try it with the other two images
    
    > steghide extract -sf ./picture2.bmp -p “DUEDILIGENCE”
    > 
    
    Still, we got nothing, but i got luck with the last one :)
    
    > steghide extract -sf ./picture3.bmp -p “DUEDILIGENCE”
    > 
    
    The Console output with wrote extracted data to “flag.txt”. it must be the flag here :). Let’s cat it.
    
    > cat ./flag.txt
    > 
    
    And the console output is:
    
    picoCTF{h1dd3n_1n_pLa1n_51GHT_18375919}
    
- **Pitter, Patter, Platters (Medium)**
    
    Author: syreal
    
    ### Description
    
    'Suspicious' is written all over this disk image. Download [suspicious.dd.sda1](https://jupiter.challenges.picoctf.org/static/0d39390cff1ab51699596b6e650e7cba/suspicious.dd.sda1)
    
    Solution:
    
    For this challenge, I was given a raw disk image file (`suspicious.dd.sda1`). The first thing I did was inspect the file layout with:
    
    `fdisk -l suspicious.dd.sda1`
    
    After confirming it was a valid partition, I listed its filesystem structure using `fls`:
    
    `fls suspicious.dd.sda1`
    
    This showed a file entry:
    r/r 12: suspicious-file.txt
    
    I extracted the contents of that file with:
    
    `icat suspicious.dd.sda1 12`
    
    The contents said:
    
    **"Nothing to see here! But you may want to look here -->"**
    
    This suggested that there might be hidden data in the **slack space** (unused bytes between the end of file content and the end of the disk cluster). To find where this string is located in raw disk space, I searched for it using:
    
    `strings -a -t x suspicious.dd.sda1 | grep "Nothing to see here!"`
    
    Which returned:
    
    `200400 Nothing to see here! But you may want to look here -->`
    
    That told me the string starts at hex offset `0x200400`. To inspect the data after that location (i.e., possibly in slack), I dumped 200 bytes from that offset:
    
    `xxd -s 0x200400 -l 200 suspicious.dd.sda1`
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2023.png)
    
    And sure enough, that showed the flag — but **in reverse**. So I copied the reversed flag:
    
    `}83460cae_3<_|Lm_111t5_3b{FTCocip`
    
    I used CyberChef to reverse the string, giving me the final flag:
    
    picoCTF{b3_5t111_mL|_<3_eac06438
    
- **shark on wire 2 (Medium)**
    
    Author: Danny
    
    ### Description
    
    We found this [packet capture](https://jupiter.challenges.picoctf.org/static/b506393b6f9d53b94011df000c534759/capture.pcap). Recover the flag that was pilfered from the network.
    
    Solution:
    
    This challenge was a deceptive Forensics problem that relied solely on Wireshark for analysis. At first glance, one might expect to simply follow TCP or UDP streams to locate the flag. However, this approach proves ineffective, as the challenge contains many false flags scattered throughout the packet capture to intentionally mislead the analyst.
    
    To solve the challenge, the key was to search through the raw packet data for specific keywords. By using the search function (`Ctrl+F` on Windows or `Cmd+F` on Mac/Linux), and filtering for the strings “start” and “end” in the **Packet Bytes** pane, it becomes possible to locate two important packets. One packet contains only the string “start” as its payload, and another, later in the timeline, contains “end”. These two packets serve as clear delimiters, marking the beginning and end of the true data sequence.
    
    Upon inspecting the “start” packet more closely, it was observed that the source IP address was `10.0.0.66`. Following this lead, all packets originating from this IP address were isolated by applying the Wireshark display filter `ip.addr == 10.0.0.66`. This reduced the noise significantly, making the relevant packets easier to analyze.
    
    To gain additional insight into the packets, transport address resolution was enabled through the Wireshark menu under **View > Name Resolution > Resolve Transport Address**. With this option enabled, a 4-digit number could be seen in each packet's transport layer info—typically beginning with the digit 5 (e.g., 5021, 5097, 5132, etc.).
    
    The method to extract the flag involved taking the **last three digits** from each of these 4-digit numbers, in the order they appear in the timeline. Each 3-digit number was then interpreted as an ASCII value. For example, the number 5021 yields `021`; the ASCII character for decimal 21 is a control character, so likely in this case it was actually 066 (from 5066), which maps to 'B'. Continuing this process for each packet between “start” and “end”, a sequence of ASCII characters is formed that ultimately reveals the correct flag.
    
    This technique bypasses all the planted decoys and false flags by focusing only on a pattern tied to a specific IP and a structured payload format. It demonstrates the importance of careful inspection, filtering, and pattern recognition in network forensic challenges.
    
    to get the ports I did 
    
    tshark -r capture.pcap -T fields -e udp.port -Y "udp.port == 22" > ports.txt
    And edited them using Notepad++ with the Replace feature (Ctrl + h)
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2024.png)
    
    picoCTF{p1LLf3r3d_data_v1a_st3g0}
    
- **like1000 (Medium)**
    
    Author: Danny
    
    ### Description
    
    This [.tar file](https://jupiter.challenges.picoctf.org/static/52084b5ad360b25f9af83933114324e0/1000.tar) got tarred a lot.
    
    Solution:
    
    For this challenge, I was given a `.tar` file — specifically `1000.tar`. At first glance, it just looked like a regular archive, but after extracting it once, I noticed that it contained another `.tar` file inside... and *another*... and *another*. Basically, it was a **recursive archive**.
    
    Rather than manually extracting layer after layer (which could take forever), I went for a smarter approach.
    
    I used `foremost`, a file carving tool that's great for recovering embedded files based on headers/footers — even deep inside binary blobs or archives:
    
    `foremost 1000.tar`
    
    It scanned through all the nested `.tar` content and eventually pulled out a `.png` file from deep inside the layers. Opening the `.png` file revealed the **flag** embedded inside the image.
    
    picoCTF{l0t5_0f_TAR5}
    
- **What Lies Within (Medium)**
    
    Author: Julio/Danny
    
    ### Description
    
    There's something in the [building](https://jupiter.challenges.picoctf.org/static/011955b303f293d60c8116e6a4c5c84f/buildings.png). Can you retrieve the flag?
    
    Solution:
    
    So for this, we are given a png file, after scanning the file I used zsteg to check the contents of the file and it gave me the flag.
    
    zsteg -s all buildings.png
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2025.png)
    
    picoCTF{h1d1ng_1n_th3_b1t5}
    
- **UnforgottenBits (Hard)**
    
    Author: LT 'syreal' Jones
    
    ### Description
    
    Download this disk image and find the flag.
    Note: if you are using the webshell, download and extract the disk image into
    
    ```
    /tmp
    ```
    
    not your home directory.
    
    - [Download compressed disk image](https://artifacts.picoctf.net/c/488/disk.flag.img.gz)
    
    Solution:
    
- **DISKO 3 (Medium)**
    
    Author: Darkraicg492
    
    ### Description
    
    Can you find the flag in this disk image?
    This time, its not as plain as you think it is!
    Download the disk image [here](https://artifacts.picoctf.net/c/542/disko-3.dd.gz).
    
    Solution:
    
    So for this challenge, I was given a disk. Now what I did first after extracting it was to first check its contents using 
    
    fdisk -l disko-3.dd
    
    Seeing as it was only one partition, I tried to look inside the disk itself.
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2026.png)
    
    I saw that there seems to be a log inside, so I checked inside it and saw a flag.gz file. Curious I extracted it from the disk into my folder.
    
    ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2027.png)
    
    cat disko-3.dd 522628 > flag.gz
    After extracting the file, It contained a .txt file and opening it gave me the flag
    
    picoCTF{n3v3r_z1p_2_h1d3_7e0a17da}
    
- **c0rrupt (Medium)**
    
    Author: Danny
    
    ### Description
    
    We found this [file](https://jupiter.challenges.picoctf.org/static/ab30fcb7d47364b4190a7d3d40edb551/mystery). Recover the flag.
    
    Solution:
    
    ### Step 1: Identifying the File Type
    
    We’re given a file named ***mystery*** and need to figure out what type of file it is and repair it to recover the flag.
    
    I started by using the ***file*** command to determine the file type:
    
    ```
    $ file mystery
    mystery: data
    ```
    
    The result, ***data***, is the default output when the ***file*** command cannot recognize the file type. This aligns with the hint about a broken file header, so let’s inspect it further.
    
    # Step 2: Examining the File Header
    
    To understand the file structure, I used the ***xxd*** command to generate a hexdump of the file’s header:
    
    ```
    $ xxd -g 1 mystery | head
    00000000: 89 65 4e 34 0d 0a b0 aa 00 00 00 0d 43 22 44 52  .eN4........C"DR
    00000010: 00 00 06 6a 00 00 04 47 08 02 00 00 00 7c 8b ab  ...j...G.....|..
    ```
    
    The ***xxd*** command generates a hexdump of the specified file. In this case, the ***| head*** ensures that only the beginning of the hexdump is shown, not the entire file. The ***-g*** flag separates the output into groups of bytes, with ***1***
     specifying that each group contains one byte (represented as two 
    hexadecimal characters) and separated by a space. For more details, you 
    can refer to the [documentation](https://linux.die.net/man/1/xxd).
    
    From this output, I noticed elements like ***gAMA*** and ***pHYs***, which are typically found in **PNG** files. However, the magic numbers—the first 8 bytes—were incorrect. PNG files should start with:
    
    ```
    89 50 4E 47 0D 0A 1A 0A
    ```
    
    # Step 3: Fixing the Magic Numbers
    
    I started by creating a copy of the mystery file and saving it as ***fixed.png***. This way, I preserved the original file and worked on the copy, allowing me to revert to the original if needed.
    
    ```
    $ cp mystery fixed.png
    ```
    
    The next command is slightly more complex as it combines two operations.
    
    ```
    $ printf '\x89\x50\x4E\x47\x0D\x0A\x1A\x0A' | dd of=fixed.png bs=1 seek=0 count=8 conv=notrunc
    ```
    
    First, the ***printf*** command is used to output data in a specific format. In this case, ***\x*** is used to represent hexadecimal values corresponding to the PNG magic numbers. Unlike the ***echo*** command, which doesn’t handle formatting, ***printf*** ensures the output is correctly structured.
    
    The output of ***printf*** is then passed to the ***dd*** command using a pipe ***(|)***, which directs the result of one command as input to another. The ***dd*** command is used here to write the data to the ***fixed.png*** file with specific formatting and options.
    
    The ***of=fixed.png*** specifies the file to write to, ***bs=1*** sets the block size to one byte, and ***seek=0*** ensures writing starts at the very beginning of the file. The ***count=8*** limits the operation to 8 bytes (the size of the PNG magic numbers), while ***conv=notrunc*** ensures the file is not truncated and only these bytes are overwritten.
    
    This combination allows precise modification of the ***fixed.png*** file, adding the correct PNG magic numbers without altering the rest of its content.
    
    Let’s verify the fix:
    
    ```
    $ xxd -g 1 fixed.png | head
    00000000: 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 43 22 44 52  .PNG........C"DR
    ```
    
    The magic numbers are now correct!
    
    # Step 4: Correcting the IHDR Chunk
    
    Next, I noticed the ***IHDR*** chunk was corrupted. After the magic number, a PNG file typically contains the ***IHDR*** chunk. However, as seen in the output above, we have ***C”DR*** instead. To fix this, I replaced the relevant bytes:
    
    ```
    $ printf '\x00\x00\x00\x0D\x49\x48\x44\x52' | dd of=fixed.png bs=1 seek=8 count=8 conv=notrunc
    ```
    
    This command is similar to the one in step 3, but with a few key differences. The ***\x49\x48\x44\x52*** part corrects the chunk type to ***IHDR***, while ***seek=8*** specifies the position in the file where the writing begins.
    
    Now, let’s check if the file is recognized as a PNG:
    
    ```
    $ file fixed.png
    fixed.png: PNG image data, 1642 x 1095, 8-bit/color RGB, non-interlaced
    ```
    
    Success! The file is identified as a PNG, but it’s not yet viewable.
    
    # Step 5: Resolving Remaining Errors
    
    Using the ***pngcheck*** tool, I identified additional errors:
    
    ```
    $ pngcheck -c -v fixed.png 2>/dev/null
    ```
    
    Zoom image will be displayed
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*cKwPf9LFCGvjivtKdUc6UQ.png)
    
    **Image 1:** Output from pngcheck
    
    As you can see, the file still contains errors. Specifically, the ***CRC*** error in the ***pHYs*** chunk is incorrect. Let’s fix it by replacing the incorrect bytes:
    
    ```
    $ printf '\x38\xD8\x2C\x82' | dd of=fixed.png bs=1 seek=79 count=4 conv=notrunc
    ```
    
    Now, we verify if the ***CRC*** error was fixed:
    
    ```
    $ pngcheck -c -v fixed.png 2>/dev/null
    ```
    
    Zoom image will be displayed
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*Vx6rB3C2gxz33N3dy9LVig.png)
    
    **Image 2:** Output from pngcheck
    
    We have resolved the issue with the ***CRC*** error, but we still have an invalid chunk length.
    
    # Step 6: Fixing the Chunk Length
    
    Let’s revisit the hexadecimal header, starting right after the ***pHYs*** chunk, as everything up to that point has been corrected.
    
    ```
    $ xxd -g 1 -s 0x53 -l 77 fixed.png | head
    00000053: aa aa ff a5 ab 44 45 54 78 5e ec bd 3f 8e 64 cd  .....DETx^..?.d.
    00000063: 71 bd 2d 8b 20 20 80 90 41 83 02 08 d0 f9 ed 40  q.-.  ..A......@
    ```
    
    In the command above, the ***-s*** flag followed by ***0x53*** specifies the starting point, which in this case is the end of the ***pHYs*** chunk. The ***-l 77*** flag indicates the length to display, corresponding to the end of the first header command.
    
    As we know, the first 4 bytes of a chunk represent its size. Here, we have ***aa aa ff a5***, which indicates an unusually large size. Another notable detail is that the ***DET***
     chunk does not exist in the PNG as a chunck, suggesting an error. Upon 
    reviewing the PNG specification, I identified that the most likely 
    intended chunk is the ***IDAT*** chunk. To fix this, we simply need to:
    
    ```
    $ printf '\x49\x44\x41\x54' | dd of=fixed.png bs=1 seek=87 count=4 conv=notrunc
    ```
    
    Now that we’ve corrected the ***IDAT*** chunk, let’s address the issue with its size. According to the PNG specification:
    
    > “There can be multiple IDAT chunks; if so, they must appear consecutively with no other chunks in between.”
    > 
    
    Let’s check if there are additional ***IDAT*** chunks and determine the size difference between this one and the next with the command:
    
    ```
    $ binwalk -R "IDAT" fixed.png
    DECIMAL       HEXADECIMAL     DESCRIPTION
     ----------------------------------------
     ----------------------------------------
     87            0x57            Raw signature (IDAT)
     65544         0x10008         Raw signature (IDAT)
     131080        0x20008         Raw signature (IDAT)
     196616        0x30008         Raw signature (IDAT)
    ```
    
    The first ***IDAT*** chunk starts at ***0x57***, and the next begins at ***0x10008***. In PNG files, the end of a chunk is 4 bytes before the start of the next one. Therefore, the first chunk ends at:
    
    ```
    0x10008 - 0x4 = 0x10004
    ```
    
    To calculate the size of the first chunk, subtract the starting point of the data (***0x5B***, which is ***0x57 + 4*** for the length field) and account for the checksum:
    
    ```
    0x10004 - 0x5B - 0x4 = 0xFFA5
    ```
    
    Because
     our size field contains incorrect values (which are AA AA), I replaced 
    them with the correct bytes for the chuck size. For ***0xFFA5***, the first two bytes would be ***00 00***. With the corrected size, we can update the length field:
    
    ```
    $ printf '\x00\x00' | dd of=fixed.png bs=1 seek=83 count=2 conv=notrunc
    ```
    
    After these adjustments, the file passed all ***pngcheck*** validations:
    
    ```
    $ pngcheck -c -v fixed.png 2>/dev/null
    ```
    
    Zoom image will be displayed
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*xjqGxt1rtzHYFmafhLuhig.png)
    
    **Image 3:** Output from pngcheck
    
    # Step 7: Viewing the Image
    
    Opening the file revealed the image with the flag:
    
    Zoom image will be displayed
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*qF6_SC0Oniygc7JCZINeYQ.jpeg)
    
    picoCTF{c0rrupt10n_1847995}
    
- **WhitePages (Medium)**
    
    Author: John Hammond
    
    ### Description
    
    I stopped using YellowPages and moved onto WhitePages... but [the page they gave me](https://jupiter.challenges.picoctf.org/static/74274b96fe966126a1953c80762af80d/whitepages.txt) is all blank!
    
    Solution:
    
    # Step 1: Inspecting the File
    
    The challenge description hints that the information isn’t immediately visible, which suggests hidden data within the file.
    
    After downloading the file ***whitepages.txt***, I opened it using a simple text editor like ***Kate*** or ***Sublime*** — but it appeared empty. Since nothing was visible, I suspected hidden characters or special encoding.
    
    To get more information, I decided to inspect the ***hex representation*** of the file using the ***xxd*** command:
    
    ```
    $ xxd -g 1 whitepages.txt
    ```
    
    This revealed the following output:
    
    ```
    00000000: e2 80 83 e2 80 83 e2 80 83 e2 80 83 20 e2 80 83  ............ ...
    00000010: 20 e2 80 83 e2 80 83 e2 80 83 e2 80 83 e2 80 83   ...............
    00000020: 20 e2 80 83 e2 80 83 20 e2 80 83 e2 80 83 e2 80   ...... ........
    ```
    
    The file wasn’t empty at all! Instead, it contained a repeating “***e2 80 83***” pattern along with “***20***” scattered throughout.
    
    # Step 2: Understanding the Hidden Pattern
    
    By examining the repeating “***e2 80 83***”
     sequence, I noticed a possible encoding pattern. After searching 
    online, I found that these hexadecimal values correspond to a ***UNICODE EM SPACE***.
    
    Here’s a quick breakdown:
    
    Zoom image will be displayed
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*fv1Obtotuv28BxurdFkngw.jpeg)
    
    **Image 1**: Adapted table from [Wikipedia](https://en.wikipedia.org/wiki/Whitespace_character).
    
    The second pattern, “**20**”, represents a ***regular ASCII space***.
    
    At this point, I had two distinct space characters (“***e2 80 83”*** and “***20***”)
     appearing repeatedly. This suggested a possible encoding system, but I 
    wasn’t sure if it was binary yet. Since binary encoding often relies on ***two distinct symbols***, I hypothesized that one type of space could represent ***0*** and the other could represent ***1***.
    
    # Step 3: Decoding the Hidden Binary Data
    
    To test this, I wrote a simple Python script to convert these spaces into binary, then decode them into readable text.
    
    Here’s the script:
    
    ```
    def convertSpacesToBinary():
        with open('whitepages.txt', 'rb') as f:
            result = f.read()
        result = result.replace(b'\xe2\x80\x83', b'0')  # Unicode EM SPACE -> 0
        result = result.replace(b'\x20', b'1')  # ASCII Space -> 1
        result = result.decode()
        return result
    
    def convertFromBinaryToASCII(binaryValues):
        binary_int = int(binaryValues, 2)
        byte_number = (binary_int.bit_length() + 7) // 8
        binary_array = binary_int.to_bytes(byte_number, "big")
        ascii_text = binary_array.decode('ascii')
        print(ascii_text)
    
    convertFromBinaryToASCII(convertSpacesToBinary())
    ```
    
    ## How the Script Works
    
    The ***convertSpacesToBinary***
     function first reads the file as raw bytes, ensuring that all 
    characters, including non-visible ones, are captured accurately. It then
     replaces occurrences of the ***UNICODE EM SPACE*** (e2 80 83) with 0 and replaces ***ASCII*** space (20) with 1, effectively converting the hidden pattern into a binary sequence.
    
    The ***convertFromBinaryToASCII***
     function takes this binary sequence and processes it further. It first 
    converts the binary string into an integer, then transforms that integer
     into a byte array. Finally, it decodes the byte array into an ASCII 
    string, revealing the hidden message embedded within the file.
    
    # Step 4: Extracting the Flag
    
    After running the script, the hidden binary data was successfully decoded into ASCII text — revealing the ***flag***.
    
    Zoom image will be displayed
    
    ![](https://miro.medium.com/v2/resize:fit:1400/1*8vxn4fM_W5RiJE7KNLENdg.jpeg)
    
    **Image 2**: Flag
    
    **Final Flag (in base64 encoding):**
    
    `cGljb0NURntub3RfYWxsX3NwYWNlc19hcmVfY3JlYXRlZF9lcXVhbF9jNTRmMjdjZDA1YzIxODlmODE0N2NjNmY1ZGViMmU1Nn0=**Note:** To decode run:echo -n "encoded_string" | base64 --decode`
    
    picoCTF{not_all_spaces_are_created_equal_c54f27cd05c2189f8147cc6f5deb2e56}
    
- **shark on wire 1 (Medium)**
    
    Author: Danny
    
    ### Description
    
    We found this [packet capture](https://jupiter.challenges.picoctf.org/static/483e50268fe7e015c49caf51a69063d0/capture.pcap). Recover the flag.
    
    Solution:
    
    We were given a `.pcap` file to analyze. First thing I always do when dealing with PCAPs is toss it into **Wireshark** — no surprises there.
    
    Since there were no obvious hints or filters given, I took a straightforward approach: check out the **conversations** between IPs to look for any that stand out.
    
    In Wireshark: `Statistics → Conversations`
    
    From there, I sorted the conversations by number of packets — starting with the ones that had the most traffic. I checked each stream manually using: `Follow → TCP Stream`
    Eventually, I landed on a conversation that had **19 packets**. That stream contained some plaintext, and buried in there was the flag.
    
    picoCTF{StaT31355_636f6e6e}
    
- **m00nwalk (Medium)**
    
    Author: Joon
    
    ### Description
    
    Decode this [message](https://jupiter.challenges.picoctf.org/static/fc1edf07742e98a480c6aff7d2546107/message.wav) from the moon.
    
    Solution:
    
- **So Meta (Medium)**
    
    Author: Kevin Cooper/Danny
    
    ### Description
    
    Find the flag in this [picture](https://jupiter.challenges.picoctf.org/static/916b07b4c87062c165ace1d3d31ef655/pico_img.png).
    
    ---
    
    Solution:
    
    So for this solution we just used exiftool and found the flag inside it
    
    picoCTF{s0_m3ta_d8944929}
    
    - **WebNet0 (Hard)**
        
        Author: Jason
        
        ### Description
        
        We found this [packet capture](https://jupiter.challenges.picoctf.org/static/0c84d3636dd088d9fe4efd5d0d869a06/capture.pcap) and [key](https://jupiter.challenges.picoctf.org/static/0c84d3636dd088d9fe4efd5d0d869a06/picopico.key). Recover the flag.
        
        Solution:
        
        The challenge began with two files provided by the creator: a `.pcap`
         file, which is a packet capture file, and a key file that seemed to be a
         decryption key. The contents of the key file immediately suggested it 
        was a private key, as indicated by the header in the file:
        
        ![](https://miro.medium.com/v2/resize:fit:1050/1*Ukk181dItY6NP-TSKmrZyA.png)
        
        Upon opening the `.pcap` file in Wireshark, it initially showed nothing but routine headers and seemingly unimportant traffic.
        
        Zoom image will be displayed
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*40tlSyR3twjGHNkyv7JTnw.png)
        
        However,
         a closer inspection revealed something interesting multiple packets 
        contained the keyword "Encrypted." This led me to examine the protocol 
        hierarchy within Wireshark.
        
        Zoom image will be displayed
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*-CN_mT5jqR8NymfgHrtHEg.png)
        
        In the protocol hierarchy, I noticed a significant portion of the traffic was **classified under TLS, or Transport Layer Security**, within the TCP stream. **TLS
         is a protocol designed to ensure privacy and data integrity between 
        client-server communications, often used to secure data transmitted over
         the internet.**
        
        Realizing that the **traffic was encrypted**, I remembered the **key file provided with the challenge.** It was time to decrypt the data. Navigating to the “Preferences” tab in Wireshark, **I accessed the “RSA Keys” settings**. **Knowing that the key file was an RSA private key (thanks to the file’s header), I added it to the RSA keys list in Wireshark.**
        
        Zoom image will be displayed
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*F5CyWNmi_aqIM3IpypzYOA.png)
        
        After refreshing the packet list, the **previously encrypted traffic now appeared as readable HTTP traffic**. To quickly find the flag, I used **Wireshark’s
         built-in filter, searching for “Packet Details” containing the keyword 
        “Pico.” This search led me directly to the flag:**
        
        ![](https://miro.medium.com/v2/resize:fit:244/1*tYazBvZFnrQ8edaH_6nY3w.png)
        
        picoCTF{nongshim.shrimp.crackers}
        

### **WMSUCCS-CTF**

- **Certified Location**
    
    **Category** : Forensics
    **Points** : 25
    
    Trust is encoded, but the truth lies in plain sight.
    
    ## Files :
    
    - [myloc.txt](https://www.notion.so/myloc.txt)
    
    Solution:
    
    I was given a txt file name "myloc.txt", inside the file is what I thought was a pem certificate. However after further analysis. I noticed that it was actually a base64 hash. After decoding it, it gave me a text
    "Location: Quezon City"
    
    im not sure of what the flag format is so im just going to do
    CCS{Quezon_City}
    
- **Grep's Kitchen**
    
    **Category** : Forensics
    **Points** : 25
    
    The chef left a secret recipe somewhere in this mess. Find it before service begins!
    
    ## Files :
    
    - [find](https://www.notion.so/find)
    
    Solution:
    I was given a zip file name here.zip, After extracting the file I was given 2 folders that had multiple text files that contained the same values since each txt file was a copy of the original.
    I checked the amount of files inside and it was a total of 85. I noticed the challenge title being grep so I had a idea to just grep the flag format so I did
    
    grep -r "CCS{" .
    
    and it gave me a .txt file that cointained the format that I gave and after scrolling I was able to find the flag
    
    CCS{grep_is_g00d_f0r_s34rch1ng}
    
- **Header Hunt**
    
    **Category** : Forensics
    **Points** : 50
    
    This file refuses to open. Perhaps it's missing something... fundamental.
    
    ## Files :
    
    - [invalid](https://www.notion.so/invalid)
    
    Solution:
    
    I was given a altered/corrupted file, after using file and exiftool to determine what the file type is. I noticed that it was a jpeg file having JFIF in its hexadecimal values. ANd while reading the title of the challenge. I was able to come up that the issue would be inside the hexademical value specifically in the header part.
    
    After fixing the header values being
    FF D8 FF E0 00 10 4A 46 49 46 00 01
    
    I was able to open the image and was given the flag of
    CCS{M1ss1ng_D0t}
    
- **Hex Trail**
    
    **Category** : Forensics
    **Points** : 25
    
    The end is where the truth hides. Look beyond what meets the eye.
    
    ## Files :
    
    - [alice.jpg](https://www.notion.so/alice.jpg)
    
    Solution:
    
    I was given a jpg file and it contained a picture. Since there wasnt anything suspicious that could be found on the image itself. I noticed the title of the challenge being "Hex Trail". So I figured that the code could either be inside the hex itself or a form of hidden file.
    So I opened ghex and checked for any CCS{ format and I was able to find it at the bottom of the hex.
    
    CCS{0MGsi4L1cE?}
    
- **Lost in Translation**
    
    **Category** : Forensics
    **Points** : 50
    
    Some secrets are hidden in plain sight, but you must see through the layers.
    
    ## Files :
    
    - [WhatIsThis.txt](https://www.notion.so/WhatIsThis.txt)
    
    Solution:
    
    For this challenge, I was given a `.txt` file that, upon inspection, appeared to contain a long string of hexadecimal values. Recognizing that hex can sometimes represent binary data like images, I converted the hex into a binary format and saved it as a `.png` file. When I opened the image, it contained a message or clue that pointed to a website: `https://owpor.github.io/WhereIsIt/`. Visiting the site, nothing was immediately obvious, so I inspected the page using browser developer tools (pressing F12). I checked the **Application** tab (in Chrome) and looked through **Local Storage**, where I found a suspicious key-value entry containing a string that started with `Base64x3:` followed by a long encoded value. That label implied the string had been Base64-encoded **three times**, so I decoded it using a tool like CyberChef or command-line `base64` in three layers. The first decode gave another Base64 string, the second decode revealed another, and the final decode produced the actual flag: `CCS{##@N1c3F0llow$)`. This challenge is a good example of hiding data in unconventional places — in this case, local storage inside a browser-accessed webpage — and layering encodings to obscure the real content.
    
    CCS{##@N1c3F0llow$)
    
- **PDF Mirage**
    
    **Category** : Forensics
    **Points** : 50
    
    This document refuses to open. The fix is simpler than you think... but the secret hides in plain sight.
    
    ## Files :
    
    - [corrupted_T_T.pdf](https://www.notion.so/corrupted_T_T.pdf)
    
    Solution:
    
    I was given a pdf file named "corrupted_T_T.pdf" it contained a text and a wmsu logo the text says "No flag". After reading the description. I did the pdftohtml format to see any changes/layers that were added in the pdf. and after that I was able to get a previous copy of the pdf and got the flag
    
    CCS{N0Fl4Gx?}
    
- **Spectral Whispers**
    
    **Category** : Forensics
    **Points** : 25
    
    Listen closely... or perhaps, look closer. The truth hides in the unseen.
    
    ## Files :
    
    - [musichuh.wav](https://www.notion.so/musichuh.wav)
    
    Solution:
    
    I was given a .wav file, since it says to look for the message I opened up audacity and viewed the wave file as a spectogram.
    After viewing it, I realized that the audio itself was morse code after listening to it a bunch of times. I was given this
    .... - -- .- --.. .---- -. --. .- ..- -.. .---- ---
    After translating would give
    HTMAZ1NG AUD1O
    
    I think the flag is
    CCS{4MAZ1NGAUD1O}
    

### HackTheBox

- **Suspicious Threat (Easy)**
    
    **Type** : Challenge
    **Points** : 30
    
    Our SSH server is showing strange library linking errors, and critical folders seem to be missing despite their confirmed existence. Investigate the anomalies in the library loading process and filesystem. Look for hidden manipulations that could indicate a userland rootkit. Creds: `root:hackthebox`
    
    Solution:
    
    The challenge needed me to connect to the server first using the following command
    
    `ssh root@<ip_address>`    Then we use the password of `hackthebox`
    
    After we read the challenge description, we know that it is somesort of rootkit attack. So we did the command `ldd /bin/ls` to see if there are any malicious/suspicious files that were moved. 
    
    We are able to see a file `/lib/x86_64-linux-gnu/libc.hook.so.6`
    
    Now that we see it, we will be removing/moving it so that it doesnt mess with the server to the tmp folder
    
    `mv /lib/x86_64-linux-gnu/libc.hook.so.6 /tmp`
    
    Now that we have successfull removed the malicious file, we can now check the entire server for a flag file. so we do
    
    `find / -name flag.txt 2>/dev/null` 
    
    and we that it is located and now we just copy the location and use the cat command
    
    `cat /folder/sub-folder/flag.txt` 
    
- **Fishy HTTP (Easy)**
    
    **Type** : Challenge
    **Points** : 30
    
    I found a suspicious program on my computer making HTTP requests to a web server. Please review the provided traffic capture and executable file for analysis. (Note: Flag has two parts)
    
    Solution:
    
    We are given a `pcap`file and a `eexecutable(.exe)` file.
    
    We first checked the `pcap` file to look for any weird connections/events. We are able to see that there seems to be a submissition of a long string of words and at the end has == meaning that it is a form of base64, after further inspection. We are able to deduce that we needed to get the first letters of each word and decode it using base64 from Cyberchef. I made a python script that would decode the file and provide use the base64 string.
    
    `IFZvbHVtZSBpbiBkcml2ZSBDIGhhcyBubyBsYWJlbC4NCiBWb2x1bWUgU2VyaWFsIE51bWJlciBpcyBBMDc5LUFERkINCg0KIERpcmVjdG9yeSBvZiBDOlxUZW1wDQoNCjA1LzA3LzIwMjQgIDA5OjIyIEFNICAgIDxESVI+ICAgICAgICAgIC4NCjA1LzA3LzIwMjQgIDA5OjIyIEFNICAgIDxESVI+ICAgICAgICAgIC4uDQowNS8wNy8yMDI0ICAwNzoyMyBBTSAgICAgICAgNjcsNTE1LDc0NCBzbXBob3N0LmV4ZQ0KICAgICAgICAgICAgICAgMSBGaWxlKHMpICAgICA2Nyw1MTUsNzQ0IGJ5dGVzDQogICAgICAgICAgICAgICAyIERpcihzKSAgMjksNjM4LDUyMCw4MzIgYnl0ZXMgZnJlZQ0KJ2g3N1BfczczNDE3aHlfcmV2U0hFTEx9JyANCg==`
    
    After we decoded it we are given a part of the flag. 
    
    `h77P_s73417hy_revSHELL}`
    
    Now we just need to figure out the final piece of the flag.
    
    To find it, we needed to examine the contents of the executable file. I used `detect-it-easy(die)` to scan the file. We are able to see that it is a `dotNET`script. So I used another tool being OpenLS to scan the contents of the file. We see that it seems to have certain hexes for specific tags.
    
    We wrote another python script to further decode the html tags into ASCII, then we can see that it contains the final piece of the flag. 
    
    Now we just need to merge both of the flag pieces to complete the flag.ge
    
    The challenge needed me to connect to the server first using the following command
    
    `ssh root@<ip_address>`    Then we use the password of `hackthebox`
    
    After we read the challenge description, we know that it is somesort of rootkit attack. So we did the command `ldd /bin/ls` to see if there are any malicious/suspicious files that were moved. 
    
    We are able to see a file `/lib/x86_64-linux-gnu/libc.hook.so.6`
    
    Now that we see it, we will be removing/moving it so that it doesnt mess with the server to the tmp folder
    
    `mv /lib/x86_64-linux-gnu/libc.hook.so.6 /tmp`
    
    Now that we have successfull removed the malicious file, we can now check the entire server for a flag file. so we do
    
    `find / -name flag.txt 2>/dev/null` 
    
    and we that it is located and now we just copy the location and use the cat command
    
    `cat /folder/sub-folder/flag.txt` 
    

### CTFLearn

- **Taking LS  (Easy)**
    
    **Points** : 10
    
    Just take the Ls. Check out this zip file and I be the flag will remain hidden. [https://mega.nz/#!mCgBjZgB!_FtmAm8s_mpsHr7KWv8GYUzhbThNn0I8cHMBi4fJQp8](https://mega.nz/#!mCgBjZgB!_FtmAm8s_mpsHr7KWv8GYUzhbThNn0I8cHMBi4fJQp8)
    
    Solution:
    
    To solve this we needed to find a hidden file inside the folders. After doing ls -la we can see a passwords folder that is made hidden. Opening this will give us the password for the locked pdf. After entering it, we can see the flag
    
    ABCTF{T3Rm1n4l_is_C00l}
    
- **WOW.... So Meta (Easy)**
    
    This photo was taken by our target. See what you can find out about him from it. [https://mega.nz/#!ifA2QAwQ!WF-S-MtWHugj8lx1QanGG7V91R-S1ng7dDRSV25iFbk](https://mega.nz/#!ifA2QAwQ!WF-S-MtWHugj8lx1QanGG7V91R-S1ng7dDRSV25iFbk)
    
    Solution:
    
    We are given a image file and we did a exiftool to check the metadata for the flag
    
    flag{EEe_x_I_FFf}
    
- **Binwalk (Easy)**
    
    Here is a file with another file hidden inside it. Can you extract it? [https://mega.nz/#!qbpUTYiK!-deNdQJxsQS8bTSMxeUOtpEclCI-zpK7tbJiKV0tXYY](https://mega.nz/#!qbpUTYiK!-deNdQJxsQS8bTSMxeUOtpEclCI-zpK7tbJiKV0tXYY)
    
    Solution:
    
    To solve this, we needed to first extract the hidden file using binwalk -e “file”. After that we are given a zlib file. Using Cyberchef we can extract any hidden files within it. It gave us a image file that contained the flag.
    
    ABCTF{b1nw4lk_is_us3ful}
    
- **Exif (Easy)**
    
    If only the password were in the image?
    
    [https://mega.nz/#!SDpF0aYC!fkkhBJuBBtBKGsLTDiF2NuLihP2WRd97Iynd3PhWqRw](https://mega.nz/#!SDpF0aYC!fkkhBJuBBtBKGsLTDiF2NuLihP2WRd97Iynd3PhWqRw) You could really ‘own’ it with exif.
    
    Solution:
    
    Use the exiftool on the image and the flag can be seen
    
    flag{3l1t3_3x1f_4uth0r1ty_dud3br0}
    
- **Rubber Duck (Easy)**
    
    Find the flag! Simple forensics challenge to get started with.
    
    https://ctflearn.com/challenge/download/933
    
    Solution:
    
    Use exiftool to scan the metadata to find the flag
    
    CTFlearn{ILoveJakarta}
    
- **07601 (Medium)**
    
    [https://mega.nz/#!CXYXBQAK!6eLJSXvAfGnemqWpNbLQtOHBvtkCzA7-zycVjhHPYQQ](https://mega.nz/#!CXYXBQAK!6eLJSXvAfGnemqWpNbLQtOHBvtkCzA7-zycVjhHPYQQ) I think I lost my flag in there. Hopefully, it won't get attacked...
    
    Solution:
    
    To solve we needed to extract the hidden files using binwalk, after that we did a strings and grep command on the image file. and we saw the flag 
    
    strings 'I Warned You.jpeg' |grep "CTF"
    
    ABCTF{Du$t1nS_D0jo}
    
- **Git Is Good (Easy)**
    
    The flag used to be there. But then I redacted it. Good Luck. [https://mega.nz/#!3CwDFZpJ!Jjr55hfJQJ5-jspnyrnVtqBkMHGJrd6Nn_QqM7iXEuc](https://mega.nz/#!3CwDFZpJ!Jjr55hfJQJ5-jspnyrnVtqBkMHGJrd6Nn_QqM7iXEuc)
    
    Solution:
    
    To solve this, we needed to view the git changes of the file using git commands
    
    we did the git command of (git log —stat “file”) to see a summary of the changes
    
    └─$ git log --stat flag.txt
    after we saw the changes, we are given multiple commit hashes to check
    
    then with the commit hash that we want to check specifically
    
    └─$ git show d10f77c4e766705ab36c7f31dc47b0c5056666bb -- flag.txt
    in this specific commit we can see the flag before they changed it.
    
    flag{protect_your_git}
    
- **I'm a dump  (Easy)**
    
    The keyword is hexadecimal, and removing an useless H.E.H.U.H.E. from the flag. The flag is in the format CTFlearn{*}
    
    [https://ctflearn.com/challenge/download/883](https://ctflearn.com/challenge/download/883)
    
    Solution:
    
    To solve this, we needed to use the hexeditor tool to view the files hexes. Using this we are able to see the flag. We just removed any unnecessary letters to submit it
    
    CTFlearn{fl4ggyfl4g}
    
- **Snowboard (Easy)**
    
    Find the flag in the jpeg file. Good Luck!
    
    [https://ctflearn.com/challenge/download/934](https://ctflearn.com/challenge/download/934)
    
    Solution:
    
    We used the file command (file ‘file) to check what the file type is. We can see that it has a comment that contains base64 string. Decoding this string we get the flag
    
    CTFlearn{SkiBanff}
    
- **PikesPeak (Easy)**
    
    Pay attention to those strings!
    
    [https://ctflearn.com/challenge/download/935](https://ctflearn.com/challenge/download/935)
    
    Solution:
    
    used the strings + grep command, the correct flag is using the format of the website being 
    
    CTFlearn{} - other flags have some misspelling on their part
    
    CTFlearn{Gandalf}
    
- **Milk's Best Friend (Medium)**
    
    There's nothing I love more than oreos, lions, and winning. [https://mega.nz/#!DC5F2KgR!P8UotyST_6n2iW5BS1yYnum8KnU0-2Amw2nq3UoMq0Y](https://mega.nz/#!DC5F2KgR!P8UotyST_6n2iW5BS1yYnum8KnU0-2Amw2nq3UoMq0Y) Have Fun :)
    
    Solution:
    
    Used binwalk to extract the rar file inside, then used the strings + grep on the image file to see the flag.
    
    flag{eat_more_oreos}
    
- **Chalkboard (Easy)**
    
    Solve the equations embedded in the jpeg to find the flag. Solve this problem before solving my Scope challenge which is worth 100 points.
    
    [https://ctflearn.com/challenge/download/972](https://ctflearn.com/challenge/download/972)
    
    Solution:
    
    Used exiftool to find the flag, but we needed to solve a simple math equation (solve x and y to find the flag)
    
    CTFlearn{I_Like_Math_x_y}
    where x and y are the solution to these equations:..
    3x + 5y = 31
    7x + 9y = 59
    
    We just multiplied the first problem by 7 and the second problem with 3
    
    doing this we can subtract each to get the y
    
    (21x+35y)−(21x+27y)=217−177
    
    (35y−27y)=40(35y - 27y) = 40
    
    (35y−27y)=40
    
    8y = 40
    
    y = 5
    
    since we have y, we can just substitute it and solve the x easily
    
    CTFlearn{I_Like_Math_2_5}
    
- **A CAPture of a Flag (Medium)**
    
    This isn't what I had in mind, when I asked someone to capture a flag... can you help? You should check out WireShark. [https://mega.nz/#!3WhAWKwR!1T9cw2srN2CeOQWeuCm0ZVXgwk-E2v-TrPsZ4HUQ_f4](https://mega.nz/#!3WhAWKwR!1T9cw2srN2CeOQWeuCm0ZVXgwk-E2v-TrPsZ4HUQ_f4)
    
    Solution:
    
    Rename the file into a .pcap file. After that we check wireshark to see any suspicious connections. we filter it using a http using the protocol hierarchy, and select the http only. We can see a message that is encrypted in base64, we can decode it and this gives us the flag. 
    
    flag{AFlagInPCAP}
    
- **Tux! (Easy)**
    
    The flag is hidden inside the Penguin! Solve this challenge before solving my 100 point Scope challenge which uses similar techniques as this one.
    
    [https://ctflearn.com/challenge/download/973](https://ctflearn.com/challenge/download/973)
    
    Solution:
    
    We used binwalk to extract the hidden files, we have a locked zip file. To find the password we did a file command to see the file type and see a base64 encoded string of text. After we decode it we can see that it is the password. Using this we get the flag
    
    CTFlearn{Linux_Is_Awesome}
    
- **Up For A Little Challenge? (Medium)**
    
    [https://mega.nz/#!LoABFK5K!0sEKbsU3sBUG8zWxpBfD1bQx_JY_MuYEWQvLrFIqWZ0](https://mega.nz/#!LoABFK5K!0sEKbsU3sBUG8zWxpBfD1bQx_JY_MuYEWQvLrFIqWZ0)
    
    You Know What To Do ...
    
    Solution:
    
    To solve this, we first did a strings command on the image file. It then gave us the following info:
    
    link ([https://mega.nz/#!z8hACJbb!vQB569ptyQjNEoxIwHrUhwWu5WCj1JWmU-OFjf90Prg](https://mega.nz/#!z8hACJbb!vQB569ptyQjNEoxIwHrUhwWu5WCj1JWmU-OFjf90Prg))
    
    password (Nothing Is As It Seems)
    
    downloading the zip file inside the link gives us a locked zip file. Now if we used the password we can see that it gives us a image file. On the far left corner of the screen we can see a very small flag. using a magnifying glass tool we can see that the flag is 
    
    flag{hack_complete}
    

### Web Exploitation

### Pico

- **n0s4n1ty 1 (EAsy)**
    
    Author: Prince Niyonshuti N.
    
    ### Description
    
    A developer has added profile picture upload functionality to a website.
    However, the implementation is flawed, and it presents an opportunity for you.
    Your mission, should you choose to accept it, is to navigate to the provided
    web page and locate the file upload area. Your ultimate goal is to find the
    hidden flag located in the `/root` directory.
    
    Additional details will be available after launching your challenge instance.
    
    Solution:
    

### Reverse Engineering

### Solved

### OSINT

### Solved

### Binary Exploitation

### Solved

### General/Miscellaneous

### WMSU

- **The Obscured Trail**
    
    **Category** : Miscellaneous
    **Points** : 50
    
    The answer is right in front of you, but it refuses to speak clearly. Listen carefully.
    
    ## Files :
    
    - [random.txt](https://www.notion.so/random.txt)
    
    Solution:
    
    For this challenge, I was given a long string of hex values. From experience, the first thing I do with raw hex is throw it into CyberChef and try a basic “From Hex” operation. That revealed some readable—but scrambled—text.
    
    After inspecting it, I realized the string was reversed. So I added a **"Reverse"** step in CyberChef, and that output looked like Base64. Sure enough, decoding it gave me another payload, but it didn’t look like normal text.
    
    Turns out, it was **Brainfuck**—a minimalist programming language often used in CTFs to obfuscate short messages. I ran it through a Brainfuck interpreter, and it finally spit out the flag.
    
    > Flag: CCS{W4tdad4mz_Luhkas!}
    > 
- **PICOCTF**
    - **mus1c (Medium)**
        
        Author: Danny
        
        ### Description
        
        I wrote you a [song](https://jupiter.challenges.picoctf.org/static/c594d8d915de0129d92b4c41e25a2313/lyrics.txt). Put it in the picoCTF{} flag format.
        
        Solution:
        
        To solve this we are using the **Rockstar programming language** 
        
        https://codewithrockstar.com/online
        
        using this we pasted the lyrics into it and after it played we got a string of decimals.
        
        Now using cyberchef we are able to decode the string of decimals into readable text.
        
        rrrocknrn0113r
        
        Now to wrap it with the flag format we get
        
        picoCTF{rrrocknrn0113r}
        
    - **Based (Medium)**
        
        Author: Alex Fulton/Daniel Tunitis
        
        ### Description
        
        To
         get truly 1337, you must understand different data encodings, such as 
        hexadecimal or binary. Can you get the flag from this program to prove 
        you are on the way to becoming 1337? Connect with `nc jupiter.challenges.picoctf.org 15130`.
        
        Solution:
        
        To solve the challenge we just needed to decode the string of text that we are given, with the order being 
        
        Binary - 01110000 01101001 01100101 - pie
        
        Octal - 143 157 155 160 165 164 145 162 - computer
        
        Hex - 636f6e7461696e6572 - container
        
        and we get the flag
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2028.png)
        
        picoCTF{learning_about_converting_values_02167de8}
        
    - **plumbing (Medium)**
        
        Author: Alex Fulton/Danny Tunitis
        
        ### Description
        
        Sometimes
         you need to handle process data outside of a file. Can you find a way 
        to keep the output from this program and search for the flag? Connect to
         `jupiter.challenges.picoctf.org 4427`.
        
        Solution:
        
        We just did a find command with the flag format
        
        picoCTF{digital_plumb3r_5ea1fbd7}
        
    - **flag_shop (Medium)**
        
        Author: Danny
        
        ### Description
        
        There's a flag shop selling stuff, can you buy a flag? [Source](https://jupiter.challenges.picoctf.org/static/dd28f0987f28c894f35d5d48564c3402/store.c). Connect with `nc jupiter.challenges.picoctf.org 44566`.
        
        Solution:
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*4qDDF_Psn84MbGId45KSdw.png)
        
        Throughout
         this process, I started looking for possible ways to exploit the c 
        program to somehow manipulate the multiplication command to make it 
        minus or a decimal to increase my balance. My first thought was to put 
        in a decimal number for my requested amount to make it an extremely 
        small amount but there was a pesky if statement forcing the input to be 
        > 1. Following from there came my Eureka moment. I noticed that the 
        int variable used to calculate the total cost was signed, meaning I 
        could use an integer overflow to flip the sign and make the cost 
        extremely negative. The largest number an int can hold is **2147483647,** divided by 900 the cost of the flag and we get **2386092** which is the theoretical maximum I could input. From there I simply inputted **2400000** and alas… “I’m in”.
        
        ```
        if(number_flags > 0){
                            int total_cost = 0;
                            total_cost = 900*number_flags;
                            printf("\nThe final cost is: %d\n", total_cost);
                            if(total_cost <= account_balance){
                                account_balance = account_balance - total_cost;
                                printf("\nYour current balance after transaction: %d\n\n", account_balance);
                            }
        ```
        
        Zoom image will be displayed
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*cVoa73hrHfnGxf7sF1DFEg.png)
        
        then we just need to buy it
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2029.png)
        
        picoCTF{m0n3y_bag5_68d16363}
        
    - **1_wanna_b3_a_r0ck5tar (Medium)**
        
        ### Description
        
        I wrote you another [song](https://jupiter.challenges.picoctf.org/static/96904d361d61fada5bd2d13536706f9a/lyrics.txt). Put the flag in the picoCTF{} flag format
        
        Solution:
        
        `picoCTF{BONJOVI}`
        
    - **Lets Warm Up (Easy)**
        
        Author: Sanjay C/Danny Tunitis
        
        ### Description
        
        If I told you a word started with 0x70 in hexadecimal, what would it start with in ASCII?
        
        Solution:
        
        convert the hex 0x70 to ASCII is p. so the flag is p and just wrap it in the flag format
        
        picoCTF{p}
        
    - **what's a net cat? (Easy)**
        
        Author: Sanjay C/Danny Tunitis
        
        ### Description
        
        Using netcat (nc) is going to be pretty important. Can you connect to `jupiter.challenges.picoctf.org` at port `25103` to get the flag?
        
        Solution:
        
        just do the netcat command to connect so 
        
        nc `jupiter.challenges.picoctf.org` `25103`
        
        we get the flag
        
        picoCTF{nEtCat_Mast3ry_d0c64587}
        
    - **strings it (Easy)**
        
        Author: Sanjay C/Danny Tunitis
        
        ### Description
        
        Can you find the flag in [file](https://jupiter.challenges.picoctf.org/static/5bd86036f013ac3b9c958499adf3e2e2/strings) without running it?
        
        Solution:
        
        Just use the strings and grep command
        
        strings strings | grep "pico"
        
        we get the flag
        
        picoCTF{5tRIng5_1T_827aee91}
        
    - **Warmed Up (Easy)**
        
        Author: Sanjay C/Danny Tunitis
        
        ### Description
        
        What is 0x3D (base 16) in decimal (base 10)?
        
        Solution:
        
        Use Cyberchef to decode the 0x3D from Base 16 and it gives the decimal value of
        
        61
        
        61 is the flag so we just wrap it using
        
        picoCTF{61}
        
    - **Bases (Easy)**
        
        Author: Sanjay C/Danny T
        
        ### Description
        
        What does this `bDNhcm5fdGgzX3IwcDM1` mean? I think it has something to do with bases.
        
        Solution:
        
        Use Cyberchef to decode the base64 to a flagi
        
        l3arn_th3_r0p35
        
        then we wrap it with the flag format
        
        picoCTF{l3arn_th3_r0p35}
        
    - **First Grep (Easy)**
        
        Author: Alex Fulton/Danny Tunitis
        
        ### Description
        
        Can you find the flag in [file](https://jupiter.challenges.picoctf.org/static/315d3325dc668ab7f1af9194f2de7e7a/file)? This would be really tedious to look through manually, something tells me there is a better way.
        
        Solution:
        
        Use grep command
        
        grep 'pico' file
        
        picoCTF{grep_is_good_to_find_things_f77e0797}
        
    - **2Warm (Easy)**
        
        Author: Sanjay C/Danny Tunitis
        
        ### Description
        
        Can you convert the number 42 (base 10) to binary (base 2)?
        
        Solution:
        
        Use the bash command
        
        echo "obase=2; 42" | bc
        
        This command sets the output base (obase) to 2 (binary) and then calculates the binary representation of the decimal number 42.
        
        picoCTF{101010}
        
    - **PW Crack 3 (Medium)**
        
        Author: LT 'syreal' Jones
        
        ### Description
        
        Can you crack the password to get the flag?
        Download the password checker [here](https://artifacts.picoctf.net/c/18/level3.py) and you'll
        need the encrypted [flag](https://artifacts.picoctf.net/c/18/level3.flag.txt.enc) and the
        [hash](https://artifacts.picoctf.net/c/18/level3.hash.bin) in the same directory too.
        There are 7 potential passwords with 1 being correct. You can find these by
        examining the password checker script.
        
        Solution:
        
        We can modify ***level_3_pw_check()*** function to include the list of passwords at the beginning of the function and iterate through them until the correct password that matches with the stored password is found.
        
        So from
        
        ```
        def level_3_pw_check():
            user_pw = input("Please enter correct password for flag: ")
            user_pw_hash = hash_pw(user_pw)
        
            if( user_pw_hash == correct_pw_hash ):
                print("Welcome back... your flag, user:")
                decryption = str_xor(flag_enc.decode(), user_pw)
                print(decryption)
                return
            print("That password is incorrect")
        
        level_3_pw_check()
        
        # The strings below are 7 possibilities for the correct password.
        #   (Only 1 is correct)
        pos_pw_list = ["f09e", "4dcf", "87ab", "dba8", "752e", "3961", "f159"]
        ```
        
        To
        
        ```
        def level_3_pw_check():
        
            # The strings below are 7 possibilities for the correct password.
            #   (Only 1 is correct)
            pos_pw_list = ["f09e", "4dcf", "87ab", "dba8", "752e", "3961", "f159"]
        
            #user_pw = input("Please enter correct password for flag: ")
        
            for i in range(0, len(pos_pw_list)):
        
                user_pw = pos_pw_list[i]
                user_pw_hash = hash_pw(user_pw)
        
        		    if( user_pw_hash == correct_pw_hash ):
        		        print("Welcome back... your flag, user:")
        		        decryption = str_xor(flag_enc.decode(), user_pw)
        		        print(decryption)
        		        return
        
            print("That password is incorrect")
        
        level_3_pw_check()
        ```
        
        so it would give us the flag
        
        picoCTF{m45h_fl1ng1ng_6f98a49f}
        
    - **PW Crack 4 (Medium)**
        
        Author: LT 'syreal' Jones
        
        ### Description
        
        Can you crack the password to get the flag?
        Download the password checker [here](https://artifacts.picoctf.net/c/19/level4.py) and you'll
        need the encrypted [flag](https://artifacts.picoctf.net/c/19/level4.flag.txt.enc) and the
        [hash](https://artifacts.picoctf.net/c/19/level4.hash.bin) in the same directory too.
        There are 100 potential passwords with only 1 being correct. You can find these
        by examining the password checker script.
        
        Solution:
        
        We used the same concept as PW Crack 3, being to put the pw_list in the pw_checker so that it will automatically scan throught each one.
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2030.png)
        
        picoCTF{fl45h_5pr1ng1ng_ae0fb77c}
        
    - **PW Crack 5 (Medium)**
        
        Author: LT 'syreal' Jones
        
        ### Description
        
        Can you crack the password to get the flag?
        Download the password checker [here](https://artifacts.picoctf.net/c/33/level5.py) and you'll
        need the encrypted [flag](https://artifacts.picoctf.net/c/33/level5.flag.txt.enc) and the
        [hash](https://artifacts.picoctf.net/c/33/level5.hash.bin) in the same directory too. Here's a
        [dictionary](https://artifacts.picoctf.net/c/33/dictionary.txt) with all possible passwords based
        on the password conventions we've seen so far.
        
        Solution:
        
        This challenge uses the same principle and ideo from the previous PW Crack. So we just want to automate it to check each line of code and since we are given a .txt file that contains a thousand of possible passwords. We can simple do the following inside the pw_check program:
        
        def level_5_pw_check():
        with open("dictionary.txt", 'r') as flag:
        for line in flag:
        user_pw = line.strip()
        user_pw_hash = hash_pw(user_pw)
        
        if( user_pw_hash == correct_pw_hash ):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), user_pw)
        print(decryption)
        return
        
        print("That password is incorrect")
        
        As we can see instead of the usual for loop that we include the array, we can just open the file immidietly so that it will scan each one.
        
        From
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2031.png)
        
        To
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2032.png)
        
        Running this will reveal us the flag
        
        picoCTF{h45h_sl1ng1ng_fffcda23}
        
    - **Serpentine (Medium)**
        
        Author: LT 'syreal' Jones
        
        ### Description
        
        Find the flag in the Python script!
        [Download Python script](https://artifacts.picoctf.net/c/37/serpentine.py)
        
        Solution:
        
        So for this challenge, we modified the python program file to print us the flag. since the print flag function was not part in the given choice. I just simply added the function itself.
        
        We can that there are functions of flag_enc and print_flag but the print_flag function is not present in the main. So we just simply added the function into the choices
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/c1fcc86c-ca68-4056-b54a-bbf2a16c6abf.png)
        
        so from the given choice we simply modified it.f
        
        From
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2033.png)
        
        To
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2034.png)
        
        now with this we are able to select choice b to give us the flag
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2035.png)
        
        picoCTF{7h3_r04d_l355_7r4v3l3d_8e47d128}
        
    - **chrono (Medium)**
        
        Author: Mubarak Mikail
        
        ### Description
        
        How to automate tasks to run at intervals on linux servers?
        Use ssh to connect to this server:
        `Server: saturn.picoctf.net
        Port: 64705
        Username: picoplayer 
        Password: bLgSMmbY6X`
        
        Solution:
        
        First we needed to log in the server using ssh
        
        ssh -p `64705` `picoplayer`@`saturn.picoctf.net`
        
        entering this will ask us to input the password, so we just gave it `bLgSMmbY6X`
        
        after that we are inside the account. Now we just need to find the file which keeps track of tasks that are run periodically on a linux server. that being the “crontab” file
        
        so doing:
        
        `cat /etc/crontab`
        
        will give us the contents of which files are being automated, but instead of that we get the flag
        
        picoCTF{Sch3DUL7NG_T45K3_L1NUX_1b4d8744}
        
    - **Big Zip (Easy)**
        
        Author: LT 'syreal' Jones
        
        ### Description
        
        Unzip this archive and find the flag.
        
        - [Download zip file](https://artifacts.picoctf.net/c/504/big-zip-files.zip)
        
        Solution:
        
        To find a specific string in multiple subfolders we can do 
        
        grep -r "pico" big-zip-files
        
        with this command we are able to location the specific subfolder and its textfile to find the text file that has the flag.
        
        picoCTF{gr3p_15_m4g1c_ef8790dc}
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2036.png)
        
    - **repetitions (Easy)**
        
        Author: Theoneste Byagutangaza
        
        ### Description
        
        Can you make sense of this file?
        Download the file [here](https://artifacts.picoctf.net/c/476/enc_flag).
        
        Solution:
        
        it was a string of base64 that we needed to repeat to decode the flag. so we needed eitehr a loop or manually decode each message from base64
        
        picoCTF{base64_n3st3d_dic0d!n8_d0wnl04d3d_4557ec3e}
        
    - **First Find (Easy)**
        
        Author: LT 'syreal' Jones
        
        ### Description
        
        Unzip this archive and find the file named 'uber-secret.txt'
        
        - [Download zip file](https://artifacts.picoctf.net/c/500/files.zip)
        
        Solution:
        
        To find a specific string in multiple subfolders we can do 
        
        grep -r "pico" files
        
        with this command we are able to location the specific subfolder and its textfile to find the text file that has the flag.
        
        picoCTF{f1nd_15_f457_ab443fd1}
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2037.png)
        
    - [**runme.py](http://runme.py) (Easy)**
        
        Author: Sujeet Kumar
        
        ### Description
        
        Run the `runme.py` script to get the flag. Download the script with your
        browser or with `wget` in the webshell.
        [Download runme.py Python script](https://artifacts.picoctf.net/c/34/runme.py)
        
        Solution:
        
        just opened the python file and the flag is easily found
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2038.png)
        
        picoCTF{run_s4n1ty_run}
        
    - **PW Crack 2 (Easy)**
        
        Author: LT 'syreal' Jones
        
        ### Description
        
        Can you crack the password to get the flag?
        Download the password checker [here](https://artifacts.picoctf.net/c/14/level2.py) and you'll
        need the encrypted [flag](https://artifacts.picoctf.net/c/14/level2.flag.txt.enc) in the same directory
        too.
        
        Solution:
        
        To solve this we are given a python file that contains the decryption and the encrypted flag file. Viewing the python file, we can see that it has a algorithm that checks for a specific password. We can see that the password it is looking for is hard coded but encrypted into hexidecimals. 
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2039.png)
        
        So after we decode this into ASCII we get the password
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2040.png)
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2041.png)
        
        then we just enter the password and we get the flag
        
        picoCTF{tr45h_51ng1ng_9701e681}
        
    - **PW Crack 1 (Easy)**
        
        Author: LT 'syreal' Jones
        
        ### Description
        
        Can you crack the password to get the flag?
        Download the password checker [here](https://artifacts.picoctf.net/c/11/level1.py) and you'll
        need the encrypted [flag](https://artifacts.picoctf.net/c/11/level1.flag.txt.enc) in the same
        directory too.
        
        Solution:
        
        We are given a python file and encrypted flag file. Inside the python file contains the decoding algorithm to get the flag. We can see that the password thats set is hard coded.
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2042.png)
        
        So we just needed to type the password and we would get the flag
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2043.png)
        
        picoCTF{545h_r1ng1ng_fa343060}
        
    - **HashingJobApp (Easy)**
        
        Author: LT 'syreal' Jones
        
        ### Description
        
        If you want to hash with the best, beat this test!
        
        Additional details will be available after launching your challenge instance.
        
        Solution:
        
        We are given a server that we will need to connect to access the challenge
        
        After accessing the server, we are tasked with hashing a specific word into md5. We would need to repeat this 3 times using CyberChef.
        
        ![Screenshot From 2025-08-04 16-52-57.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/Screenshot_From_2025-08-04_16-52-57.png)
        
        picoCTF{4ppl1c4710n_r3c31v3d_3eb82b73}
        
    - **Glitch Cat (Easy)**
        
        Author: LT 'syreal' Jones
        
        ### Description
        
        Our flag printing service has started glitching!
        `$ nc saturn.picoctf.net 50499`
        
        Solution:
        
        After we connect to the server, we are given the flag but some of the parts are encrypted into hexadecimals.
        
        picoCTF{gl17ch_m3_n07_' + chr(0x62) + chr(0x64) + chr(0x61) + chr(0x36) + chr(0x38) + chr(0x66) + chr(0x37) + chr(0x35) + '}
        
        We would just need to decode the hexadecimals using CyberChef and just add the decoded parts into the flag.
        
        bda68f75
        
        so we would get
        
        picoCTF{gl17ch_m3_n07_bda68f75}
        
    - [**fixme2.py](http://fixme2.py) (Easy)**
        
        Author: LT 'syreal' Jones
        
        ### Description
        
        Fix the syntax error in the Python script to print the flag.
        [Download Python script](https://artifacts.picoctf.net/c/4/fixme2.py)
        
        Solution:
        
        To solve this, we needed to fix the python file’s algorithm that was using the if else statement. So I just removed the statement and used the print function immediently
        
        So from this 
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2044.png)
        
        To this
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2045.png)
        
        After doing this we can just run the program and we will get the flag.
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2046.png)
        
        picoCTF{3qu4l1ty_n0t_4551gnm3nt_e8814d03}
        
    - [**fixme1.py](http://fixme1.py) (Easy)**
        
        Author: LT 'syreal' Jones
        
        ### Description
        
        Fix the syntax error in this Python script to print the flag.
        [Download Python script](https://artifacts.picoctf.net/c/26/fixme1.py)
        
        Solution:
        
        We are given a python file that contains a function that encrypts and decrypts the flag. So to solve this we can see that inside the python file it has a error with the indention.
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2047.png)
        
        So we just need to fix this and we should get the flag
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2048.png)
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2049.png)
        
        picoCTF{1nd3nt1ty_cr1515_09ee727a}
        
    - [**convertme.py](http://convertme.py) (Easy)**
        
        Author: LT 'syreal' Jones
        
        ### Description
        
        Run the Python script and convert the given number from decimal to binary to
        get the flag.
        [Download Python script](https://artifacts.picoctf.net/c/23/convertme.py)
        
        Solution:
        
        We are given a python program that when run, will ask the user for the binary representation of a random decimal that the program will given.
        
        **If 70 is in decimal base, what is it in binary base?**
        
        To get the binary base(binary representation) we will be using the terminal with the command of:
        
        echo "obase=2; 70" | bc
        
        This will convert the given decimal into binary, giving us 1000110
        
        ![Screenshot From 2025-08-04 17-19-39.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/Screenshot_From_2025-08-04_17-19-39.png)
        
        picoCTF{4ll_y0ur_b4535_9c3b7d4d}
        
    - **Codebook (Easy)**
        
        Author: LT 'syreal' Jones
        
        ### Description
        
        Run the Python script in the same directory as
        
        - [Download code.py](https://artifacts.picoctf.net/c/2/code.py)
        - [Download codebook.txt](https://artifacts.picoctf.net/c/2/codebook.txt)
        
        Solution:
        
        To solve this, we just needed to run the python script in the same directory as the codebook text file
        
        picoCTF{c0d3b00k_455157_7d102d7a}
        
    - **Magikarp Ground Mission (Easy)**
        
        Author: syreal
        
        ### Description
        
        Do you know how to move between directories and read files in the shell? 
        Start the container, `ssh` to it, and then `ls` once connected to begin.
         Login via `ssh` as `ctf-player` with the password, `481e7b14`
        
        Solution:
        
        This challenge was a simple one meant to test basic Unix command-line knowledge. The setup had multiple nested directories, and each one contained a file with part of the flag. The goal was to navigate through the file system using commands like `cd` and `ls`, and read file contents using `cat`.
        
        Once I found all three files and read them, I just concatenated the parts to form the full flag.
        
        picoCTF{xxsh_0ut_0f_\/\/4t3r_1118a9a4}
        
    - **Tab, Tab, Attack (Easy)**
        
        Author: syreal
        
        ### Description
        
        Using tabcomplete in the Terminal will add years to your life, esp. when 
        dealing with long rambling directory structures and filenames: [Addadshashanammu.zip](https://mercury.picoctf.net/static/72712e82413e78cc8aa8d553ffea42b0/Addadshashanammu.zip)
        
        Solution:
        
        # Step 1: Unzipping the Archive
        
        To begin our quest, we unzip the “Addadshashanammu.zip” file and examine its contents:
        
        ```
        unzip Addadshashanammu.zip
        ```
        
        # Step 2: Tab Completion to the Rescue
        
        Upon
         extracting the zip file, we discover a labyrinthine structure of 
        directories. Tab completion comes to our aid, making navigation a 
        breeze. As we traverse through the directories using tab completion, we 
        find the hidden executable file “fang-of-haynekhtnamet” buried deep 
        within the path:
        
        ```
        cd Addadshashanammu/Almurbalarammi/Ashalmimilkala/Assurnabitashpi/Maelkashishi/Onnissiralis/Ularradallaku
        ```
        
        Step 3: Unleashing the Power of the Fang
        
        We set permissions to make the “fang-of-haynekhtnamet” executable:
        
        ```
        chmod +x fang-of-haynekhtnamet
        ```
        
        Finally, we run the executable and are met with a triumphant message:
        
        ```
        ./fang-of-haynekhtnamet
        *ZAP!* picoCTF{l3v3l_up!_t4k3_4_r35t!_d32e018c}
        ```
        
    - **Wave a flag (Easy)**
        
        Author: syreal
        
        ### Description
        
        Can you invoke help flags for a tool or binary? [This program](https://mercury.picoctf.net/static/f95b1ee9f29d631d99073e34703a2826/warm) has extraordinarily helpful information...
        
        Solution:
        
        We are given a binary file, to solve this I simply did a strings + grep command
        
        strings warm | grep "pico”
        
        in which we are given the flag
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2050.png)
        
        picoCTF{b1scu1ts_4nd_gr4vy_f0668f62}
        
    - **Python Wrangling (Easy)**
        
        Author: syreal
        
        ### Description
        
        Python scripts are invoked kind of like programs in the Terminal... Can you run [this Python script](https://mercury.picoctf.net/static/5c4c0cbfbc149f3b0fc55c26f36ee707/ende.py) using [this password](https://mercury.picoctf.net/static/5c4c0cbfbc149f3b0fc55c26f36ee707/pw.txt) to get [the flag](https://mercury.picoctf.net/static/5c4c0cbfbc149f3b0fc55c26f36ee707/flag.txt.en)?
        
        Solution:
        
        **Files Provided:**
        
        - `ende.py`: A custom Python script used to encrypt and decrypt files.
        - `flag.txt.enc`: An encrypted flag file.
        - `pw.txt`: A file containing a hashed-looking password string.
        
        ---
        
        First, I checked how the custom script worked by running it with the `-h` flag:
        
        `python3 ende.py -h`
        
        This revealed usage instructions:
        
        Usage: [ende.py](http://ende.py/) (-e/-d) [file]
        Examples:
        To decrypt a file named 'pole.txt', do: '$ python [ende.py](http://ende.py/) -d pole.txt'
        
        From this, I understood that to **decrypt** the flag file, I had to use the `-d` option:
        
        `python3 ende.py -d flag.txt.enc`
        
        Upon running that, the script prompted for a password. I opened `pw.txt`, copied the string inside, and used it as input. It worked — the script decrypted the file and printed the flag:
        
        picoCTF{4p0110_1n_7h3_h0us3_192ee2db}
        
    - **Static ain't always noise (Easy)**
        
        Author: syreal
        
        ### Description
        
        Can you look at the data in this binary: [static](https://mercury.picoctf.net/static/66932732825076cad4ba43e463dae82f/static)? This [BASH script](https://mercury.picoctf.net/static/66932732825076cad4ba43e463dae82f/ltdis.sh) might help!
        
        Solution:
        
        To solve this we did a strings command on the “static” file
        
        strings static 
        
        ![image.png](Challenges%20&%20Flags%2022e3dc4f1a94808ab30de5040590ee5a/image%2051.png)
        
        picoCTF{d15a5m_t34s3r_f5aeda17}
        
    - **Nice netcat... (Easy)**
        
        Author: syreal
        
        ### Description
        
        There is a nice program that you can talk to by using this command in a shell: `$ nc mercury.picoctf.net 22902`, but it doesn't speak English...
        
        Solution:
        
        Opening the server we are given a string of decimals, now we just needed to decode this using CyberChef and we get the flag.
        
        picoCTF{g00d_k1tty!_n1c3_k1tty!_d3dfd6df}
        
    - **Obedient Cat (Easy)**
        
        Author: syreal
        
        ### Description
        
        This file has a flag in plain sight (aka "in-the-clear"). [Download flag](https://mercury.picoctf.net/static/fb851c1858cc762bd4eed569013d7f00/flag).
        
        Solution:
        
        Just use the cat command on the filefi
        
        picoCTF{s4n1ty_v3r1f13d_28e8376d}
        
    - **Permissions (Medium)**
        
        Author: Geoffrey Njogu
        
        ### Description
        
        Can you read files in the root file?
        The system admin has provisioned an account for you on the main server:
        `ssh -p 52964 picoplayer@saturn.picoctf.net`Password: `e3pn6lmvHt`Can you login and read the root file?
        
        Solution:
        
        Zoom image will be displayed
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*hzPbSYijp_y-pjVtnkZOYQ.png)
        
        Check the sudo permissions the user has available to them. (Hint: What permissions do you have?)
        
        ```
        sudo -l
        ```
        
        As we can see below we have sudo access to the vi text editor. This means that we can run vi as root on any file
        
        Zoom image will be displayed
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*J6GX56BgtECpeFlru48_0w.png)
        
        In this case we created our own file (test) in the current directory with vi
        
        Zoom image will be displayed
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*4i2eevDMDuOCgWU2BNlQig.png)
        
        Run the below script in command mode — vi. (To get to command mode in the vi text editor, hit the **esc** key). You can get some of these hints for scripts from [GTFO bins](https://gtfobins.github.io/)
        
        ```
        :!/bin/bash
        ```
        
        Zoom image will be displayed
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*ryU7ojl2ycumLlDsqgQjxw.png)
        
        We get root!
        
        Zoom image will be displayed
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*PoubZ59B7NkixpeBiyo36A.png)
        
        Now
         head over to the /root directory to get our flag. From the challenge 
        description we’ve been asked if we can read the root file.
        
        At first we ran **ls** but it did not display any files for us. With the assumption that there could be hidden files in this directory, we ran **ls -la** and we see some hidden files. Seen something that you’ve been looking for? Lets find out
        
        Zoom image will be displayed
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*fa49rBqgTULaFIi0RDCudA.png)
        
        Go ahead and read the file. There you go, Congratulations
        
        Zoom image will be displayed
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*rTi3N_TSjeL3Jk9SQlDpbQ.png)
        
        picoCTF{uS1ng_v1m_3dit0r_f6ad392b}
        
    - **dont-you-love-banners (Medium)**
        
        Author: Loic Shema / syreal
        
        ### Description
        
        Can you abuse the banner?
        
        Additional details will be available after launching your challenge instance.
        
        Solution:
        
        After we hit Launch Instance, we’ll be given 2 ports to connect to. I first 
        visited the first one that says to have some leak of important 
        information.
        
        ![](https://miro.medium.com/v2/resize:fit:794/1*oeNfO_qInxlye60tjMJfdg.png)
        
        The server just simply gives us a free password, so let’s go to the real 
        challenge. We need to answer a few questions before we can enter. The 
        first question is the password which we just recently got from 
        connecting to the previous port. For the other two we can simply search 
        and, like hint 2 mentioned, we can keep guessing until we get them 
        correctly.
        
        what is the password?
        
        - My_Passw@rd_@1234
        
        What is the top cyber security conference in the world?
        
        - DEF CON
        
        the first hacker ever was known for phreaking(making free phone calls), who was it?
        
        - ’JOHN DRAPER’/ ‘JOHN THOMAS DRAPER’/ ‘JOHN’/ ‘DRAPER’
        
        (answers are not case sensitive)
        
        Zoom image will be displayed
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*wbxUdowc_HOTlANM6SFEWQ.png)
        
        Now that we’re in, why don’t we look around what we got here?
        
        ![](https://miro.medium.com/v2/resize:fit:1196/1*Obs30O1ke6MUVWtzVQUMZg.png)
        
        ![](https://miro.medium.com/v2/resize:fit:780/1*aJxwAG2BI1I7XD1hzriUEg.png)
        
        We
         got 2 ASCII text files. One seems familiar since it’s the banner 
        printed to welcome when we connect to the system using Netcat. Another 
        file just tells us to keep digging. So, I searched deeper.
        
        ![](https://miro.medium.com/v2/resize:fit:1056/1*uqGZcvhX_LtucoH8NeUi3w.png)
        
        I found files in **/root** directory, but we don’t have permission to read the flag file.
        
        ```
        player@challenge:~$ cat /root/script.py
        cat /root/script.py
        
        import os
        import pty
        
        incorrect_ans_reply = "Lol, good try, try again and good luck\n"
        
        if __name__ == "__main__":
            try:
              with open("/home/player/banner", "r") as f:
                print(f.read())
            except:
              print("*********************************************")
              print("***************DEFAULT BANNER****************")
              print("*Please supply banner in /home/player/banner*")
              print("*********************************************")
        
        try:
            request = input("what is the password? \n").upper()
            while request:
                if request == 'MY_PASSW@RD_@1234':
                    text = input("What is the top cyber security conference in the world?\n").upper()
                    if text == 'DEFCON' or text == 'DEF CON':
                        output = input(
                            "the first hacker ever was known for phreaking(making free phone calls), who was it?\n").upper()
                        if output == 'JOHN DRAPER' or output == 'JOHN THOMAS DRAPER' or output == 'JOHN' or output== 'DRAPER':
                            scmd = 'su - player'
                            pty.spawn(scmd.split(' '))
        
                        else:
                            print(incorrect_ans_reply)
                    else:
                        print(incorrect_ans_reply)
                else:
                    print(incorrect_ans_reply)
                    break
        
        except:
            KeyboardInterrupt
        ```
        
        Luckily, we can read **script.py**
         which seems to be the one we talked with at the beginning. We can see 
        all the answers to those questions clearly from this file. However, the 
        crucial part is this part:
        
        ```
        with open("/home/player/banner", "r") as f:
                print(f.read())
        ```
        
        I tried altering the banner content with **echo “test text” > banner**
         and the welcome banner changes accordingly. The question is “How can we
         use this to read the flag?”, and that’s how the first hint “**Do you know about symlinks?**”
         comes in handy. I searched about it and found that Symlinks act as 
        reference pointers to files or directories. We can think of the symlinks
         as a shortcut to the file like if we link **link1 -> /root/flag.txt**, **calling** **link1** means to **call /root/flag.txt**.
        
        We can create symlinks with this command:
        
        - **ln -s <part to target> <linkname>**
        
        ![](https://miro.medium.com/v2/resize:fit:1008/1*N6FgL-1PbiUz1WglcnYYBQ.png)
        
        Replace the banner with a symlink so that the system reads /root/flag.txt when trying to display the banner.
        
        picoCTF{b4nn3r_gr4bb1n9_su((3sfu11y_f7608541}
        
    - **SansAlpha (Medium)**
        
        Author: syreal
        
        ### Description
        
        The Multiverse is within your grasp! Unfortunately, the server that contains
        the secrets of the multiverse is in a universe where keyboards only have
        numbers and (most) symbols.
        
        Additional details will be available after launching your challenge instance.
        
        Solution:
        
        Launch the instance and then connect using the given password. We’ll be at bash shell. Sadly, as I tried, **we can’t use any alphabets and backslash(‘ \ ’).**
        
        Zoom image will be displayed
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*261up61PiJRJD7PAGvUBoQ.png)
        
        As I tried to find commands without letters and \ to use in this 
        challenge, I found wildcards which are special symbols to match one or 
        more characters in file names, file paths, or command-line operations.
        
        - [Wildcards (tldp.org)](https://tldp.org/LDP/GNU-Linux-Tools-Summary/html/x11655.htm)
        - [Globbing (tldp.org)](https://tldp.org/LDP/abs/html/globbingref.html)
        
        Here are some Wildcard characters I will use later on:
        
        - **?** : match 1 character, ex. /**???** -> /**bin** /**dev** /**etc** /**lib**
        - : match 0 or more characters, ex. /lib* -> /lib /lib**32** /lib**64**
        - [ ]  **[ ]** : matches any single character within the specified range or set, ex. file**[345]**.txt or file**[3–5]**.txt -> file**3**.txt, file**4**.txt, file**5**.txt, file**6**.txt
        - **[!]** : matches any character that is not in the specified range or set, ex. file**[!12]**.txt -> any files from file**0**.txt-file**9**.txt, except file**1**.txt and file**2**.txt
        
        I started by searching the current directory using **./*** to see all the files and noticed that, unlike our Kali terminal, this bash only returns 1 result at a time. I continued to use ***** and found a **flag file**, but don’t have permission to read it. Therefore, I switched to using ‘**?**’ to search more and found a couple of files in the current directory which also returned permission denied.
        
        Zoom image will be displayed
        
        ![](https://miro.medium.com/v2/resize:fit:662/1*lbrsQdICJiDGZv1Ie36jiA.png)
        
        ![](https://miro.medium.com/v2/resize:fit:914/1*7RuLT-p9JNPvDMYrSvzTxg.png)
        
        Having no usable commands, I had no other choice but to start searching from the root directory(‘ **/** ’ ). My strategy was to keep adding ‘**?**’ one by one to make sure I found as many as possible files or paths.
        
        ![](https://miro.medium.com/v2/resize:fit:894/1*xTlWY0nzcDFRkedfpGxADA.png)
        
        Thanks to this method, I found that the full path to the flag file which is **/home/ctf-player/blargh/flag.txt**, meaning that we’re currently on **/home/ctf-player**. Nevertheless, as we expected, calling the full path doesn’t help us with the permission denied issue. I paid extra attention to**/bin/** as it contains essential command binaries, such as ls, cat, and chmod. 
        Most of the commands found seem not to help with the challenge except **/bin/base64** which somehow also matches with the hint given for this challenge. I tried to call “**/bin/base64 /home/ctf-player/blargh/flag.txt**” hoping it would return the base64 encrypted version of the flag.
        
        ![](https://miro.medium.com/v2/resize:fit:1218/1*mrSXfxti4N0Jh01Y-hGXGA.png)
        
        The problem is that the system seems to be confused with the command. From 
        my point of view, I think the server, in fact, matches all the commands just like our Kali terminal but returns to us only the first command it 
        found. In this case, It could look like this on the server side:
        
        ![](https://miro.medium.com/v2/resize:fit:994/1*FFkqBI417fJGxr2albk38A.png)
        
        That’s why it tried to base32 the file after **/bin/base32**, then there’s also **/bin/base64**
         which exceeds the expected operand. For this reason, I guess we have to
         be more specific about the command we glob. I tried use **/???/????64** to find only the file that’s in **/???** path, the name has any **4 characters followed by ‘64’.**
        
        ![](https://miro.medium.com/v2/resize:fit:1146/1*LYVPqFcepgeK8-8xwcT6_g.png)
        
        But then **/bin/x86_64** also matches the pattern, so I added **[!_] at the 4th character** to exclude any file that has ‘**_**’
         at the 4th character. After all this mess, we finally got base64 of the
         flag which we can easily decode with any method of our choice.
        
        Zoom image will be displayed
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*Cj0pYLZgYE2eNJryL7btbA.png)
        
        Zoom image will be displayed
        `picoCTF{7h15_mu171v3r53_15_m4dn355_4945630a}`
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*RTZ_mFEPIlQ68SxfS72KbA.png)
        
    - **Rust fixme 1 (Easy)**
        
        Author: Taylor McCampbell
        
        ### Description
        
        Have you heard of Rust? Fix the syntax errors in this Rust file to print the flag!
        Download the Rust code [here](https://challenge-files.picoctf.net/c_verbal_sleep/3f0e13f541928f420d9c8c96b06d4dbf7b2fa18b15adbd457108e8c80a1f5883/fixme1.tar.gz).
        
        Solution:
        
        # Setup rust and run the code
        
        ```
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
        source $HOME/.cargo/env
        ```
        
        ```
        cp -r fixme1 /tmp/rust_proj
        cd /tmp/rust_proj
        cargo build
        cargo run
        ```
        
        Let’s build it:
        
        ```
        ┌──(root㉿kali)-[/tmp/rust_proj]
        └─# cargo build
           Compiling crossbeam-utils v0.8.20
           Compiling rayon-core v1.12.1
           Compiling either v1.13.0
           Compiling crossbeam-epoch v0.9.18
           Compiling crossbeam-deque v0.8.5
           Compiling rayon v1.10.0
           Compiling xor_cryptor v1.2.3
           Compiling rust_proj v0.1.0 (/tmp/rust_proj)
        error: expected `;`, found keyword `let`
         --> src/main.rs:5:37
          |
        5 |     let key = String::from("CSUCKS") // How do we end statements in Rust?
          |                                     ^ help: add `;` here
        ...
        8 |     let hex_values = ["41", "30", "20", "63", "4a", "45", "54", "76", "01", "1c", "7e", "59", "63", "e1", "61...
          |     --- unexpected token
        
        error: argument never used
          --> src/main.rs:26:9
           |
        25 |         ":?", // How do we print out a variable in the println function?
           |         ---- formatting specifier missing
        26 |         String::from_utf8_lossy(&decrypted_buffer)
           |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ argument never used
        
        error[E0425]: cannot find value `ret` in this scope
          --> src/main.rs:18:9
           |
        18 |         ret; // How do we return in rust?
           |         ^^^ help: a local variable with a similar name exists: `res`
        
        For more information about this error, try `rustc --explain E0425`.
        error: could not compile `rust_proj` (bin "rust_proj") due to 3 previous errors
        ```
        
        # Solve Issues of the Script
        
        - **// How do we end statements in Rust?** : Using Semicolon `;` after the code
        
        ```
        let key = String::from("CSUCKS")
        let key = String::from("CSUCKS");
        ```
        
        - **// How do we end statements in Rust?** : Using `return`
        
        ```
        if res.is_err() {
            ret;
        }
        
        if res.is_err() {
            return;
        }
        ```
        
        - **// How do we print out a variable in the println function?** : Using `"{}"`
        
        ```
        println!(
            ":?",
            String::from_utf8_lossy(&decrypted_buffer)
        );
        
        println!(
            "{}",
            String::from_utf8_lossy(&decrypted_buffer)
        );
        ```
        
        # Fixed Script `main.rs`
        
        ```
        use xor_cryptor::XORCryptor;
        
        fn main() {
            // Key for decryption
            let key = String::from("CSUCKS"); // How do we end statements in Rust?
        
            // Encrypted flag values
            let hex_values = ["41", "30", "20", "63", "4a", "45", "54", "76", "01", "1c", "7e", "59", "63", "e1", "61", "25", "7f", "5a", "60", "50", "11", "38", "1f", "3a", "60", "e9", "62", "20", "0c", "e6", "50", "d3", "35"];
        
            // Convert the hexadecimal strings to bytes and collect them into a vector
            let encrypted_buffer: Vec<u8> = hex_values.iter()
                .map(|&hex| u8::from_str_radix(hex, 16).unwrap())
                .collect();
        
            // Create decrpytion object
            let res = XORCryptor::new(&key);
            if res.is_err() {
                return; // How do we return in rust?
            }
            let xrc = res.unwrap();
        
            // Decrypt flag and print it out
            let decrypted_buffer = xrc.decrypt_vec(encrypted_buffer);
            println!(
                "{}", // How do we print out a variable in the println function?
                String::from_utf8_lossy(&decrypted_buffer)
            );
        }
        ```
        
        Now run it & the flag will be appeared:
        
        ```
        ┌──(root㉿kali)-[/tmp/rust_proj]
        └─# cargo run
        
            Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.00s
             Running `target/debug/rust_proj`
        ```
        
        picoCTF{4r3_y0u_4_ru$t4c30n_n0w?}
        
    - **Special (Medium)**
        
        
        Solution:
        
        **Approach**
        
        This took *a lot* of experimenting with bash shell syntax that I was familiar, throwing everything at the wall until I stumbled on the use of `((cat))`whilst trying to concatenate potential flag files in the working folder. This command would not emit the typical error and would await for further input on standard input, as if `cat` command was being executed without arguments.
        
        Knowing this, and assuming `cat` could be replaced by any command, the next test was to use `((ls))` to start gathering information about what is in the current working folder that may be accessible.
        
        `((ls))` showed a single entry `blargh`.
        
        I then spent a quite a while trying to interact with `blargh` and the method of command execution I had found. What I quickly realised though was the `((<command>))` mechanism did not facilitate the use of arguments, for example attempts to `cat blargh` or `ls -al` failed, they were not being parsed properly by the "Special (TM)" interpretor.
        
        There had to be a method of getting additional data into 
        commands, which is when I started experimenting with input redirection. 
        Finding the following command syntax was doing as I expected:
        
        ```
        ((cat)) < blargh
        
        ```
        
        This returned an error indicating `blargh` was actually a directory and not a file, therefore having a guess at its possible contents led to the final solution.
        
        **Solution**
        
        The final command used to drop the flag during the event was :
        
        `Special$ ((cat)) < blargh/flag.txt
        ((cat)) < blargh/flag.txt`
        
        picoCTF{5p311ch3ck_15_7h3_w0r57_0c61d335}
        
    - **Specilier (Medium)**
        
        
        Solution:
        
        I logged in through the given instances and tried to explore different possibility to get the flag. Initially, I tried some linux system commands. But, that didn’t provide any results. It really seemed off. I guess the creator of this challenge has either deleted / moved these binaries from **/bin** directory.
        
        Zoom image will be displayed
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*v6Opywam9ILDlxdDEBvWWw.png)
        
        But luckily, there are commands like **pwd**, **cd** that provided intended response. So, I decided to autocomplete the command by pressing **<tab>** button and it yielded the following result:
        
        Zoom image will be displayed
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*LXLSxQqovqwBy7_hokepKg.png)
        
        Fortunately, these commands were working fine. So, I decided to construct a shell 
        program that would print the files & folders for the current directory.
        
        > Commands like for, while, do, then, done, if, elif, echo
         can be constructed as a program and it can be used to print the working
         directory contents. Quickly, I wrote a simple function that could 
        perform the same.
        > 
        
        ```
        for file in *
        do
          if [ -d "$file" ]; then
            echo "$file is a directory."
          elif [ -f "$file" ]; then
            echo "$file is a file."
          fi
        done
        ```
        
        This program would differentiate the files and folders and display it accordingly.
        
        Zoom image will be displayed
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*lCwE_wDPiA-Z3-SmhHc3oA.png)
        
        From the above result, we could see that there are three directories. Let’s poke in and execute the same command.
        
        ## Abra Directory:
        
        Zoom image will be displayed
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*hee3_ghE8wiBKKYnrzomvQ.png)
        
        Similarly, **Ala** and **sim** folder had the following results.
        
        Zoom image will be displayed
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*ies0xR-lR5HB2QaPmIbMNw.png)
        
        Now, let’s modify the code a bit, and print the content of each files from their folders:
        
        ```
        for folder in abra ala sim
        do
          cd "$folder"
          for file in *
          do
            if [ -d "$file" ]; then
              echo "$file: directory."
            elif [ -f "$file" ]; then
              echo "$folder/$file:"
              printf "%s " $(<$file) # input redirection; alternative to 'cat'
              printf "\n\n"
            fi
          done
          cd ..
        done
        ```
        
        Zoom image will be displayed
        
        ![](https://miro.medium.com/v2/resize:fit:1400/1*iR2h9-8_i4gmTQ_XYFdGgA.png)
        
        There we go! ⛳️
        
        > picoCTF{y0u_d0n7_4ppr3c1473_wh47_w3r3_d01ng_h3r3_a8567b6f}
        > 

### **Steganography**

### WMSUCCS-CTF

- **Deceptive_QR**
    
    # Deceptive QR
    
    **Category** : Steganography
    **Points** : 25
    
    Not everything is as it seems. The surface lies, but the truth is buried deeper.
    
    ## Files :
    
    - [qr.jpeg](https://www.notion.so/qr.jpeg)
    
    Solution:
    
    I was given a jpeg file that contains a qr code. after scanning the image I was given the text "I am not the flag :P". First, I thought that it was just a dead end. But after noticing the file size of the jpeg file. I noticed that it was a bit larger than normal files. So I first did a binwalk. However it didnt show anything. Now on my second try I did a steghide. since it needs a passphrase for it to extract, I thought of using brute force. However after noticing the text that was given to me. I tried using it and after it finished scanning. It gave me the flag.
    
    CCS{Wh4t_T00l}
    
- **Rizz**
    
    The challenge, titled *Empty but Full* (50 points, Steganography), provided a `.docx` file that initially appeared empty. Suspecting hidden content, I unzipped the DOCX (since it's a ZIP container format) using `unzip b2x2.docx -d extracted_docx/`, which revealed an embedded image inside `word/media/image1.jpeg`. 
    
    Viewing the image showed a picture of Shrek with a blue line and the words "Not Here," suggesting a deliberate misdirection. Examining the document’s `document.xml` revealed a crucial textual hint: *“Sometimes, you gotta pull more than just rizz from the image.”* 
    
    This confirmed that the flag was likely hidden within the image itself. Running `strings` on the JPEG file revealed a suspicious fragment: `shr3k isO]e theO%( keygwwT`, which clearly resembled the phrase “shrek is the key.” 
    
    Interpreting this as a password hint, I used `steghide extract -sf image1.jpeg -p shr3k`, which successfully extracted a hidden file containing the flag. The challenge was solved using a combination of DOCX structure analysis, string inspection, and steganographic extraction. 
    
    Tools used included `unzip` for file extraction, `strings` for plaintext detection, and `steghide` for hidden file recovery. The challenge highlighted the importance of recognizing misdirection and thematic clues—here, the image’s content and Shrek reference led directly to the solution.
    
    CCS{5hr3k_r1zZ}
    
- **Empty_but_Full**
    
    # Empty but Full
    
    **Category** : Steganography
    **Points** : 50
    
    This archive appears empty... but look closer. The void speaks in patterns.
    
    ## Files :
    
    - [b2x2.zip](https://www.notion.so/b2x2.zip)
    
    Solution:
    

**Competitions**

- **DownUnderCTF (2025)**
    - **beginner**
        - **our-lonely-dog**
            
            Dear Tantalost,
            
            e-dog has been alone in the [downunderctf.com](http://downunderctf.com/) email server for so long, please yeet him an email of some of your pets to keep him company, he might even share his favourite toy with you.
            
            He has a knack for hiding things one layer deeper than you would expect.
            
            Regards,
            crem
            
            Solution:
            
            send email to [e-dog@downunderctf.com](mailto:e-dog@downunderctf.com), then download the replay we received as .eml file , u will find the flag as value of the X-FLAG header :)
            `DUCTF{g00d-luCk-G3tT1nG-ThR0uGh-Al1s-Th3-eM41Ls}`
            
        - **Network Disk Forensics**
            
            Dear Tantalost,
            
            Nobody likes having to download large disk images for CTF challenges so this time we're giving you a disk over the network!
            
            Regards,
            jscarsbrook
            
            Solution:
            
            Let's recap. We've got a disk image sitting on a server. That image contains an image file with the flag inside. And we need to connect to the server via NBD to access the image.
            
            We're ready to break out our leet terminal skills.You can run the `nbdinfo` command to "display information and metadata about NBD servers and exports" (source: man nbdinfo).
            
            Let's try:
            
            ```
            nbdinfo --list nbd://chal.2025.ductf.net:30016
            
            ```
            
            This command queries the NBD (Network Block Device) server at `chal.2025.ductf.net` on port `30016` to retrieve metadata about the available exports. The `--list` flag tells `nbdinfo`
             to enumerate the export names, sizes, and supported features. This is 
            useful for verifying that the server is accessible and understanding 
            what kind of block device it provides before attempting to mount or 
            interact with it.
            
            ```
            ┌──(kali㉿kali)-[~]
            └─$ nbdinfo --list nbd://chal.2025.ductf.net:30016
            protocol: newstyle-fixed without TLS, using simple packets
            export="root":
                    export-size: 16777216 (16M)
                    uri: nbd://chal.2025.ductf.net:30016/root
                    is_rotational: false
                    is_read_only: false
                    can_block_status_payload: false
                    can_cache: false
                    can_df: false
                    can_fast_zero: false
                    can_flush: false
                    can_fua: false
                    can_multi_conn: false
                    can_trim: false
                    can_zero: false
                    block_size_minimum: 1
                    block_size_preferred: 4096 (4K)
                    block_size_maximum: 33554432 (32M)
            
            ```
            
            Perfect — that output tells us exactly what we need:
            
            - The NBD export is named **`root`**
            - The size is small (`16MB`) — likely a single-partition image
            - The URI is: `nbd://chal.2025.ductf.net:30016/root`
            
            To connect to the NBD Server, you might be tempted to do something like this:
            
            ```
            ┌──(kali㉿kali)-[~]
            └─$ sudo nbd-client chal.2025.ductf.net 30016 /dev/nbd0
            
            [sudo] password for kali:
            Warning: the oldstyle protocol is no longer supported.
            This method now uses the newstyle protocol with a default export
            Negotiation: ..Error: Unknown error returned by server.
            Exiting.
            
            ```
            
            `nbd-client` didn't work because the `nbd-client`
             tool expects an NBD server using the oldstyle protocol, but the 
            challenge server is using the newstyle-fixed protocol without TLS (as 
            can be seen in the output from `nbdinfo`: `protocol: newstyle-fixed without TLS, using simple packets`) and requires the client to specify an export name — in this case, `"root"`.
            
            The server is exporting a block device named "root", but `nbd-client` (by default) tries to connect without specifying an export name, which results in negotiation failure.
            
            `nbd-client` does support newstyle, but it's 
            known to be finicky or less reliable with newstyle exports unless 
            explicitly configured. In this case, it fails silently.
            
            We'll need to use something else.
            
            After a bit of searching, I landed on `qemu-nbd`, which allows us to (among other things) "bind a `/dev/nbdX` block device to a QEMU server (on Linux)."
            
            `qemu-nbd` is better suited for modern NBD 
            exports and gives us more control, including specifying the full NBD URI
             (we'll get to this shortly).
            
            Before we can use `qemu-nbd` (assuming it's already installed), we need to make sure the system is ready to handle NBD devices. By default, the `nbd` kernel module isn’t loaded on most systems. Without it, `/dev/nbdX` devices (like `/dev/nbd0`)
             don’t exist — so any tool that tries to connect to an NBD export will 
            fail because the kernel interface simply isn’t available.
            
            We can use `modprobe nbd` to dynamically load the kernel driver that enables the NBD subsystem and creates the `/dev/nbd*` devices.
            
            ```
            ┌──(kali㉿kali)-[~]
            └─$ sudo modprobe nbd max_part=8
            
            ```
            
            What's `max_part=8` for? Good question, well asked.
            That option controls the maximum number of partitions the kernel will scan per NBD device. So, `max_part=8` tells the kernel: "For each `/dev/nbdX`, support up to 8 partitions (like `/dev/nbd0p1`, `/dev/nbd0p2`, etc.)." Without this, partition scanning might be limited or disabled, and mount or fdisk may not behave as expected.
            
            Running the full `modprobe nbd` command above loaded the module and made `/dev/nbd0` available, allowing the system to map and mount the remote disk properly.
            
            We can use `ls` to confirm that the system has 
            created virtual block devices. These devices can be connected to remote 
            disk images over the network using `qemu-nbd`.
            
            ```
            ┌──(kali㉿kali)-[~]
            └─$ ls /dev/nbd*
            
            /dev/nbd0  /dev/nbd10  /dev/nbd12  /dev/nbd14  /dev/nbd2  /dev/nbd4  /dev/nbd6  /dev/nbd8
            /dev/nbd1  /dev/nbd11  /dev/nbd13  /dev/nbd15  /dev/nbd3  /dev/nbd5  /dev/nbd7  /dev/nbd9
            
            ```
            
            We're now ready to connect the remote NBD export (`root`) from the server to a local block device (`/dev/nbd0`).
            
            ```
            ┌──(kali㉿kali)-[~]
            └─$ sudo qemu-nbd --connect=/dev/nbd0 --format=raw nbd://chal.2025.ductf.net:30016/root
            
            ```
            
            By specifying `--format=raw`, we tell `qemu-nbd` not to expect any image container format like qcow2 — just a raw disk. After this, `/dev/nbd0` acts like a real disk containing the ext4 filesystem, and we can inspect or mount it just like a local drive.
            
            `fdisk -l` lists all partitions on the given disk.
            
            ```
            ┌──(kali㉿kali)-[~]
            └─$ sudo fdisk -l /dev/nbd0
            Disk /dev/nbd0: 16 MiB, 16777216 bytes, 32768 sectors
            Units: sectors of 1 * 512 = 512 bytes
            Sector size (logical/physical): 512 bytes / 512 bytes
            I/O size (minimum/optimal): 512 bytes / 131072 bytes
            
            ```
            
            This confirms that the remote NBD export 
            is working, and helps us determine if the image contains partitions. In 
            our case, it reports a 16 MiB raw disk, which suggests either no 
            partition table or a single partition that spans the entire disk. That's
             a hint that we may be able to mount the whole device directly, without 
            needing to extract a specific partition (like `/dev/nbd0p1`).
            
            Go ahead and mount the image.
            
            ```
            ┌──(kali㉿kali)-[~]
            └─$ sudo mount /dev/nbd0 /mnt
            
            ```
            
            We mount the NBD-backed disk directly to `/mnt`. Since the image contains a raw ext4 filesystem with no partition table, we can mount `/dev/nbd0` directly, rather than needing to mount a partition like `/dev/nbd0p1`.
            
            Finally, using File Manager, navigate to the `/mnt` directory and you'll see the remote disk image.
            
            ![File Manager](https://github.com/samcsss/Writeups/raw/main/2025-DUCTF/images/network-disk-forensics-1.png)
            
            Opening the `flag.jpg` image in the top-level directory reveals the flag.
            
            ![Flag](https://github.com/samcsss/Writeups/raw/main/2025-DUCTF/images/network-disk-forensics-2.png)
            
        - Horoscope
            
            Dear Tantalost,
            
            Forwarded Mail:
            
            > Hey Sis! Its getting pretty bad out here.. they keep telling us to connect on this new
            and improved protocol. The regular web is being systematically attacked and compromised
            > 
            > 
            > Little Tommy has been born! He's a Taurus just a month before matching his mum and dad!
            > Hope to see you all for Christmas
            > 
            > Love, XXXX
            > 
            
            Regards,
            
            pix
            
            Solution:
            
            This challenge gave a few unusual clues referencing **zodiac signs** — specifically, the son mentioned being a *Taurus* and his parents being *Gemini*. That felt oddly specific, so I considered it might relate to a protocol or system named after zodiac signs.
            
            After doing some research, I discovered the **Gemini Protocol**, a lightweight, privacy-focused alternative to HTTP. Realizing this could be the intended vector, I installed a **Gemini browser** (I used Lagrange but any Gemini-compatible client would work).
            
            Once I opened the provided Gemini link in the browser, I navigated to the **homepage** and found the **flag clearly displayed** there.
            
            `DUCTF{g3mini_pr0t0col_s4ved_us}`
            
        - **Wiki**
            
            Dear Tantalost,
            
            Use the Wiki to find the flag...
            
            NOTE: This challenge is a continuation of "Horoscopes", we recommend you complete that challenge first!
            
            Regards,
            pix
            
            Solution:
            
            wiki was gemini://chal.2025.ductf.net:30015/linker.gmi
            I went through all the pages until I found the right one : gemini://chal.2025.ductf.net:30015/pages/rabid_bean_potato.gmi
            
            `DUCTF{rabbit_is_rabbit_bean_is_bean_potato_is_potato_banana_is_banana_carrot_is_carrot}`
            
        - **Trusted**
            
            Dear Tantalost,
            
            It looks like they never really finished their admin panel.. Or they let the intern do it. The connection info and credientials are all inside the server, but we can't seem to get in.
            
            Maybe you can take a look at it and tell us whats behind the admin panel?
            
            NOTE: This challenge is a continuation of "Horoscopes", we recommend you complete that challenge first!
            
            Regards,
            pix
            
            Solution:
            
            One page says the admin page is on port 756f (which is 30063)
            Another one says the password is But+ripples+show=truth%in motion
            So connect via nc : `nc -v chal.2025-us.ductf.net 30063`
            
            then send the following : 
            `/password_protected.gmi?But%2Bripples%2Bshow%3Dtruth%25in%20motion`
            
            and thats it
            
            `DUCTF{Cr1pPl3_Th3_1nFr4sTrUCtu53}`
            
    - **osint**
        - **fat donke diss**
            
            Dear Tantalost,
            
            ain't no fat donke tryin to spit bars on the fat monke
            
            Regards,
            MC Fat Monke
            
            Solution:
            
            To solve this challenge, I started by investigating the identity of "MC Fat Monke." A quick Google search pointed me to a **SoundCloud account** that matched the name.
            
            On his SoundCloud page, I noticed a **recently uploaded track**. In the track’s description, there was a link that led to a **YouTube video** — clearly something important.
            
            I watched the YouTube video closely and spotted a moment where **he was on his computer**. Pausing and zooming in on the screen, I found a String of text **displayed on the screen** — this turned out to be the location of the flag.
            
            `DUCTF{I_HAVE_NOT_THOUGHT_UP_OF_A_FLAG_YET}`
            
        - **Zer0C00l (Medium)**
            
            Dear Tantalost,
            
            We've been able to pull some audio from a tape backup, only problem 
            is it's from 1995!! We know it's a Sydney number and there must be a 
            modem at the other end...who are they calling?
            
            Wrap the answer within `DUCTF{...}` (case insensitive)
            
            NOTE: You do not need to physically call anyone to solve this challenge!
            
            Regards,
            
            Nosurf
            
            Solution:
            
            DTMF decoder to the digits 3693244. Since the clue said it was a Sydney call from 1995 i applied the 1990s Australian numbering change that added a leading 9 to Sydney local number giving 9369 3244 (full format (02) 9369 3244. They asked “wwho are they calling?” ......Searching ....... found this 61-2-9369-3244. Baud: 9600. Flags: V32b, V42b, MNP, XA. SysOp: Nick Harvey. AKA: 3:712/941. System: Hotline. Location: Waverley NSW. Date: 1996-08-31 - 1997-02- 
            
            `DUCTF{hotline}` 
            
    - **misc**
        - **scrapbooking**
            
            

## Writeup References

https://james-mercado-work.medium.com/p0isonp4wn-hack4gov-2019-ctf-writeups-9c405f4d9e16

https://james-mercado-work.medium.com/p0isonp4wn-haxxor4-0-ctf-writeups-31ca7ce6570d

https://blog.huli.tw/2024/06/28/en/google-ctf-2024-writeup/

https://github.com/erfanghorbanee/picoCTF-2024

https://infosecwriteups.com/