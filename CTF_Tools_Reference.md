# 🛠️ CTF Tools \& Commands (June Note)



🔐 Hash \& Encoding Tools

\- Hashes.com – Decrypt / hash algorithm identifier

\- Dcode.fr – Cipher decoder

\- TunnelsUp Hash Analyzer – Hash analyzer

\- base64 -d <filename> – Decode Base64 encoded file



🖼️ Steganography Tools

\- steghide

&nbsp; - steghide extract -sf atbash.jpg – Extract hidden data

\- zsteg <image file>

&nbsp; - Detects hidden data patterns in images

\- exiftool <file> – Extract metadata from files/images

\- stepic -d / -e -i – Hide/extract messages in PNG files

\- strings -a <file> | grep <key> – Look for readable text

\- QR Decoder – Decode information from QR codes



🔍 Forensics \& File Inspection

\- gunzip -c filename.gz > new\_filename  – Extract gz file

\- file <filename> – Get file type info

\- cat <file> – View file contents

\- nano <file> – Open and edit file in terminal

\- grep "keyword" <file> – Search inside a file

\- grep -r "term" /path/to/dir – Recursive grep

\- srch\_strings <file> | grep "picoCTF" – Advanced string search

\- Get-Item -Path .\\none.txt -Stream \* – Check for alternate data streams (PowerShell)

\- fdisk -l disk.img – To find the size of the Linux partition in a given disk image (e.g., disk.img)





🧱 Binary \& Hex Analysis

\- binwalk <file> – Analyze binary files, extract embedded data

\- bvi <file> – Hex/ASCII binary editor

\- ghex <file> / HxD – GUI hex editor



🌐 Web Reconnaissance

\- Google Dorking

&nbsp; Use: "keyword" OR "phrase" to find exposed data/pages

\- Bookmarklet

&nbsp; Add a JS script as a bookmark to execute client-side functions

\- Important Pages to Check on Web Servers

&nbsp; - /robots.txt

&nbsp; - /.htaccess

&nbsp; - /.DS_Store



🌐 Networking

\- nc (Netcat) – TCP/UDP connections, port scanning, backdoors



