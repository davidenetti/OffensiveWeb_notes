Obfuscation is a technique used to make a script more difficult to read by humans but allows it to function the same from a technical point of view, though performance may be slower. This is usually achieved automatically by using an obfuscation tool, which takes code as an input, and attempts to re-write the code in a way that is much more difficult to read, depending on its design.

# Deobfuscation online tools
- JS Console;
- Prettier;
- Beautifier;
- JSNice.

# Terminal commands
- **echo test | base64**: base64 encode
- **echo ENCODED_B64 | base64 -d**: base64 decode
- **echo test | xxd -p**: hex encode
- **echo ENCODED_HEX | xxd -p -r**: hex decode
- **echo test | tr 'A-Za-z' 'N-ZA-Mn-za-m'**: rot13 encode
- **echo ENCODED_ROT13 | tr 'A-Za-z' 'N-ZA-Mn-za-m'**:	rot13 decode
