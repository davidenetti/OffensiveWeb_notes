Polyglots, in a security context, are files that are a valid form of multiple different file types. For example, a GIFAR is both a GIF and a RAR file. There are also files out there that can be both GIF and JS, both PPT and JS, etc.
Polyglot files are often used to bypass protection based on file types. Many applications that allow users to upload files only allow uploads of certain types, such as JPEG, GIF, DOC, so as to prevent users from uploading potentially dangerous files like JS files, PHP files or Phar files.

One example of a polyglot file is a **Phar-JPEG file**. Phar files are used to carry out PHP object injection attacks:

This type of attack can lead to RCE. However, it requires the attacker to be able to upload a readable Phar file, and Phar files are not often allowed by file upload functionalities. So a Phar-JPEG file allows the malicious upload to look like a harmless JPEG file to bypass upload restrictions, but still retain the capabilities of a Phar file.

First, it is important to understand that **different file types are simply chunks of bytes that follow a predefined structure**.

For example, let’s look at the **PHAR (PHp ARchive) format**. For a Phar file to be valid, it needs to follow a certain structure: it contains a stub section, a manifest section and finally, a file content section.

- Stub: the stub is a chunk of PHP code which is executed when the file is accessed in an executable context. At a minimum, the stub must contain __HALT_COMPILER(); at its conclusion. Otherwise, there are no restrictions on the contents of a Phar stub;
- Manifest: this section contains metadata about the archive and its contents;
- File contents: this section contains the actual files in the archive;
- Signature (optional): for verifying archive integrity.


### PHP/JPG poliglot file

- Download a PNG image;
- Use exiftool as follow.

```bash
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" <YOUR-INPUT-IMAGE>.jpg -o polyglot.php
```

Attention: **Sometimes you need to compress the image size for the upload**.