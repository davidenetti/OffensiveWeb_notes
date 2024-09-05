In certain web technology frameworks, a common practice is to initially isolate uploaded files in a separate folder. After ensuring the file’s content type is valid, these frameworks then transfer the file to its intended destination directory. This process typically relies on technologies like antiviruses to identify and prevent any potential malicious code. However, what if the developer mistakenly places the sandboxed directory and the destination directory (from which the file is fetched) in the same location?


Code example
```php
<?php
$target_dir = "avatars/";
$target_file = $target_dir . $_FILES["avatar"]["name"];

// temporary move
move_uploaded_file($_FILES["avatar"]["tmp_name"], $target_file);

if (checkViruses($target_file) && checkFileType($target_file)) {
    echo "The file ". htmlspecialchars( $target_file). " has been uploaded.";
} else {
    unlink($target_file);
    echo "Sorry, there was an error uploading your file.";
    http_response_code(403);
}

function checkViruses($fileName) {
    // checking for viruses
    ...
}

function checkFileType($fileName) {
    $imageFileType = strtolower(pathinfo($fileName,PATHINFO_EXTENSION));
    if($imageFileType != "jpg" && $imageFileType != "png") {
        echo "Sorry, only JPG & PNG files are allowed\n";
        return false;
    } else {
        return true;
    }
}
?>
```

As observed, both the temporary directory and the destination directory are identical. The conditional statement evaluates two factors: content type and antivirus scan results, along with the file type (determined by the file extension). **Theoretically, there exists a time frame between moving the file to the temporary folder and checking (or deleting) the file when malicious code is detected**. This brief window allows a file with malicious content to linger on the server for a few milliseconds — ample time to be exploited through a GET request.

To exploit it:
- Intercept the POST "upload request" with Burp;
- Send it to the Intruder;
- Intercept the GET request with Burp;
- Send it to the Intruder
- We need to send both the POST request (to upload the file) and the GET request (to read the PHP output);
- For both the POST and the GET, we need to set the payload as **NULL payload and continues indefinitely**.

