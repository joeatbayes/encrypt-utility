A utility to encrypt or decrypt a file using AES encryption and up to a 32 byte key

I wanted this tool because pgp is not available everywhere I want to take 
protected files and I wanted a simple yet fast tool to encrypt private 
files before moving them to other computers. 

Example Usage:

Encrypt a File:
  bash
     echo "123456" | ./encrypt -e -r file.txt

  Encrypts file.txt to file.txt.enc (Base64-encoded).
  Removes file.txt.  Omit -r option to keep original file

Decrypt a File:
  bash
    echo "123456" | ./encrypt -d -r file.txt.enc
  
  Decrypts file.txt.enc (Base64-decoded) to file.txt.
  Removes file.txt.enc.  omit the -r option to keep 
  original file.

The password is piped in on stdin to make it easy 
to script while keeping password out of ps lists 
where it can be harvested by malicious code. 

Encypted file contents are base64 encoded to avoid
issues with line feed / new line transalations between
windows and linux.


BUILDING:
  Install golang
  git clone git@github.com:joeatbayes/encrypt-utility.git
  cd to directory where you cloned the code
  go build encrypt.go
  add the built executable to someplace on your path 

