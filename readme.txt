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
  go get golang.org/x/crypto/pbkdf2
  go build encrypt.go
  add the built executable to someplace on your path 

  Why I didn't include binaries.
  I don't know you, you don't know me, you really should read 
  the source code in encrypt.go before trusting this utility 
  to do what I claim and nothing else.   


Alternative to Password Manager?
  Why I Prefer Simple, Transparent Encryption Over Password Managers
  
  Password managers are often touted as the ultimate solution for securing
  and managing your passwords, but they come with their own set of
  challenges. Over the years, I've encountered several issues that have 
  made me rethink their reliability:
  
  Data Corruption: Password managers occasionally corrupt stored data, 
  leaving you locked out of your accounts when you need access the most.

  Trust Concerns: Some password managers are developed in jurisdictions where
  data security and user privacy may not be a priority—or worse, are actively
  compromised.
  
  End of Support: I've had two companies behind popular password managers 
  shut down, leaving users stranded without updates or support.

  In contrast, using a simple, transparent encryption tool to store your 
  passwords in files encrypted with a passphrase you can remember offers a 
  level of control and reliability that password managers often lack:
  
  Complete Transparency: By using a programming language like Go—a widely 
  used, secure, and easy-to-understand language—you can review the code to 
  ensure it does exactly what it claims. This eliminates the risk of hidden
  malicious features, such as silently copying your private data to unknown
  servers.

  Long-Term Viability: Encrypting files locally doesn’t depend on a company's
  continued existence or support. As long as you have access to the encryption
  tool and remember your passphrase, your data remains accessible.

  Auditable Simplicity: A simple tool with a clean, concise codebase can be
  validated even by non-engineers, ensuring there are no backdoors or
  vulnerabilities.

  As a security professional, these aspects are invaluable. They provide the
  confidence that my sensitive data is secure, under my control, and free from 
  external dependencies. While password managers may suit some users, this
  approach prioritizes transparency, independence, and trustworthiness—qualities
  that are increasingly rare in today’s digital landscape.


