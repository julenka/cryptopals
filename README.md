# cryptopals
Solutions to cryptopals Cryptography puzzles: http://cryptopals.com/

# 9/24 Set 1 Challenge 7: Installing OpenSSL
I need to install OpenSSL on Windows to use OpenSSL::Cipher. 

1. Download OpenSSL code from https://www.openssl.org/source/
2. Install PERL from https://www.activestate.com/ActivePerl
3. Run cpan -i "Text::Template"
4. cd C:\Users\julen\Desktop\openssl-1.1.0f.tar\openssl-1.1.0f\
5. perl Configure VC-WIN64I no-asm
6. nmake install


 For VC-WIN64, the following defaults are use:

     PREFIX:      %ProgramW6432%\OpenSSL
     OPENSSLDIR:  %CommonProgramW6432%\SSL


### OpenSSL 1.1.0 doesn't seem to be working. Time to try using 1.2.0
https://stackoverflow.com/questions/36120065/build-openssl-in-visual-studio-2013