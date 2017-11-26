# Cryptopals Puzzle Notes!
My notes from cryptopals Cryptography puzzles, at http://cryptopals.com/

# Set 1 Challenge 7: Installing OpenSSL

### Step 1: Install the OpenSSL Library
I need to install OpenSSL on Windows to use OpenSSL::Cipher.

Getting it to compile is hard. Following instructions from [here](https://stackoverflow.com/questions/36120065/build-openssl-in-visual-studio-2013)


1. Download [1.0.2h openssl source](https://github.com/openssl/openssl/archive/OpenSSL_1_0_2h.zip)
2. Install PERL from https://www.activestate.com/ActivePerl
3. Install [NASM 2.13.01](http://www.nasm.us/pub/nasm/releasebuilds/2.13.01/win64/), and add it to PATH
4. Open "x64 Native Tools Command Prompt for VS 2017" (search for it in start menu)
3. Run the following commands

    perl Configure VC-WIN64A --prefix=C:\openssl_x64 no-asm no-shared enable-tlsext enable-static-engine
    ms\do_win64a
    nmake -f ms\ntdll.mak
    nmake -f ms\ntdll.mak install

This will install openssl library in `C:\openssl_x64`

### Step 2: Configure project to link against OpenSSL library and get include paths to work

I copied both the include and lib folders from `C:\openssl_x64` locally so that it would be easier to link and get include paths in the future.

Then I made the following changes:

1. Add the following directory in "VC++ Directories -> Library Directories": (MSBuildProjectDirectory)\lib
2. Add the following directory in "VC++ Directories -> Additional Include Directories": (MSBuildProjectDirectory)\lib
3. Add the following to "Linker->Input": "ssleay32.lib;libeay32;"


### Step 3: Use the API to do AES-128 decryption in ECB mode under key YELLOW SUBMARINE
Sources
[OpenSSL Wiki](https://wiki.openssl.org/index.php/AES)
[Stackoverflow example](https://stackoverflow.com/questions/9889492/how-to-do-encryption-using-aes-in-openssl)
