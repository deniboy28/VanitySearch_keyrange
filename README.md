# VanitySearch

VanitySearch is a bitcoin address prefix finder. If you want to generate safe private keys, use the -s option to enter your passphrase which will be used for generating a base key as for BIP38 standard (*VanitySearch.exe -s "My PassPhrase" 1MyPrefix*). You can also use *VanitySearch.exe -ps "My PassPhrase"* which will add a crypto secure seed to your passphrase.\
VanitySearch may not compute a good grid size for your GPU, so try different values using -g option in order to get the best performances. If you want to use GPUs and CPUs together, you may have best performances by keeping one CPU core for handling GPU(s)/CPU exchanges (use -t option to set the number of CPU threads).

# Feature

<ul>
  <li>Fixed size arithmetic</li>
  <li>Fast Modular Inversion (Delayed Right Shift 62 bits)</li>
  <li>SecpK1 Fast modular multiplication (2 steps folding 512bits to 256bits using 64 bits digits)</li>
  <li>Use some properties of elliptic curve to generate more keys</li>
  <li>SSE Secure Hash Algorithm SHA256 and RIPEMD160 (CPU)</li>
  <li>Multi-GPU support</li>
  <li>CUDA optimisation via inline PTX assembly</li>
  <li>Seed protected by pbkdf2_hmac_sha512 (BIP38)</li>
  <li>Support P2PKH, P2SH and BECH32 addresses</li>
  <li>Support split-key vanity address</li>
</ul>

# Discussion Thread



```
VanitySearch [-check] [-v] [-u] [-b] [-c] [-gpu] [-stop] [-i inputfile]
             [-gpuId gpuId1[,gpuId2,...]] [-g g1x,g1y,[,g2x,g2y,...]]
             [-o outputfile] [-m maxFound] [-ps seed] [-s seed] [-t nbThread]
             [-nosse] [-r rekey] [-check] [-kp] [-sp startPubKey]
             [-rp privkey partialkeyfile] [prefix]

 prefix: prefix to search (Can contains wildcard '?' or '*')
 -v: Print version
 -u: Search uncompressed addresses
 -b: Search both uncompressed or compressed addresses
 -c: Case unsensitive search
 -gpu: Enable gpu calculation
 -stop: Stop when all prefixes are found
 -i inputfile: Get list of prefixes to search from specified file
 -o outputfile: Output results to the specified file
 -gpu gpuId1,gpuId2,...: List of GPU(s) to use, default is 0
 -g g1x,g1y,g2x,g2y, ...: Specify GPU(s) kernel gridsize, default is 8*(MP number)
 -startkey hex_private_key: Start the search from a specific private key (hex format)
 -endkey hex_private_key: End the search at a specific private key (hex format)
 -m: Specify maximun number of prefixes found by each kernel call
 -s seed: Specify a seed for the base key, default is random
 -ps seed: Specify a seed concatened with a crypto secure random seed
 -t threadNumber: Specify number of CPU thread, default is number of core
 -nosse: Disable SSE hash function
 -l: List cuda enabled devices
 
 -check: Check CPU and GPU kernel vs CPU
 -cp privKey: Compute public key (privKey in hex hormat)
 -kp: Generate key pair
 -rp privkey partialkeyfile: Reconstruct final private key(s) from partial key(s) info.
 -sp startPubKey: Start the search with a pubKey (for private key splitting)
 -r rekey: Rekey interval in MegaKey, default is disabled
```

Exemple (Windows, Intel Core i7-4770 3.4GHz 8 multithreaded cores, GeForce GTX 1050 Ti):

```
C:\C++\VanitySearch\x64\Release>VanitySearch.exe -stop -gpu -startkey 0000000000000000000000000000000000000000000000400000000000000000 -endkey 00000000000000000000000000000000000000000000007fffffffffffffffff 1PWo3J
```


# Trying to attack a list of addresses

The bitcoin address (P2PKH) consists of a hash160 (displayed in Base58 format) which means that there are 2<sup>160</sup> possible addresses. A secure hash function can be seen as a pseudo number generator, it transforms a given message in a random number. In this case, a number (uniformaly distributed) in the range [0,2<sup>160</sup>]. So, the probability to hit a particular number after n tries is 1-(1-1/2<sup>160</sup>)<sup>n</sup>. We perform n Bernoulli trials statistically independent.\
If we have a list of m distinct addresses (m<=2<sup>160</sup>), the search space is then reduced to 2<sup>160</sup>/m, the probability to find a collision after 1 try becomes m/2<sup>160</sup> and the probability to find a collision after n tries becomes 1-(1-m/2<sup>160</sup>)<sup>n</sup>.\
An example:\
We have a hardware capable of generating **1GKey/s** and we have an input list of **10<sup>6</sup>** addresses, the following table shows the probability of finding a collision after a certain amount of time:

| Time     |  Probability  |
|----------|:-------------:|
| 1 second |6.8e-34|
| 1 minute |4e-32|
| 1 hour |2.4e-30|
| 1 day |5.9e-29|
| 1 year |2.1e-26|
| 10 years | 2.1e-25 |
| 1000 years | 2.1e-23 |
| Age of earth | 8.64e-17 |
| Age of universe | 2.8e-16 (much less than winning at the lottery) |

Calculation has been done using this [online high precision calculator](https://keisan.casio.com/calculator)

As you can see, even with a competitive hardware, it is very unlikely that you find a collision. Birthday paradox doesn't apply in this context, it works only if we know already the public key (not the address, the hash of the public key) we want to find.  This program doesn't look for collisions between public keys. It searchs only for collisions with addresses with a certain prefix.

# Compilation

## Windows

Intall CUDA SDK and open VanitySearch.sln in Visual C++ 2017.\
You may need to reset your *Windows SDK version* in project properties.\
In Build->Configuration Manager, select the *Release* configuration.\
Build and enjoy.\
\
Note: The current relase has been compiled with CUDA SDK 10.0, if you have a different release of the CUDA SDK, you may need to update CUDA SDK paths in VanitySearch.vcxproj using a text editor. The current nvcc option are set up to architecture starting at 3.0 capability, for older hardware, add the desired compute capabilities to the list in GPUEngine.cu properties, CUDA C/C++, Device, Code Generation.

## Linux

 - Intall CUDA SDK.
 - Install older g++ (just for the CUDA SDK). Depenging on the CUDA SDK version and on your Linux distribution you may need to install an older g++.
 - Install recent gcc. VanitySearch needs to be compiled and linked with a recent gcc (>=7). The current release has been compiled with gcc 7.3.0.
 - Edit the makefile and set up the appropriate CUDA SDK and compiler paths for nvcc. Or pass them as variables to `make` invocation.

    ```make
    CUDA       = /usr/local/cuda-8.0
    CXXCUDA    = /usr/bin/g++-4.8
    ```

 - You can enter a list of architectrures (refer to nvcc documentation) if you have several GPU with different architecture.

 - Set CCAP to the desired compute capability according to your hardware. See docker section for more. Compute capability 2.0 (Fermi) is deprecated for recent CUDA SDK.

 - Go to the VanitySearch directory.
 - To build CPU-only version (without CUDA support):
    ```sh
    $ make all
    ```
 - To build with CUDA:
    ```sh
    $ make gpu=1 CCAP=2.0 all
    ```

Runnig VanitySearch (Intel(R) Xeon(R) CPU, 8 cores,  @ 2.93GHz, Quadro 600 (x2))
```sh
$ export LD_LIBRARY_PATH=/usr/local/cuda-8.0/lib64
$ ./VanitySearch -t 7 -gpu -startkey 0000000000000000000000000000000000000000000000400000000000000000 -endkey 00000000000000000000000000000000000000000000007fffffffffffffffff 1PWo3J

```

# License

VanitySearch is licensed under GPLv3.
