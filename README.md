# why ChaCha20?
from https://crypto.stackexchange.com/questions/34455/whats-the-appeal-of-using-chacha20-instead-of-aes
```
I believe there are three main reasons why ChaCha20 is sometimes preferred to AES.

On a general-purpose 32-bit (or greater) CPU without dedicated instructions, ChaCha20 is generally faster than AES. The reason for this is the fact that ChaCha20 is based on ARX (Addition-Rotation-XOR), which are CPU friendly instructions. At the same time, AES uses binary fields for the S-box and Mixcolumns computations, which are generally implemented as a look-up table to be more efficient.

AES's use of a look-up table with an index derived from the secret makes general implementations vulnerable to cache-timing attacks. ChaCha20 is not vulnerable to such attacks. (AES implemented through AES-NI is also not vulnerable).

Daniel J. Bernstein is having significant greater-than-average success in advertising his algorithms. (I'm not implying there are no merits. I'm just stating the fact that his algorithms have success in terms of deployment).

Of course, other reasons justify the choice of AES instead of ChaCha20.

To name a few:

Dedicated instructions on high-end CPUs
Amount of received cryptanalysis
Availability of studies on side-channel (other than cache timing) protections
```