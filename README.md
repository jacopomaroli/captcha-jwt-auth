# Captcha JWT Auth
This service allows you to generate a captcha and provides a jwt after solving it.  
A validation endpoint is also provided.

# Quickstart
1. `mkdir captcha-jwt-auth`
2. `cd captcha-jwt-auth`
3. `wget https://github.com/jacopomaroli/captcha-jwt-auth/raw/master/docker-compose.yml`
4. `wget https://github.com/jacopomaroli/captcha-jwt-auth/raw/master/env.example`
5. copy .env.example to .env
6. generate the corresponding keys and replace the values in the .env file using the following
    CJA_CAPTCHA_KEY
    ```
    openssl rand 32 | base64 -w 0
    ```
    CJA_CAPTCHA_NONCE
    ```
    openssl rand 24 | base64 -w 0
    ```
    CJA_JWT_SECRET
    ```
    openssl rand 256 | base64 -w 0
    ```
7. Run `docker-compose up -d`
8. Run `docker-compose logs -f`
9. Open http://localhost:3000/captcha on your browser
10. Look at the logs in the terminal where you run `docker-compose logs -f`, look `solution` and `sessionData` fields and replace them in the following command
```
curl -vvv -X POST -H "Content-Type: application/json" -d "{\"sessionData\": \"$SESSION_DATA\", \"solution\": \"$SOLUTION\"}" http://localhost:3000/session
```
11. get the JWT from the previous point and replace it in the following request to validate it
```
curl -vvv -X POST -H "Content-Type: application/json" -d "{\"jwt\": \"$JWT\"}" http://localhost:3000/validate
```

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

# References, shoutouts, and things that helped developing the project
- https://github.com/zupzup/rust-jwt-example
- https://kerkour.com/rust-web-framework-2022
- https://stackoverflow.com/questions/56117273/actix-web-reports-app-data-is-not-configured-when-processing-a-file-upload
- https://actix.rs/actix-web/src/actix_web/data.rs.html#153-155
- https://blog.logrocket.com/packaging-a-rust-web-service-using-docker/
- https://zsiciarz.github.io/24daysofrust/book/vol2/day4.html
- https://docs.rs/slog/latest/slog/index.html
- https://rust-docs.riochain.io/slog_derive/index.html
- https://actix.rs/docs/middleware/
- https://github.com/timtonk/actix-web-middleware-requestid
