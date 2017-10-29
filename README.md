# AtCryptoAuthLib
Arduino library for the Atmel/Microchip ATECC508a<br>
<br>
NOTE: You must change the i2c buffer length in the Wire library to make this work.<br>
I changed it to 160 but a shorter length (72 maybe) may also work.<br>
<br>
#define BUFFER_LENGTH 160<br>

