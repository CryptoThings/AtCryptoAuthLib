
//#include "cryptoauthlib.h"
//#include "hal/atca_hal.h"
//#include "atssl.h"


#include "Arduino.h"
#include "atca_iface.h"
#include "atca_status.h"

#include "Wire.h"
//#include "i2c_t3.h"


/*
		hal->halinit = &hal_i2c_init;
		hal->halpostinit = &hal_i2c_post_init;
		hal->halreceive = &hal_i2c_receive;
		hal->halsend = &hal_i2c_send;
		hal->halsleep = &hal_i2c_sleep;
		hal->halwake = &hal_i2c_wake;
		hal->halidle = &hal_i2c_idle;
		hal->halrelease = &hal_i2c_release;
		hal->hal_data = NULL;

*/

extern "C" {

ATCA_STATUS hal_i2c_init( void *hal, ATCAIfaceCfg *cfg);
ATCA_STATUS hal_i2c_post_init(ATCAIface iface);
ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t *txdata, int txlength);
ATCA_STATUS hal_i2c_receive( ATCAIface iface, uint8_t *rxdata, uint16_t *rxlength);
ATCA_STATUS hal_i2c_wake(ATCAIface iface);
ATCA_STATUS hal_i2c_idle(ATCAIface iface);
ATCA_STATUS hal_i2c_sleep(ATCAIface iface);
ATCA_STATUS hal_i2c_release(void *hal_data );
ATCA_STATUS hal_i2c_discover_buses(int i2c_buses[], int max_buses);
ATCA_STATUS hal_i2c_discover_devices(int busNum, ATCAIfaceCfg *cfg, int *found );

#ifdef DEBUG_I2C
void hexdump(const void *buffer, uint32_t len, uint8_t cols);
#endif

};

uint8_t i2c_addr = 0x60;

ATCA_STATUS hal_i2c_init( void *hal, ATCAIfaceCfg *cfg)
{
  Wire.begin(i2c_addr);

// opMode = I2C_OP_MODE_ISR, I2C_OP_MODE_DMA, I2C_OP_MODE_IMM
// i2c_t3 Wire.setOpMode(I2C_OP_MODE_IMM);

  Wire.setClock(400000);
  return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_post_init(ATCAIface iface)
{
  return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t *txdata, int txlength)
{
  int i;
  size_t s;
#ifdef DEBUG_I2C
  Serial.println("hal_i2c_send ");
  hexdump(txdata, txlength, 40);
  Serial.flush();
#endif

  txdata[0] = 0x03;
  txlength++;
  Wire.beginTransmission(i2c_addr);
  for (i = 0; i < txlength; i++) {
    s = Wire.write(txdata[i]);
    if (s == 0) {
#ifdef DEBUG_I2C
      Serial.print("hal_i2c_send ERROR len ");
      Serial.print(txlength);
      Serial.print(" i ");
      Serial.println(i);
      Serial.flush();
#endif
      return ATCA_INVALID_SIZE;
    }
  }
  Wire.endTransmission();

#ifdef DEBUG_I2C
  Serial.print("hal_i2c_send end ");
  Serial.println(txlength);
  Serial.flush();
#endif
  return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_receive( ATCAIface iface, uint8_t *rxdata, uint16_t *rxlength)
{
  ATCA_STATUS status = ATCA_SUCCESS;
  int i;
  int retries = 0;
  int no_resp_tries = 0;
  uint8_t len;
  uint8_t count = 0;
  uint16_t nrcv;

  len = (uint8_t)*rxlength;
  memset(rxdata, 0, *rxlength);
  do {

    status = ATCA_SUCCESS;
    //! Address the device and indicate that bytes are to be read
    nrcv = Wire.requestFrom(i2c_addr, len);
    if (nrcv == 0) {
      status = ATCA_RX_NO_RESPONSE;
    } else {
      //! Receive count byte
      rxdata[0] = Wire.read();
      //count = nrcv;
      count = (rxdata[0] > nrcv) ? nrcv : rxdata[0];
      for (i = 1; i < count; i++) {
        rxdata[i] = Wire.read();
      }
      if ((count < ATCA_RSP_SIZE_MIN) || (rxdata[0] > len)
          || (rxdata[0] > count))
      {
        status = ATCA_INVALID_SIZE;
      } else {
        status = isATCAError(rxdata);
      }
    }

    if (status == ATCA_EXECUTION_ERROR) {
#ifdef DEBUG_I2C
      Serial.println("hal_i2c_receive ATCA_EXECUTION_ERROR");
      hexdump(rxdata, count, 40);
#endif
      return ATCA_EXECUTION_ERROR;
    }
    if (status == ATCA_CHECKMAC_VERIFY_FAILED) {
#ifdef DEBUG_I2C
      Serial.println("hal_i2c_receive ATCA_CHECKMAC_VERIFY_FAILED");
      hexdump(rxdata, count, 40);
#endif
      return ATCA_CHECKMAC_VERIFY_FAILED;
    }

    if (status != ATCA_RX_NO_RESPONSE) {
      retries++;
    }
    no_resp_tries++;
    if (status != 0) {
#ifdef DEBUG_I2C
#ifdef CORE_TEENSY
      Serial.printf("hal_i4c_receive error %x %d [%02x %02x %02x %02x]\n", status, count, rxdata[0], rxdata[1], rxdata[2], rxdata[3]);
      Serial.flush();
#endif
#endif
    }
    if (no_resp_tries > 10000) {
      status = ATCA_RX_TIMEOUT;
      break;
    }
    if (retries > 3) {
      break;
    }
    if (status != ATCA_SUCCESS) {
      delayMicroseconds(250);
    }

  } while (status != ATCA_SUCCESS);

#ifdef DEBUG_I2C
  Serial.print("hal_i2c_receive end ");
  Serial.print(*rxlength);
  Serial.print(" ");
  Serial.print(count);
  Serial.println("");
  hexdump(rxdata, count, 40);
  Serial.flush();
#endif

  *rxlength = count;

  if (status == ATCA_RX_TIMEOUT)
    status = ATCA_RX_NO_RESPONSE;

  delayMicroseconds(1000);
  return status;
}

ATCA_STATUS hal_i2c_wake(ATCAIface iface)
{
  int i;
  uint8_t buf[4];
  int count = 0;
  ATCA_STATUS status;

#ifdef DEBUG_I2C
    Serial.print("hal_i2c_wake ");
#endif
  do {
    count++;
    Wire.setClock(100000);

    Wire.beginTransmission(i2c_addr);
    Wire.endTransmission();

    Wire.setClock(400000);

    delayMicroseconds(3000);

    Wire.requestFrom(i2c_addr, (uint8_t)4);
    for (i = 0; Wire.available() && (i < 4); i++) {
      buf[i] = Wire.read();
    }
    Wire.endTransmission();

    // expected[4] = { 0x04, 0x11, 0x33, 0x43 };
    // expected[4] = { 0x04, 0x11, 0x33, 0x43 };
    status = isATCAError(buf);
    if ((buf[0] == 4) && ((status == ATCA_SUCCESS) || (status == ATCA_WAKE_SUCCESS))) {
      delayMicroseconds(100);
#ifdef DEBUG_I2C
      hexdump(buf, 4, 40);
#endif
      break;
    } else {
      delayMicroseconds(1000);
      continue;
    }
  } while (1);

#ifdef DEBUG_I2C
    Serial.print(" ");
    Serial.println(count);
    Serial.flush();
#endif
  return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_idle(ATCAIface iface)
{
  Wire.beginTransmission(i2c_addr);
  // idle word address value
  Wire.write(0x02);
  Wire.endTransmission();
  delayMicroseconds(1000);
  return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_sleep(ATCAIface iface)
{
  Wire.beginTransmission(i2c_addr);
  // sleep word address value
  Wire.write(0x01);
  Wire.endTransmission();
  delayMicroseconds(1000);
  return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_release(void *hal_data )
{
//  Wire.end();
  return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_discover_buses(int i2c_buses[], int max_buses)
{
  return ATCA_UNIMPLEMENTED;
}

ATCA_STATUS hal_i2c_discover_devices(int busNum, ATCAIfaceCfg *cfg, int *found )
{
  return ATCA_UNIMPLEMENTED;
}






