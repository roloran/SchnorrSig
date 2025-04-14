#if CONFIG_FREERTOS_UNICORE
#define ARDUINO_RUNNING_CORE 0
#else
#define ARDUINO_RUNNING_CORE 1
#endif

#include <Arduino.h>
#include <SchnorrSigCtx.h>
#include <SchnorrSigSign.h>
#include <SchnorrSigVerify.h>


void printBinary(uint8_t* data, size_t len) {
    char hex[(len*2)+1];
    int i = 0;
    for (i = 0 ; i != len; i++) {
        sprintf(&hex[2*i], "%02X", data[i]);
    }
    hex[sizeof(hex)-1] = '\0';
    printf("%s", hex);
}

void printSignature(struct SchnorrSigCtx::signature* sig) {
  printf("\nSignature:\n");
  printf("Point[%d byte]: ", sig->point_len);
  printBinary(sig->point, sig->point_len);
  printf("\nSignature[%d byte]: ", sig->sig_len);
  printBinary(sig->sig, sig->sig_len);
  printf("\n");
}

void setup() {
  delay(2000); // Time for attaching monitor
  Serial.begin(115200);
  delay(2000);

  printf("\n////////////////////////////////////////////////////////////////////////////////\n");
  printf("Schnorr signature example start\n");
  int res = 0;

  ////////////////////////////////////////////////////////////////////////////////
  // SETUP // always necessary ///////////////////////////////////////////////////
  ////////////////////////////////////////////////////////////////////////////////
  // Create the SSC context. This initializes mbedtls settings and the rng.
  // Only one instance should be used across all signing and verifying operations.

  size_t seed_len = MBEDTLS_CTR_DRBG_MAX_SEED_INPUT - MBEDTLS_CTR_DRBG_ENTROPY_LEN;
  uint8_t seed[seed_len];    
  esp_fill_random(seed, seed_len);

  SchnorrSigCtx ssc = SchnorrSigCtx();
  res = ssc.init(seed, seed_len);
  assert(res == 0); // Insert appropriate error handling here

  // Data used for signing
  char test[] = "Hello World!";

  ////////////////////////////////////////////////////////////////////////////////
  // GENERATE NEW SCHNORR KEYS ///////////////////////////////////////////////////
  ////////////////////////////////////////////////////////////////////////////////
  // Create a new private/public keypair.
  // Only necessary if no keys exist yet.
  printf("Generate new keypair\n");
  SchnorrSigCtx::privkey *keypair = ssc.gen_keypair();
  assert(keypair != NULL);

  // Export the private key
  // It can be loaded from the hexdump for persistence while signing messages afterwards
  size_t privkey_len = 0;
  char privkey[128]; // NOTICE: The private key is exported as hexadecimal string
  res = ssc.export_private_key(keypair, privkey, &privkey_len);
  assert(res == 0); // Insert appropriate error handling here
  
  printf("Private key [%d byte]: %.*s\n", (privkey_len-1) / 2, privkey_len-1, privkey); // 2 Chars == 1 Byte

  // Export the public key
  // It can be shared and loaded from the hexdump to verify messages afterwards
  size_t pubkey_len = 0;
  uint8_t pubkey[256]; // NOTICE: The public key is exported as byte array
  res = ssc.export_public_key(keypair->pub, pubkey, &pubkey_len);
  assert(res == 0); // Insert appropriate error handling here
  
  printf("Public key [%d byte]: ", pubkey_len); // 1 Byte == 2 Chars
  printBinary(pubkey, pubkey_len);
  printf("\n");

  ////////////////////////////////////////////////////////////////////////////////
  // SIGN AND VERIFY MESSAGES ////////////////////////////////////////////////////
  ////////////////////////////////////////////////////////////////////////////////
  // OPTION 1: Keys already in memory
  printf("\nSign/Verify Option 1\n");
  // To sign messages, create a SSS object and initialize it with a context SSC (only one
  // context is usually needed) and the private key.
  SchnorrSigSign sss = SchnorrSigSign();
  // The SSS object must be initialized with either of the following init() methods.
  res = sss.init(&ssc, keypair);
  assert(res == 0); // Insert appropriate error handling here

  // The signature for a message is created by creating a signature object and passing it with
  // the message to be signed to the SSC's sign method.
  struct SchnorrSigCtx::signature new_sig;
  res = sss.sign((const unsigned char*)test, strlen(test), &new_sig);
  assert(res == 0); // Insert appropriate error handling here
  printSignature(&new_sig);

  // To verify messages, create a SSV object with a context SSC (only one context is usually
  // needed) and the public key of the party signing the message.
  SchnorrSigVerify ssv = SchnorrSigVerify();
  res = ssv.init(&ssc, keypair->pub);
  assert(res == 0); // Insert appropriate error handling here

  // Checking a signature is done by storing the received signature and point values in a
  // signature object, and passing the message and the signature to the SSV object's verify
  // method. The SSV object must be initialized with the signer's public key.
  struct SchnorrSigCtx::signature test_sig;
  test_sig.point_len = new_sig.point_len;
  memcpy(test_sig.point, new_sig.point, new_sig.point_len);
  test_sig.sig_len = new_sig.sig_len;
  memcpy(test_sig.sig, new_sig.sig, new_sig.sig_len);
  res = ssv.verify((const unsigned char*)test, strlen(test), &test_sig);
  assert(res == 0); // Insert appropriate error handling here
  printf("Verify test: %d\n", res);

  test_sig.sig[8] = 0xFF;
  printf("Verify test broken sig: %d\n", ssv.verify((const unsigned char*)test, strlen(test), &test_sig));

  /////////////////////////////////////////////////////////////////////////////
  // OPTION 2: Loading the keys from hex-strings
  // To sign messages, create a SSS object and initialize it with a context SSC (only one
  // context is usually needed) and the private key.
  printf("\nSign/Verify Option 2\n");
  SchnorrSigSign sss2 = SchnorrSigSign();
  #ifdef USE_SECP192K1
  res = sss2.init(&ssc, "CA5101EAB68AAE3001D2E4307032A4D9566BE47143207DCB");
  #else
  res = sss2.init(&ssc, "44D6873DB1C77A225590BF640FE11287990EE879F553EE485E02F8793FF7AB98");
  #endif
  assert(res == 0); // Insert appropriate error handling here

  // The signature for a message is created by creating a signature object and passing it with
  // the message to be signed to the SSC's sign method.
  struct SchnorrSigCtx::signature new_sig2;
  res = sss2.sign((const unsigned char*)test, strlen(test), &new_sig2);
  assert(res == 0); // Insert appropriate error handling here
  printSignature(&new_sig2);

  // To verify messages, create a SSV object with a context SSC (only one context is usually
  // needed) and the public key of the party signing the message.
  SchnorrSigVerify ssv2 = SchnorrSigVerify();
  #ifdef USE_SECP192K1
  res = ssv2.init(&ssc, "03B452D8DA11A15BC376787F54EEE103E0026E4F6C1766419C");
  #else
  res = ssv2.init(&ssc, "034E78736B18DAC2EFAB7481768296DB6FF0D1816C6DB46A7C3E8E4B3C1A2C17E6");
  #endif
  assert(res == 0); // Insert appropriate error handling here

  // Checking a signature is done by storing the received signature and point values in a
  // signature object, and passing the message and the signature to the SSV object's verify
  // method. The SSV object must be initialized with the signer's public key.
  struct SchnorrSigCtx::signature test_sig2;
  test_sig2.point_len = new_sig2.point_len;
  memcpy(test_sig2.point, new_sig2.point, new_sig2.point_len);
  test_sig2.sig_len = new_sig2.sig_len;
  memcpy(test_sig2.sig, new_sig2.sig, new_sig2.sig_len);
  res = ssv2.verify((const unsigned char*)test, strlen(test), &test_sig2);
  assert(res == 0); // Insert appropriate error handling here
  printf("Verify test: %d\n", res);

  test_sig2.sig[8] = 0xFF;
  printf("Verify test broken sig: %d\n", ssv2.verify((const unsigned char*)test, strlen(test), &test_sig2));

  ////////////////////////////////////////////////////////////////////////////////
  // Using the signatures / keys generated by the Python script
  #ifndef USE_SECP192K1
  printf("\nVerify signature from Python\n");
  SchnorrSigVerify ssv_py = SchnorrSigVerify();
  res = ssv_py.init(&ssc, "03185c7f6639035cc3571bb7ecec06a0b50a561812a354494475f2ff2a3f26a7f7");
  assert(res == 0); // Insert appropriate error handling here

  struct SchnorrSigCtx::signature test_sig_py;
  res = ssv_py.load("0267abcb3b5ca624b08bf1a664259b5ac5cadce53a21a826ac069f4487b86b09cc:f68da1695c5655fffdc184d751f898b6c6c02995ece6058e58749fb61455f9ee", &test_sig_py);
  assert(res == 0); // Insert appropriate error handling here
  printSignature(&test_sig_py);
  res = ssv_py.verify((const unsigned char*)test, strlen(test), &test_sig_py);

  printf("Verify test: %d\n", res);
  #endif

  ////////////////////////////////////////////////////////////////////////////////
  // CLEANUP /////////////////////////////////////////////////////////////////////
  ////////////////////////////////////////////////////////////////////////////////
  // Remove the keypair and free it's memory
  ssc.free_privkey(keypair);

  printf("\nSchnorr signature example end\n");
}

void loop() {

}
