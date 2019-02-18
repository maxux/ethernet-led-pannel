#include "w5100.h"

byte macaddr[] = {
    0xA2, 0x43, 0x42, 0x42, 0x42, 0x01
};

Wiznet5100 w5100;
uint8_t buffer[512];

#define PIN_RED     3
#define PIN_GREEN   5
#define PIN_BLUE    6

int pin[3] = {PIN_RED, PIN_GREEN, PIN_BLUE};
int rgb[3] = {10, 0, 0};
int index = 0;

void setup() {
    Serial.begin(115200);
    
    Serial.println("[+] initializing ethernet");
    w5100.begin(macaddr);
    
    Serial.println("[+] initializing light");
    pinMode(PIN_RED, OUTPUT);
    pinMode(PIN_GREEN, OUTPUT);
    pinMode(PIN_BLUE, OUTPUT);
    
    pinMode(LED_BUILTIN, OUTPUT);
}

void loop() {
    int incoming;

    // Serial.println("[+] waiting frame");
    uint16_t len = w5100.readFrame(buffer, sizeof(buffer));

    if(len > 0) {
        if(buffer[12] != 0x88 || buffer[13] != 0xB6) {
            // Serial.println("[+] skipping frame");
            return;
        }

        rgb[0] = buffer[14];
        rgb[1] = buffer[15];
        rgb[2] = buffer[16];
    }
    
    digitalWrite(LED_BUILTIN, HIGH);
    analogWrite(pin[0], rgb[0]);
    analogWrite(pin[1], rgb[1]);
    analogWrite(pin[2], rgb[2]);
    digitalWrite(LED_BUILTIN, LOW);

    delay(10);
}
