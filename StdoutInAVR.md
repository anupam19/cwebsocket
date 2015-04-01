# Introduction #

Very often in MCU there is no standart output. But there is a way to fix this.


# Details #

We will assign stdout and stderr with serial port, so all data that came to stdout will be redirected to serial port.
```
stdout = stderr = fdevopen(serialWrite, NULL);
```
where serialWrite is function
```
int serialWrite(char c, FILE *f) {
    Serial.write(c);
    return 0;
}
```

# Example #

Printf and Assert
```
// define __ASSERT_USE_STDERR for error messages 
#define __ASSERT_USE_STDERR
#include <assert.h>

void setup() {
    Serial.begin(9600); // Open serial port
}

void loop() {
    printf("this is test output\n");
    void *p = malloc(2000);
    assert(p); // checking, if malloc was success
    memset(p, 0, sizeof(p)); // do something
}
```