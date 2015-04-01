# Options #

## Compiling ##
  * **-ffreestanding**
> Now you can use void main() {} without return value. This will save pair bytes.
  * **-fno-inline-small-functions**
> Complier will not inline small functions. If small function used in many places, this option will save bytes.
  * **-fdata-sections**
> Create separate sections for data block (used with linker --gc-sections option)
  * **-ffunction-sections**
> Create separate sections for every function (used with linker --gc-sections option)

## Linker ##
  * **-Wl,--gc-sections**
> Don't include unused sections in result binary file.
  * **-Wl,--relax**
> Replace CALL (4 bytes) statements with RCALL (2 bytes) where possible.

[More information](http://www.tty1.net/blog/2008-04-29-avr-gcc-optimisations_en.html)