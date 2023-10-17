ESCape32 Wi-Fi Link
===================

ESP32-based embedded configurator for [ESCape32](https://github.com/neoxic/ESCape32) electronic speed controllers.


Installation
------------

Download the latest pre-built combined image [here](https://github.com/neoxic/ESCape32-WiFi-Link/releases).

Flash your board using the [ESP Flash Tool](https://www.espressif.com/en/support/download/other-tools) or any DFU utility, e.g. dfu-util.

Visit the [ESCape32 Wiki / Wi-Fi Link](https://github.com/neoxic/ESCape32/wiki/WiFiLink) page for more information.


Pinouts
-------

|    MCU   | RX | TX | LED |
|----------|---:|---:|----:|
| ESP32-C3 |  4 |  2 |  *8 |
| ESP32-S2 | 16 | 33 |  15 |

(*) active low

_Note:_ The above GPIO pin numbers can be changed using the `idf.py menuconfig` command.


Building from source
--------------------

Install the ESP-IDF environment as described [here](https://idf.espressif.com).

To build for the ESP32-S2, run:

```
idf.py set-target esp32s2
idf.py build
```

To install on the device, run:

```
idf.py flash
```

To make a combined image, run:

```
cd build
esptool.py --chip esp32s2 merge_bin -o ESCape32-WiFi-Link-ESP32-S2.bin @flash_args
```
