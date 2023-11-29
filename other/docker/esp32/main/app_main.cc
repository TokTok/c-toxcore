#include <esp_netif.h>

#include "tox_main.h"

// Does all the esp32-specific init before running generic tox code.
extern "C" void app_main(void)
{
    esp_netif_init();

    tox_main();
}
