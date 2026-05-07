# DWM3001C Starter Firmware – nRF52840 Port

This directory contains all files needed to build the
[DWM3001C starter firmware](https://github.com/Uberi/DWM3001C-starter-firmware)
for an **nRF52840**-based board inside **SEGGER Embedded Studio (SES) v7+**.

---

## Files in this port

| File | Purpose |
|------|---------|
| `dw3000_api_nrf52840.emProject` | SES solution/project file (drop-in replacement for the original `dw3000_api.emProject`) |
| `flash_placement_nrf52840.xml` | Linker section-placement descriptor (1 MB Flash, 256 KB RAM) |
| `Setup/SEGGER_Flash_nrf52840.icf` | IAR/SEGGER linker script for nRF52840 |
| `Src/platform/custom_board_nrf52840.h` | GPIO / SPI pin definitions for the DW3000 ↔ nRF52840 wiring |
| `Src/platform/sdk_config_nrf52840.h` | nRF5 SDK `sdk_config` overrides (SPIM3, GPIOTE, logging, …) |

---

## Key differences from the nRF52833 (DWM3001C) project

| Setting | nRF52833 (original) | nRF52840 (this port) |
|---------|--------------------|--------------------|
| `arm_target_device_name` | `nRF52833_xxAA` | `nRF52840_xxAA` |
| Preprocessor define | `NRF52833_XXAA` | `NRF52840_XXAA` |
| System init | `system_nrf52833.c` | `system_nrf52840.c` |
| Startup files | `ses_startup_nrf52833.s` | `ses_startup_nrf52840.s` |
| SVD file | `nrf52833.svd` | `nrf52840.svd` |
| Flash size | 512 KB (0x80000) | 1 MB (0x100000) |
| RAM size | 128 KB (0x20000) | **256 KB (0x40000)** |
| Linker script | `Setup/SEGGER_Flash.icf` | `Setup/SEGGER_Flash_nrf52840.icf` |
| Flash placement XML | `flash_placement.xml` | `flash_placement_nrf52840.xml` |

The SPI peripheral (SPIM3, 32 MHz capable) and the nrfx/legacy driver layer are
identical between the two chips, so **no changes to `deca_spi.c`, `port.c`, or any
example source files are required.**

---

## Prerequisites

1. **SEGGER Embedded Studio** v7.x (free for Nordic targets).
2. **nRF5 SDK 17.1.0** (`nRF5_SDK_17.1.0_ddde560`) extracted to
   `/usr/local/nRF5_SDK_17.1.0_ddde560` **or** update the `NordicSDKDir` macro
   inside `dw3000_api_nrf52840.emProject` to match your installation path.
3. A **J-Link** (on-board on nRF52840-DK) for flashing and RTT logging.

---

## Setup steps

### 1 – Copy port files into the repository

Copy all files from this port directory into the root of the cloned
`DWM3001C-starter-firmware` repository, preserving the directory structure:

```
DWM3001C-starter-firmware/
├── dw3000_api_nrf52840.emProject      ← new
├── flash_placement_nrf52840.xml       ← new
├── Setup/
│   ├── SEGGER_Flash.icf               (original, untouched)
│   └── SEGGER_Flash_nrf52840.icf      ← new
└── Src/
    └── platform/
        ├── custom_board_nrf52840.h    ← new
        ├── sdk_config_nrf52840.h      ← new
        └── ... (original files unchanged)
```

### 2 – Tell the SDK about the custom board

The project uses `BOARD_CUSTOM`.  The nRF5 SDK expects a file called `custom_board.h`
on the include path.  Create a thin wrapper in `Src/platform/custom_board.h`:

```c
/* Src/platform/custom_board.h */
#pragma once
#include "custom_board_nrf52840.h"
```

> If you already have a `custom_board.h` for a different board, rename it and
> adjust the include accordingly.

### 3 – Set the NordicSDKDir macro

In SES: **Tools → Options → Building → Global macros**, set:

```
NordicSDKDir=<absolute path to nRF5_SDK_17.1.0_ddde560>
```

Or edit the `macros` attribute directly in `dw3000_api_nrf52840.emProject`.

### 4 – Open and build

1. Open `dw3000_api_nrf52840.emProject` in SES.
2. Select the **Debug** configuration.
3. Choose the example to run by editing `Src/main.c` (same as the original project).
4. Build (**F7**) and flash (**F5**).

---

## Pin wiring (nRF52840-DK default)

| DW3000 signal | nRF52840 GPIO | nRF52840-DK header |
|---------------|---------------|--------------------|
| SPI CLK       | P0.03         | D13                |
| SPI MOSI      | P0.04         | D11                |
| SPI MISO      | P0.28         | D12                |
| SPI CS        | P0.29         | D10                |
| IRQ           | P0.30         | D9                 |
| RST           | P0.31         | D8                 |
| WAKEUP        | P0.02         | D7                 |

Adjust `custom_board_nrf52840.h` if your hardware uses different pins.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Build error: `nrf52840.h not found` | Wrong SDK path | Update `NordicSDKDir` |
| Build error: `ses_startup_nrf52840.s not found` | SDK < 15.3 | Use SDK 17.1.0 |
| Device not recognised by J-Link | Wrong target in project | Confirm `arm_target_device_name="nRF52840_xxAA"` |
| SPI transfer returns garbage | Wrong pin numbers | Re-check `custom_board_nrf52840.h` |
| RTT output missing | `NRF_LOG_BACKEND_RTT_ENABLED` not set | Ensure `sdk_config_nrf52840.h` is included |

---

## License

This port is provided under the same terms as the upstream project (Apache 2.0).
The nRF5 SDK files referenced by the project file are subject to Nordic's
[5-clause Nordic license](https://developer.nordicsemi.com/nRF5_SDK/nRF5_SDK_v17.x.x/sdk_license.zip).
