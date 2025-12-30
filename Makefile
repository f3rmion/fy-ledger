# ****************************************************************************
#   Ledger App FROST
#   (c) 2024 Frostguard
# ****************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.defines

########################################
#        Application Configuration     #
########################################

APPVERSION_M = 1
APPVERSION_N = 0
APPVERSION_P = 0
APPVERSION   = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

# Curve selection (BJJ or ED25519)
CURVE ?= BJJ

ifeq ($(CURVE),BJJ)
    DEFINES += CURVE_BJJ
    APPNAME = "FY-BJJ"
    APP_SOURCE_PATH += src curves/bjj
else ifeq ($(CURVE),ED25519)
    DEFINES += CURVE_ED25519
    APPNAME = "FY-ED25519"
    APP_SOURCE_PATH += src curves/ed25519
else
    $(error Invalid CURVE value: $(CURVE). Use BJJ or ED25519)
endif

# Application allowed derivation curves
CURVE_APP_LOAD_PARAMS = ed25519

# Application allowed derivation paths (not used for FROST, but required)
PATH_APP_LOAD_PARAMS = ""

# Variant (for multi-app builds)
VARIANT_PARAM = COIN
VARIANT_VALUES = frost

# Enable Bluetooth (for Nano X)
ifeq ($(TARGET_NAME),TARGET_NANOX)
    ENABLE_BLUETOOTH = 1
endif

########################################
#          Build Configuration         #
########################################

# Enable debug printf (disable for production!)
DEBUG = 0

ifneq ($(DEBUG),0)
    DEFINES += HAVE_PRINTF
    ifeq ($(TARGET_NAME),TARGET_NANOS)
        DEFINES += PRINTF=screen_printf
    else
        DEFINES += PRINTF=mcu_usb_printf
    endif
else
    DEFINES += PRINTF\(...\)=
endif

########################################
#          Compiler Definitions        #
########################################

DEFINES += APPNAME=\"$(APPNAME)\"
DEFINES += APPVERSION=\"$(APPVERSION)\"
DEFINES += MAJOR_VERSION=$(APPVERSION_M)
DEFINES += MINOR_VERSION=$(APPVERSION_N)
DEFINES += PATCH_VERSION=$(APPVERSION_P)

# Bluetooth
ifeq ($(ENABLE_BLUETOOTH),1)
    DEFINES += HAVE_BLE BLE_COMMAND_TIMEOUT_MS=2000 HAVE_BLE_APDU
endif

########################################
#              Includes                #
########################################

include $(BOLOS_SDK)/Makefile.standard_app
