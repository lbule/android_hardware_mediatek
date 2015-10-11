LOCAL_PATH    := $(call my-dir)

ifneq (,$(filter MT6735 MT6795 MT6752, $(MTK_PLATFORM)))

# TRUSTONIC Tee Keymaster
ifeq ($(TRUSTONIC_TEE_SUPPORT), yes)

include $(CLEAR_VARS)

LOCAL_MODULE := keystore.$(TARGET_BOARD_PLATFORM)
LOCAL_MODULE_TAGS := debug eng optional
LOCAL_MODULE_RELATIVE_PATH := hw

# Add new source files here
LOCAL_SRC_FILES +=\
    keymaster_mt_tbase.cpp

LOCAL_C_INCLUDES +=\
    $(LOCAL_PATH)/inc \
    external/openssl/include \
    system/core/include \

LOCAL_SHARED_LIBRARIES := libMcClient liblog libMcTeeKeymaster libcrypto

include $(BUILD_SHARED_LIBRARY)

endif

endif
