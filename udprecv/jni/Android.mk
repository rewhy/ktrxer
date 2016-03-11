#nativeDemos.so #
LOCAL_PATH := $(call my-dir) 
include $(CLEAR_VARS)

LOCAL_CFLAGS += -pie -fPIE
LOCAL_LDFLAGS += -pie -fPIE

#LOCAL_CERTIFICATE := platform

#LOCAL_CFLAGS := -ltaint
#LOCAL_LDLIBS := -llog
#LOCAL_SHARED_LIBRARIES := libtaint

LOCAL_SRC_FILES := rawsocket.c

LOCAL_MODULE := rawsocket

LOCAL_ARM_MODE := arm

#include $(BUILD_SHARED_LIBRARY)
include $(BUILD_EXECUTABLE)
