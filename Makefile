include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Analyzer
$(TWEAK_NAME)_FILES = Tweak.xm Broker.m
$(TWEAK_NAME)_PRIVATE_FRAMEWORKS = AppSupport
$(TWEAK_NAME)_FRAMEWORKS = Foundation UIKit CoreGraphics QuartzCore CoreMedia CoreVideo

$(TWEAK_NAME)_CFLAGS = -I./header

$(TWEAK_NAME)_LDFLAGS = -Llib -lAAClientLib

include $(THEOS_MAKE_PATH)/tweak.mk
