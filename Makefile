XDP_TARGETS  := nca/xdp_prog_kern 
USER_TARGETS := nca/xdp_loader

LIBBPF_DIR = ./libbpf/src/
COMMON_DIR = .

include $(COMMON_DIR)/common.mk
#LIBS += -lpthread
#CFLAGS += -O2 -mtune=native -march=native -mfpmath=both