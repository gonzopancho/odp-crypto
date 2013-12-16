## Copyright (c) 2013, Linaro Limited
## All rights reserved.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions are met:
##
##    * Redistributions of source code must retain the above copyright notice, this
##      list of conditions and the following disclaimer.
##
##    * Redistributions in binary form must reproduce the above copyright notice, this
##      list of conditions and the following disclaimer in the documentation and/or
##      other materials provided with the distribution.
##
##    * Neither the name of Linaro Limited nor the names of its contributors may be
##      used to endorse or promote products derived from this software without specific
##      prior written permission.
##
## THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
## ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
## WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
## DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
## FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
## DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
## SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
## CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
## OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
## OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


ODP_ROOT = ../..
ARCH     = linux-generic
ODP_LIB  = $(ODP_ROOT)/arch/$(ARCH)
OBJ_DIR  = ./obj
LIB      = $(ODP_LIB)/lib/odp.a

INCLUDE  = -I$(ODP_ROOT)/include
CC       = @gcc

#
# API testing stuffs
#
ODP_ATOMIC    = odp_atomic
ODP_SHM       = odp_shm


E_FLAGS  = -W -Wall -Werror -Wstrict-prototypes -Wmissing-prototypes
E_FLAGS += -Wmissing-declarations -Wold-style-definition -Wpointer-arith
E_FLAGS += -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral
E_FLAGS += -Wformat-security -Wundef -Wwrite-strings

CFLAGS  += -pthread
CFLAGS  += -I.
CFLAGS  += -I$(ODP_LIB)
CFLAGS  += $(EXTRA_CFLAGS)
CFLAGS  += $(E_FLAGS)
CFLAGS  += $(INCLUDE)
#CFLAGS  += -DODP_TEST_ATOMIC

LDFLAGS += -pthread
LDFLAGS += -lrt
LDFLAGS += $(EXTRA_CFLAGS)

ATOMIC_OBJS  =
ATOMIC_OBJS += $(OBJ_DIR)/odp_common.o
ATOMIC_OBJS += $(OBJ_DIR)/odp_atomic_test.o

SHM_OBJS  =
SHM_OBJS += $(OBJ_DIR)/odp_common.o
SHM_OBJS += $(OBJ_DIR)/odp_shm_test.o

DEPS     = $(ATOMIC_OBJS:.o=.d) $(SHM_OBJS:.o=.d)


.PHONY: all
all: $(OBJ_DIR) $(ODP_ATOMIC) $(ODP_SHM)
atomic: $(OBJ_DIR) $(ODP_ATOMIC)
shm: $(OBJ_DIR) $(ODP_SHM)

-include $(DEPS)

$(OBJ_DIR):
	mkdir $(OBJ_DIR)

$(LIB):
	@echo Building $@
	$(MAKE) -C $(ODP_LIB) libs



#
# Compile rules
#
$(OBJ_DIR)/%.o: %.c
	@echo Compiling $<
	$(CC) -c -MD $(CFLAGS) -o $@ $<

#
# Link rule
#
$(ODP_ATOMIC): $(LIB) $(ATOMIC_OBJS)
	$(CC) $(LDFLAGS) $(ATOMIC_OBJS) $(LIB) -o $@

$(ODP_SHM): $(LIB) $(SHM_OBJS)
	$(CC) $(LDFLAGS) $(SHM_OBJS) $(LIB) -o $@


.PHONY: libs
libs:
	$(MAKE) -C $(ODP_LIB) libs


.PHONY: docs
docs:
	$(MAKE) -C $(ODP_LIB) docs


.PHONY: clean
clean:
	rm -rf $(OBJ_DIR)
	rm -f $(ODP_ATOMIC)
	rm -f $(ODP_SHM)
	$(MAKE) -C $(ODP_LIB) clean

.PHONY: install
install:
	install -d $(DESTDIR)$(prefix)/lib
	install -m 0644 ${LIB} $(DESTDIR)$(prefix)/lib/
	install -d $(DESTDIR)$(prefix)/share/odp
	install -m 0755 $(ODP_ATOMIC) $(DESTDIR)$(prefix)/share/odp/
	install -m 0755 $(ODP_SHM) $(DESTDIR)$(prefix)/share/odp/