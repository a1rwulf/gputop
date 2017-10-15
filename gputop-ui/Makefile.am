data_dir = $(top_srcdir)/gputop-data

bin_PROGRAMS = gputop-ui

gputop_ui_SOURCES = \
	gputop.pb-c.h \
	gputop.pb-c.c \
	\
	imgui/imconfig.h \
	imgui/imgui.cpp \
	imgui/imgui_demo.cpp \
	imgui/imgui_draw.cpp \
	imgui/imgui.h \
	imgui/imgui_internal.h \
	imgui/stb_rect_pack.h \
	imgui/stb_textedit.h \
	imgui/stb_truetype.h \
	imgui/imgui_impl_gtk3_cogl.cpp \
	imgui/imgui_impl_gtk3_cogl.h \
	\
	gputop-soup-network.h \
	gputop-soup-network.c \
	gputop-ui-main.cpp


gputop_ui_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/gputop-client-c \
	\
	-I$(top_srcdir)/mesa/include \
	-I$(top_srcdir)/mesa/include/drm-uapi \
	-I$(top_srcdir)/mesa/src \
	-I$(top_srcdir)/mesa/src/intel \
	-I$(top_srcdir)/mesa/src/util \
	\
	-I$(top_srcdir)/libuv/include \
	\
	-I$(top_srcdir)/h2o \
	-I$(top_srcdir)/h2o/include \
	-I$(top_srcdir)/h2o/hiredis \
	\
	-I$(srcdir)/imgui \
	$(GPUTOP_UI_CFLAGS)
gputop_ui_CFLAGS = \
	-std=c99
gputop_ui_LDFLAGS = \
	$(GPUTOP_UI_LIBS) \
	-ldl
gputop_ui_LDADD = \
	$(CRYPTO_DEP_LIBS) \
	$(SSL_DEP_LIBS) \
	$(top_builddir)/libuv/libuv.la \
	$(top_builddir)/h2o/libh2o.la \
	$(top_builddir)/protobuf-c/libprotobuf-c.la \
	$(top_builddir)/mesa/libmesa.la \
	$(top_builddir)/gputop-client-c/libgputop-client.la


%.pb-c.c %.pb-c.h: $(data_dir)/%.proto Makefile.am
	$(top_builddir)/protoc-c/protoc-c --c_out=$(top_builddir)/gputop-ui -I$(data_dir) $(data_dir)/$(*F).proto

BUILT_SOURCES = \
	gputop.pb-c.h \
	gputop.pb-c.c

CLEANFILES = $(BUILT_SOURCES)
