pkglib_LTLIBRARIES = detect_time.la

detect_time_la_CFLAGS = -I../../../rust/gen -I../../../rust/dist
detect_time_la_LDFLAGS = -module -avoid-version -shared
detect_time_la_SOURCES = time.c

install-exec-hook:
	cd $(DESTDIR)$(pkglibdir) && $(RM) $(pkglib_LTLIBRARIES)
