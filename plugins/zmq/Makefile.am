pkglib_LTLIBRARIES = zmq.la

zmq_la_CFLAGS = -I../../rust/gen -I../../rust/dist
zmq_la_LDFLAGS = -module -avoid-version -shared
zmq_la_LIBADD = -lczmq
zmq_la_SOURCES = zmq.c

install-exec-hook:
	cd $(DESTDIR)$(pkglibdir) && $(RM) $(pkglib_LTLIBRARIES)
	install -d "$(DESTDIR)$(e_sysconfdir)"
	install -m 600 "zmq.yaml" "$(DESTDIR)$(e_sysconfdir)"
