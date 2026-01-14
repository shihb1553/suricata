pkglib_LTLIBRARIES = zmq.la

zmq_la_LDFLAGS = -module -avoid-version -shared
zmq_la_LIBADD = -lczmq
zmq_la_SOURCES = zmq.c

install-exec-hook:
	cd $(DESTDIR)$(pkglibdir) && $(RM) $(pkglib_LTLIBRARIES)
