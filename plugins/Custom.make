#
# $Id$
#

_CUSTOM_SUBDIRS_ = \
  tos \
  rf212 \
  dis \
  ctp

_CUSTOM_EXTRA_DIST_ = \
	Custom.m4 \
	Custom.make

_CUSTOM_plugin_ldadd_ = \
  -dlopen plugins/tosam/rf212.la \
  -dlopen plugins/tosam/tos.la \
  -dlopen plugins/tosdis/dis.la \
  -dlopen plugins/tosctp/ctp.la
