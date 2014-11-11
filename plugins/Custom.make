#
# $Id$
#

_CUSTOM_EXTRA_DIST_ = \
	Custom.m4 \
	Custom.make

_CUSTOM_plugin_ldadd_ = \
  -dlopen plugins/tosam/rf212.la \
  -dlopen plugins/tosam/tosam.la \
  -dlopen plugins/tosdis/tosdis.la \
  -dlopen plugins/tosctp/tosctp.la 
