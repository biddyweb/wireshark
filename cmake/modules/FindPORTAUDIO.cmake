#
# $Id$
#
# - Find portaudio
# Find the native PORTAUDIO includes and library
#
#  PORTAUDIO_INCLUDE_DIRS - where to find portaudio.h, etc.
#  PORTAUDIO_LIBRARIES    - List of libraries when using portaudio.
#  PORTAUDIO_FOUND        - True if portaudio found.


IF (PORTAUDIO_INCLUDE_DIRS)
  # Already in cache, be silent
  SET(PORTAUDIO_FIND_QUIETLY TRUE)
ENDIF (PORTAUDIO_INCLUDE_DIRS)

FIND_PATH(PORTAUDIO_INCLUDE_DIR portaudio.h)

SET(PORTAUDIO_NAMES portaudio)
FIND_LIBRARY(PORTAUDIO_LIBRARY NAMES ${PORTAUDIO_NAMES} )

# handle the QUIETLY and REQUIRED arguments and set PORTAUDIO_FOUND to TRUE if 
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(PORTAUDIO DEFAULT_MSG PORTAUDIO_LIBRARY PORTAUDIO_INCLUDE_DIR)

IF(PORTAUDIO_FOUND)
  SET( PORTAUDIO_LIBRARIES ${PORTAUDIO_LIBRARY} )
  SET( PORTAUDIO_INCLUDE_DIRS ${PORTAUDIO_INCLUDE_DIR} )
ELSE(PORTAUDIO_FOUND)
  SET( PORTAUDIO_LIBRARIES )
  SET( PORTAUDIO_INCLUDE_DIRS )
ENDIF(PORTAUDIO_FOUND)

MARK_AS_ADVANCED( PORTAUDIO_LIBRARIES PORTAUDIO_INCLUDE_DIRS )
