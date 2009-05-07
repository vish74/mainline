
find_package ( Xslt )
if ( NOT XSLT_PROCESSOR )
  if ( XSLTPROC )
    set ( XSLT_PROCESSOR "xsltproc" )
  elseif ( SAXON_COMMAND )
    set ( XSLT_PROCESSOR "saxon" )
  elseif ( XALAN2_COMMAND )
    set ( XSLT_PROCESSOR "xalan2" )
  endif ( XSLTPROC )
endif ( NOT XSLT_PROCESSOR )
set ( XSLT_PROCESSOR "${XSLT_PROCESSOR}"
      CACHE STRING "XSLT processor select (xsltproc, xalan2 or saxon)" )
include ( ${Xslt_USE_FILE} )

if ( XSLT_PROCESSOR )
  option (BUILD_HELP_MAN "Build manpage application help files" ON)
  option (BUILD_HELP_HTML "Build HTML application help files" OFF)

  set ( DOCBOOK_XSL_PREFIX "http://docbook.sourceforge.net/release/xsl/current"
        CACHE STRING "prefix to locate the docbook-XSL release files" )
  mark_as_advanced ( DOCBOOK_XSL_PREFIX )
  set ( OBEXPUSHD_XML_FILE "${CMAKE_CURRENT_SOURCE_DIR}/obexpushd.xml" )

  file ( READ "${OBEXPUSHD_XML_FILE}" XML_FILE_CONTENTS )
  string ( REGEX MATCHALL "<refentrytitle>[^<]*" XML_REFENTRYTITLE "${XML_FILE_CONTENTS}" )
  foreach ( file ${XML_REFENTRYTITLE} )
    string ( REGEX REPLACE "^<refentrytitle>" "" file "${file}" )
    string ( REGEX REPLACE "[[:space:]]" "" file "${file}" )
    list ( APPEND XSLT_FILES ${file} )
  endforeach ( file )
  set ( XML_FILE_CONTENTS )
  set ( XML_REFENTRYTITLE )

  if ( BUILD_HELP_MAN )
    foreach ( file  ${XSLT_FILES} )
      # this may not always match the right refentrytitle
      #file ( READ "${dbFile}" _DB_FILE_CONTENTS )
      #string ( REGEX MATCH "<manvolnum>[^<]*" XMLTO_FILEEXT_${mode} "${_DB_FILE_CONTENTS}" )
      #string ( REGEX REPLACE "^<manvolnum>" "" XMLTO_FILEEXT_${mode} "${XMLTO_FILEEXT_${mode}}" )
      #string ( REGEX REPLACE "[[:space:]]" "" XMLTO_FILEEXT_${mode} "${XMLTO_FILEEXT_${mode}}" )
      list ( APPEND XSLT_FILES_MAN ${file}.1 )
    endforeach ( file )
    xsl_transform (
      "${DOCBOOK_XSL_PREFIX}/manpages/docbook.xsl"
      "${OBEXPUSHD_XML_FILE}"
      ${XSLT_FILES_MAN}
    )
    foreach ( file ${XSLT_FILES_MAN} )
      list ( APPEND OBEXPUSHD_HELP_FILES ${file} )
      get_filename_component ( fileExt ${file} EXT )
      string ( REGEX REPLACE "^[.]" "" fileExt ${fileExt} )
      install (
	FILES ${CMAKE_CURRENT_BINARY_DIR}/${file}
	DESTINATION ${MANPAGE_INSTALL_DIR}/man${fileExt}
	PERMISSIONS OWNER_READ OWNER_WRITE
                    GROUP_READ
                    WORLD_READ
        COMPONENT documentation
        OPTIONAL
      )
    endforeach ( file )
  endif ( BUILD_HELP_MAN )

  if ( BUILD_HELP_HTML )
    foreach ( file  ${XSLT_FILES} )
      list ( APPEND XSLT_FILES_HTML ${file}.html )
    endforeach ( file )
    list ( APPEND XSLT_FILES_HTML
      index.html
    )
    xsl_transform (
      "${DOCBOOK_XSL_PREFIX}/xhtml/chunk.xsl"
      "${OBEXPUSHD_XML_FILE}"
      ${XSLT_FILES_HTML}
    )
    foreach ( file ${XSLT_FILES_HTML} )
      list ( APPEND OBEXPUSHD_HELP_FILES ${file} )
      INSTALL (
	FILES ${CMAKE_CURRENT_BINARY_DIR}/${file}
        DESTINATION ${DOCUMENTATION_INSTALL_DIR}
        PERMISSIONS OWNER_READ OWNER_WRITE
                    GROUP_READ
                    WORLD_READ
        COMPONENT documentation
        OPTIONAL
      )
    endforeach ( file )
  endif ( BUILD_HELP_HTML )

  add_custom_target ( doc DEPENDS ${OBEXPUSHD_HELP_FILES} )
endif ( XSLT_PROCESSOR )
