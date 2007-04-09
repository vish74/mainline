find_program ( XMLTO_COMMAND
  NAMES xmlto
  DOC   "path to the xmlto docbook xslt frontend"  
)
set ( XMLTO_COMMAND_ARGS
  -v -v
  CACHE STRING "additional argument to xmlto"
)
if ( NOT XMLTO_MODES )
  set ( XMLTO_MODES
    man html
    CACHE STRING "use modes for xmlto (supported: man html txt dvi ps pdf)"
    FORCE
  )
endif ( NOT XMLTO_MODES )
mark_as_advanced ( XMLTO_COMMAND XMLTO_ARGS XMLTO_MODES )

macro ( XMLTO outfiles mode)
  #special settings
  set ( XMLTO_FILEEXT_man 1 )
  set ( XMLTO_MODE_html xhtml-nochunks )

  if ( NOT XMLTO_MODE_${mode} )
    set ( XMLTO_MODE_${mode} ${mode} )
  endif ( NOT XMLTO_MODE_${mode} )
  if ( NOT XMLTO_FILEEXT_${mode} )
    set ( XMLTO_FILEEXT_${mode} ${mode} )
  endif ( NOT XMLTO_FILEEXT_${mode} )

  foreach ( dbFile ${ARGN} )
    #TODO: set XMLTO_FILEEXT_man to value from <manvolnum>
    get_filename_component ( dbFilePath ${CMAKE_CURRENT_BINARY_DIR}/${dbFile} PATH )
    get_filename_component ( dbFileWE ${dbFile} NAME_WE )
    get_filename_component ( dbFileAbsWE ${dbFilePath}/${dbFileWE} ABSOLUTE )

    add_custom_command (
      OUTPUT            ${dbFileAbsWE}.${XMLTO_FILEEXT_${mode}}
      COMMAND           ${XMLTO_COMMAND} ${XMLTO_COMMAND_ARGS} -o ${CMAKE_CURRENT_BINARY_DIR}
                        ${XMLTO_MODE_${mode}} ${CMAKE_CURRENT_SOURCE_DIR}/${dbFile}
      MAIN_DEPENDENCY   ${CMAKE_CURRENT_SOURCE_DIR}/${dbFile}
      VERBATIM
    )

    set ( ${outfiles}
      ${${outfiles}}
      ${dbFileAbsWE}.${XMLTO_FILEEXT_${mode}}
    )
  endforeach ( dbFile )
endmacro ( XMLTO outfiles )

set ( DOCBOOK_FILES
  obexpushd.xml
)

foreach ( mode ${XMLTO_MODES} )
  xmlto ( XMLTO_FILES_${mode} ${mode} ${DOCBOOK_FILES} )
  add_custom_target ( ${mode} ALL
    DEPENDS ${XMLTO_FILES_${mode}}
    VERBATIM
  )
endforeach ( mode )
