
set ( CMAKE_MODULE_PATH
  ${CMAKE_CURRENT_SOURCE_DIR}
)

find_package ( XmlTo )

xmlto (
  obexpushd.xml
  MODES man html
  ALL
)
