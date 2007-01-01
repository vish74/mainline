#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#ifndef XML_SIMPLE_H
#define XML_SIMPLE_H

#define XML_INDENT_CHAR ' '
#define XML_INDENT_COUNT 2
#define xml_indent(fd,level) {\
	char i[XML_INDENT_COUNT*level+1];\
	memset(i,(int)XML_INDENT_CHAR,sizeof(i)-1);\
	i[sizeof(i)-1] = 0;\
	fprintf(fd,"%s",i);\
}

#define xml_open(fd,level,attr) {\
	xml_indent(fd,level);\
	fprintf(fd,"<%s>\n",attr);\
}

#define xml_close(fd,level,attr) {\
	xml_indent(fd,level);\
	fprintf(fd,"</%s>\n",attr);\
}

#define xml_print(fd,level,attr,format,...) {\
	xml_indent(fd,level);\
	fprintf(fd,"<%s",attr);\
        if (format) {\
                const char* f = format;\
                fprintf(fd,">");\
                fprintf(fd,f, __VA_ARGS__ );\
	        fprintf(fd,"</%s>\n",attr);\
        } else {\
		fprintf(fd," />");\
        }\
}

#endif /* XML_SIMPLE_H */