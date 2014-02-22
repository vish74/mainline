#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

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

#define xml_el_open(fd,level,el,close,args,...) {\
	xml_indent(fd, level);\
	fprintf(fd, "<%s", el);\
        if (args) {\
		const char* a = args;\
		fprintf(fd, a, __VA_ARGS__);\
	}\
        if (close) fprintf(fd, " />\n");\
        else fprintf(fd, ">");\
}

#define xml_open(fd,level,attr)\
        xml_el_open(fd,level,attr,0,NULL,0); \
	fprintf(fd, "\n");

#define xml_close(fd,level,attr) {\
	xml_indent(fd,level);\
	fprintf(fd,"</%s>\n",attr);\
}

/* Handle XML escape sequences */
static inline char * xml_esc_string(const char *str)
{
	char *esc_str = calloc(1, (6 * strlen(str)) + 1);
	int i = 0;
	int k = 0;
	for (; str[i] != 0; ++i)
	{
		switch (str[i])
		{
		case '&':
			strncpy(esc_str + k, "&amp;", 5);
			k += 5;
			break;

		case '"':
			strncpy(esc_str + k, "&quot;", 6);
			k += 6;
			break;

		case '\'':
			strncpy(esc_str + k, "&apos;", 6);
			k += 6;
			break;

		case '<':
			strncpy(esc_str + k, "&lt;", 4);
			k += 4;
			break;

		case '>':
			strncpy(esc_str + k, "&gt;", 4);
			k += 4;
			break;

		default:
			esc_str[k] = str[i];
			++k;
			break;
		}
	}
	return esc_str;
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
		fprintf(fd," />\n");\
        }\
}
#endif /* XML_SIMPLE_H */
