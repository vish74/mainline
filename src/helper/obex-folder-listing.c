/* Copyright (C) 2006 Hendrik Sattler <post@hendrik-sattler.de>
 *       
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.		       
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *	       
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */
   
#define _GNU_SOURCE

#include "obex-folder-listing.h"

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>

#if defined(APP)
#define PROGRAM_NAME "obex-folder-listing"
#define PROGRAM_VERSION "0.1"
#endif

enum ft {
	FT_FILE,
	FT_FOLDER,
	FT_OTHER,
};

static
mode_t filemode (const char* name)
{
	struct stat s;
	if (name == NULL ||
	    stat(name,&s) == -1)
		return 0;
	else
		return s.st_mode;
}

static
enum ft filetype (mode_t m)
{
	if (S_ISREG(m))
		return FT_FILE;
	else if (S_ISDIR(m))
		return FT_FOLDER;
	else
		return FT_OTHER;
}

static
void print_filename (FILE* fd, const char* filename, mode_t st_parent, int flags)
{
	struct stat s;
	const char* name;
	char create_time[17];
	char mod_time[17];
	char acc_time[17];

	if (filename == NULL ||
	    stat(filename,&s) == -1)
		return;

	name = strrchr(filename,(int)'/');
	if (name == NULL)
		name = filename;
	else
		++name;

	if (name[0] == '.' && !(flags & OFL_FLAG_HIDDEN))
		return;
  
	switch(filetype(s.st_mode)) {
	case FT_FILE:
		fprintf(fd,"  <file");
		break;

	case FT_FOLDER:
		fprintf(fd,"  <folder");
		break;

	default:
		return;
	}

	fprintf(fd," name=\"%s\" size=\"%ld\"",name,s.st_size);

	if (flags & OFL_FLAG_TIMES) {
		if (strftime(create_time,15,"%Y%m%dT%H%M%SZ",gmtime(&s.st_ctime)))
			fprintf(fd," created=\"%s\"",create_time);
		if (strftime(mod_time,15,"%Y%m%dT%H%M%SZ",gmtime(&s.st_mtime)))
			fprintf(fd," modified=\"%s\"",mod_time);
		if (strftime(acc_time,15,"%Y%m%dT%H%M%SZ",gmtime(&s.st_mtime)))
			fprintf(fd," accessed=\"%s\"",acc_time);
	}

	if (flags & OFL_FLAG_PERMS) {	
		fprintf(fd," user-perm=\"%s%s%s\"",
			(s.st_mode&S_IRUSR)?"R":"",
			(s.st_mode&S_IWUSR)?"W":"",
			(st_parent&S_IWUSR)?"D":"");
		fprintf(fd," group-perm=\"%s%s%s\"",
			(s.st_mode&S_IRGRP)?"R":"",
			(s.st_mode&S_IWGRP)?"W":"",
			(st_parent&S_IWGRP)?"D":"");
		fprintf(fd," other-perm=\"%s%s%s\"",
			(s.st_mode&S_IROTH)?"R":"",
			(s.st_mode&S_IWOTH)?"W":"",
			(st_parent&S_IWOTH)?"D":"");
	}

	fprintf(fd," />\n");
}

static 
void print_dir (FILE* fd, const char* dir, int flags)
{
	DIR* d;
	char* filename = NULL;
	size_t flen;
	struct stat s;
	struct dirent* entry = NULL;
	char* seperator;
  
	if (dir == NULL ||
	    stat(dir,&s) == -1)
		return;
	seperator = (dir[strlen(dir)-1] == '/')? "" : "/";

	d = opendir(dir);
	flen = strlen(dir)+strlen(seperator)+1;
	while ((entry = readdir(d))) {
		if (strcmp(entry->d_name,".") == 0 ||
		    strcmp(entry->d_name,"..") == 0)
			continue;
		filename = realloc(filename,flen+strlen(entry->d_name));
		sprintf(filename,"%s%s%s",dir,seperator,entry->d_name);
		print_filename(fd,filename,s.st_mode,flags);
	}
	if (filename)
		free(filename);
	closedir(d);
}

int obex_folder_listing (FILE* fd, char* name, int flags)
{
	mode_t m = 0;
	int err = 0;

	fprintf(fd,
		"<?xml version=\"1.0\"?>\n"
		"<!DOCTYPE folder-listing SYSTEM \"obex-folder-listing.dtd\">\n"
		"<folder-listing version=\"1.0\">\n");
  
	if (flags & OFL_FLAG_PARENT) {
		char* p = strdup(name);
		char* tmp = NULL;

		if (p) do {
			tmp = strrchr(p,(int)'/');
			if (!tmp)
				break;
			tmp[0] = 0;
		} while (tmp[1] == 0 || strcmp(tmp+1,".") == 0);

		if (tmp != NULL) {
			if (strcmp(tmp+1,"..") == 0) {
				err = -EINVAL;
				goto out;
			}
			fprintf(fd,"  <parent-folder/>\n");
			if (p)
				m = filemode(p);
		} else {
			if (strcmp(p,"..") == 0) {
				err = -EINVAL;
				goto out;
			}
		}
		free(p);
	}

	switch (filetype(filemode(name))) {
	case FT_FOLDER:
		print_dir(fd,name,flags);
		break;

	case FT_FILE:
		print_filename(fd,name,m,flags);
		break;

	default:
		err = -ENOTDIR;
		goto out;
	}

out:
	fprintf(fd,"</folder-listing>\n");
	return err;

}

#if defined(APP)
void print_disclaimer () {
	fprintf(stderr,
		PROGRAM_NAME" "PROGRAM_VERSION " Copyright (C) 2006 Hendrik Sattler\n"
		"This software comes with ABSOLUTELY NO WARRANTY.\n"
		"This is free software, and you are welcome to redistribute it\n"
		"under certain conditions.\n");
}

void print_help () {
	print_disclaimer();
	fprintf(stderr,
		"\n"
		"Usage: %s [<options>]\n", PROGRAM_NAME);
	fprintf(stderr,
		"\n"
		"Options:\n"
		" -P  show parent folder indicator\n"
		" -H  also list hidden files/directories\n"
		" -t  show time attributes\n"
		" -p  show permission attributes\n"
#if 0
		" -o  show file owner attribute\n"
		" -g  show file group attribute\n"
#endif
		" -h  this help message\n");
}

int main (int argc, char** argv)
{
	char* name = ".";
	FILE* fd = stdout;
	int err;
	int c;
	int flags = 0;

	while ((c = getopt(argc,argv,"PHtph")) != -1) {
		switch (c) {
		case 'P':
			flags |= OFL_FLAG_PARENT;
			break;
		case 'H':
			flags |= OFL_FLAG_HIDDEN;
			break;
		case 't':
			flags |= OFL_FLAG_TIMES;
			break;
		case 'p':
			flags |= OFL_FLAG_PERMS;
			break;
#if 0
		case 'o':
			flags |= OFL_FLAG_OWNER;
			break;
		case 'g':
			flags |= OFL_FLAG_GROUP;
			break;
#endif
		case 'h':
			print_help();
			exit(EXIT_SUCCESS);
		}
	}

	if (optind < argc)
		name = argv[optind];

	print_disclaimer();
	err = obex_folder_listing(fd,name,flags);

	if (err) {
		fprintf(stderr,"%s\n",strerror(-err));
		exit(EXIT_FAILURE);
	} else {
		exit(EXIT_SUCCESS);
	}
}
#endif
