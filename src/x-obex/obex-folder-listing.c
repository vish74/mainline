/* Copyright (C) 2006,2010 Hendrik Sattler <post@hendrik-sattler.de>
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
   
#include "obex-folder-listing.h"
#include "xml_simple.h"

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

#ifdef _WIN32
#include <windows.h>
#include <shlwapi.h>
#define strdup(s) StrDup(s)

#else
#ifdef USE_XATTR
#include <attr/xattr.h>
#endif
#endif

enum ft {
	FT_FILE,
	FT_FOLDER,
	FT_OTHER,
};

static
mode_t mode_fixup(uid_t uid, uid_t gid, mode_t mode, int flags)
{
	uid_t e;
	if (!(flags & OFL_FLAG_OWNER)) {
		e = geteuid();
		if (0 != e && uid != e)
			mode &= ~(S_IRUSR | S_IWUSR);
	}

	if (!(flags & OFL_FLAG_GROUP)) {
		e = getegid();
		if (0 != e && gid != e)
			mode &= ~(S_IRGRP | S_IWGRP);
	}

	return mode;
}

static
mode_t filemode (const char* name, int flags)
{
	struct stat s;
	if (name == NULL ||
	    stat(name,&s) == -1)
		return 0;
	else
		return mode_fixup(s.st_uid, s.st_gid, s.st_mode, flags);;
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

#ifdef USE_XATTR
static int get_mime_type (
	const char *filename,
	char *type,
	size_t size
)
{
	ssize_t status = lgetxattr(filename, "user.mime_type", type, size);

	if (status == -1)
		return -errno;

	return 0;
}
#endif

static
void print_filename (FILE* fd, const char* filename, mode_t st_parent, int flags)
{
	struct stat s;
	const char *name;
	char *esc_name;
#ifdef USE_XATTR
	char type[256];
#endif
	char create_time[17];
	char mod_time[17];
	char acc_time[17];

	if (filename == NULL ||
	    stat(filename,&s) == -1)
		return;
	s.st_mode = mode_fixup(s.st_uid, s.st_gid, s.st_mode, flags);

	name = strrchr(filename,(int)'/');
	if (name == NULL)
		name = filename;
	else
		++name;

	if (name[0] == '.' && !(flags & OFL_FLAG_HIDDEN))
		return;
  
	xml_indent(fd,1);
	switch(filetype(s.st_mode)) {
	case FT_FILE:
		fprintf(fd,"<file");
		break;

	case FT_FOLDER:
		fprintf(fd,"<folder");
		break;

	default:
		return;
	}

	esc_name = xml_esc_string(name);
	fprintf(fd," name=\"%s\" size=\"%zd\"",esc_name,s.st_size);
	free(esc_name);

#ifdef USE_XATTR
	if (!get_mime_type(name,type,sizeof(type))) {
		fprintf(fd," type=\"%s\"",type);
	}
#endif

	if (flags & OFL_FLAG_TIMES) {
		if (strftime(create_time,15,"%Y%m%dT%H%M%SZ",gmtime(&s.st_ctime)))
			fprintf(fd," created=\"%s\"",create_time);
		if (strftime(mod_time,15,"%Y%m%dT%H%M%SZ",gmtime(&s.st_mtime)))
			fprintf(fd," modified=\"%s\"",mod_time);
		if (strftime(acc_time,15,"%Y%m%dT%H%M%SZ",gmtime(&s.st_mtime)))
			fprintf(fd," accessed=\"%s\"",acc_time);
	}

	if (flags & OFL_FLAG_OWNER) {
		fprintf(fd, " owner=\"%d\"", s.st_uid);
	}

	if (flags & OFL_FLAG_GROUP) {
		fprintf(fd, " group=\"%d\"", s.st_gid);
	}

	if (flags & OFL_FLAG_PERMS) {	
		fprintf(fd," user-perm=\"%s%s%s\"",
			(s.st_mode & S_IRUSR)?"R":"",
			((s.st_mode & S_IWUSR) && !(flags & OFL_FLAG_KEEP))?"W":"",
			((st_parent & S_IWUSR) && !(flags & OFL_FLAG_NODEL))?"D":"");
#ifndef _WIN32
		fprintf(fd," group-perm=\"%s%s%s\"",
			(s.st_mode & S_IRGRP)?"R":"",
			((s.st_mode & S_IWGRP) && !(flags & OFL_FLAG_KEEP))?"W":"",
			((st_parent & S_IWGRP) && !(flags & OFL_FLAG_NODEL))?"D":"");
		fprintf(fd," other-perm=\"%s%s%s\"",
			(s.st_mode & S_IROTH)?"R":"",
			((s.st_mode & S_IWOTH) && !(flags & OFL_FLAG_KEEP))?"W":"",
			((st_parent & S_IWOTH) && !(flags & OFL_FLAG_NODEL))?"D":"");
#endif
	}

	fprintf(fd," />\n");
}

static 
void print_dir (FILE* fd, const char* dir, int flags)
{
	DIR* d;
	char* filename = NULL;
	size_t flen;
	mode_t mode;
	struct dirent* entry = NULL;
	char* seperator;
	char *tmp;
  
	if (dir == NULL)
		return;

	mode = filemode(dir, flags);
	if (mode == 0)
		return;

	seperator = (dir[strlen(dir)-1] == '/')? "" : "/";
	d = opendir(dir);
	flen = strlen(dir)+strlen(seperator)+1;
	while ((entry = readdir(d))) {
		if (strcmp(entry->d_name,".") == 0 ||
		    strcmp(entry->d_name,"..") == 0)
			continue;
		tmp = realloc(filename,flen+strlen(entry->d_name));
		if (!tmp)
			break;
		else
			filename = tmp;
		sprintf(filename,"%s%s%s",dir,seperator,entry->d_name);
		print_filename(fd,filename,mode,flags);
	}
	if (filename)
		free(filename);
	closedir(d);
}

#include <langinfo.h>
static
char* get_system_charset ()
{
	return nl_langinfo(CODESET);
}

static
char* get_parent_folder_name (const char* path)
{
	char* p = strdup(path);
	char* tmp = NULL;

	if (!p)
		return NULL;

	do {
		tmp = strrchr(p,(int)'/');
		if (!tmp) {
			free(p);
			return strdup(".");
		}
		tmp[0] = 0;
	} while (tmp[1] == 0 || strcmp(tmp+1,".") == 0);

	return p;
}

int obex_folder_listing (FILE* fd, char* name, int flags)
{
	mode_t m = 0;
	int err = 0;
	size_t namelen = (name? strlen(name): 0);
	char* parent;

#if _WIN32
	/* backslash dir seperator must be converted to unix format*/
	unsigned int i = 0;
	for (; i < namelen; ++)
		if (name[i] == '\\')
			name[i] = '/';
#endif

	if (strncmp(name,"../", 3) == 0 || strcmp(name, "..") == 0
	    || (namelen > 3 &&
		(strstr(name,"/../") != NULL
		 || strncmp(name+namelen-3,"/..",3) == 0)))
	{
		return -EINVAL;
	}

	fprintf(fd,
		"<?xml version=\"1.0\" encoding=\"%s\"?>\n",
		get_system_charset());
	fprintf(fd,
		"<!DOCTYPE folder-listing SYSTEM \"obex-folder-listing.dtd\">\n");
	xml_open(fd,0,"folder-listing version=\"1.0\"");

	parent = get_parent_folder_name(name);
	if (parent) {
		if (flags & OFL_FLAG_PARENT)
			xml_print(fd,1,"parent-folder",NULL,0);
		m = filemode(parent, flags);
		free(parent);
	}

	switch (filetype(filemode(name, flags))) {
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
	xml_close(fd,0,"folder-listing");
	return err;

}
