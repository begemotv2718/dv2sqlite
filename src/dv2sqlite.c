/*
 * dv2sqlite.c -- stores frames information in the sqlite database
 *
 * Based on dv2sub.c, which is
 * Copyright (C) 2006 Vaclav Ovsik <zito@users.sourceforge.net>
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
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include <libdv/dv.h>
#include "dvstream.h"
#include <openssl/sha.h>
#include <sqlite3.h>

#define SQLITE_EXEC_1(db, str) {\
                                 int rc; char *zErrMsg=0;\
                                 rc = sqlite3_exec(db,str,NULL,NULL,&zErrMsg); \
                                 if(rc != SQLITE_OK){ \
                                  fprintf(stderr,"SQL error: %s\n", zErrMsg); \
                                  sqlite3_free(zErrMsg); \
                                  sqlite3_close(db); \
                                  exit(1); \
                                 }\
                                } 
#define SQLITE_EXEC_2(db, query, args...) {char *tmp;\
                                          tmp=sqlite3_mprintf(query, ## args); \
                                          if(!tmp){ fprintf(stderr,"No memory for statement\n");exit(1); } \
                                          SQLITE_EXEC_1(db, tmp); \
                                          sqlite3_free(tmp); }
typedef struct cbcontext_st
{
    sqlite3 *db;
    char *filename;
} cbcontext_t;
static int verbose_flag = 0;
static int mm_flag = 1;
static unsigned long maxframes = ULONG_MAX;



int bin2hex(const char *input, int len,  char *output)
{
  if(!input || !output || len<=0) return -1;
  static char hexdigits[] = "0123456789abcdef";
  int i;
  for(i=0;i<len;i++){
   *output++=hexdigits[(unsigned char)(input[i]) >> 4];
   *output++=hexdigits[(unsigned char)(input[i]) & 0x0F];
  }
  *output=0;
  return(len);
}

unsigned int dv_timestamp_int(dv_decoder_t *dec){
  int timestamp[4];
  int rc;
  rc=dv_get_timestamp_int(dec,timestamp);
  if(rc){
    int framerate=dv_is_PAL(dec)?25:30;
    return((3600*timestamp[0]+60*timestamp[1]+timestamp[2])*framerate+timestamp[3]);
  }
  return 0;
}



static cb_result_enum dv_info(int frameno,
        off_t offset,
	dv_decoder_t *dec,
	unsigned char *frame,
	void *ctxptr)
{
    static char lastdigest[2*SHA_DIGEST_LENGTH+1];
    static unsigned long lastunixtime=0;
    static int lasttimecode=0;
    cbcontext_t* ctx=(cbcontext_t*)ctxptr;
    if ( frameno < 0 )
	return CB_RES_OK;

    char const *system = dv_is_PAL(dec) ? "pal" : "ntsc";
    char const *format = dv_format_normal(dec) > 0 ? "normal" :
	    dv_format_wide(dec) > 0 ? "wide" :
	    dv_format_letterbox(dec) > 0 ? "letterbox" :
	    "unknown";
    int is_prog = dv_is_progressive(dec);
    char const *interlaced = is_prog > 0 ? " progressive" :
	    is_prog == 0 ? " interlaced" :
	    "";
    int samples = dv_get_num_samples(dec);

    /*Audio*/
    int channels = dv_get_num_channels(dec);
    int freq = dv_get_frequency(dec);

    /*Date and time manipulations*/
    struct tm datetime_strct;
    char timecode[40];
    dv_get_timestamp(dec, timecode);
    unsigned int curtimecode = dv_timestamp_int(dec);
    dv_get_recording_datetime_tm(dec, &datetime_strct);
    char date[40];
    char time[40];
    char strunixtime[40];
    unsigned long unixtime;
    strftime(date,40,"%F",&datetime_strct);
    strftime(time,40,"%H:%M:%S",&datetime_strct);
    strftime(strunixtime,40,"%s",&datetime_strct);
    unixtime=strtol(strunixtime,NULL,10);

    size_t frame_size = dv_is_PAL(dec) ? FRAME_SIZE_PAL : FRAME_SIZE_NTSC;

    /*Sha sum of the frame*/
    char sha1sum[SHA_DIGEST_LENGTH];
    char digest[2*SHA_DIGEST_LENGTH+1];
    SHA1(frame,(unsigned long)frame_size, sha1sum);
    bin2hex(sha1sum,SHA_DIGEST_LENGTH,digest);
   
    /*Decide if the next frame is a part of the same scene*/ 
    char *prev;
    if(((unixtime-lastunixtime == 0)||(unixtime-lastunixtime == 1))&&(curtimecode-lasttimecode <= 5)){
      prev=lastdigest;
    }else{
      prev="";
    }

    SQLITE_EXEC_2(ctx->db,"INSERT INTO dvfiles VALUES(NULL, %Q, %d, %d, %Q, %Q, %Q, %ld, %Q, %Q, NULL, %Q);",ctx->filename,frameno,offset,timecode,date,time,unixtime,digest,system,prev);
    strncpy(lastdigest,digest,sizeof(lastdigest));
    lastunixtime=unixtime;
    lasttimecode=curtimecode;

    
    return CB_RES_OK;
}



static char const *progname;

static void usage(int status)
{
    puts("Usage: dv2sqlite [options] <dvfile> [<dvfile] ...\n"
"\n"
"Options:\n"
" -d, --dbfile <dbfilename> specify the database filename"
" -h, --help                this short usage listing\n"
" -v, --verbose             be verbose\n"
" -V, --version             utility version info\n"
"\n"
"Report bugs to " PACKAGE_BUGREPORT
	    );
    exit(status);
}

int main(int argc, char *argv[], char *env[])
{
    progname = argv[0];
    char *db_filename="test.db";
    int verbose_flag=0;
    if ( argc == 1 )
	usage(1);

    while ( 1 )
    {
	static struct option long_options[] =
	    {
		{"dbfile", required_argument, NULL, 'd'},
		{"help", no_argument, NULL, 'h'},
                {"version",no_argument,NULL,'V'},
                {"verbose",no_argument,NULL,'v'},
		{0, 0, 0, 0}
	    };
	/* `getopt_long' stores the option index here. */
	int option_index = 0;

	int c = getopt_long(argc, argv, "d:hvV",
		long_options, &option_index);

	/* Detect the end of the options. */
	if ( c == -1 )
	    break;
	switch (c)
        {
          case 'd':
            db_filename=optarg;
            break;
          case 'h':
            usage(1);
          case 'V':
            puts("Version 0.1\n");
            exit(0);
          case 'v':
            verbose_flag=1;
        }    
    }

    if (optind == argc)
      usage(1);

    int fail = 0;

    cbent_t ce[8];
    cbcontext_t ctx[8];

    sqlite3 *db;
    int rc;
    rc = sqlite3_open(db_filename,&db);
    if( rc ){
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      sqlite3_close(db);
      exit(1);
    }
    SQLITE_EXEC_1(db,"CREATE TABLE IF NOT EXISTS dvfiles (id INTEGER PRIMARY KEY, filename VARCHAR, frameno INTEGER, offset INTEGER, timecode VARCHAR, date VARCHAR, time VARCHAR, unixtime INTEGER, digest VARCHAR, system VARCHAR, next VARCHAR, prev VARCHAR);");


    for(int i = optind; i < argc; i++)
    {
	int fd;
	if ( (fd = open(argv[i], O_RDONLY)) < 0 )
	{
	    fprintf(stderr, "open(\"%s\"...) failed: %s\n",
		argv[i], strerror(errno));
	    continue;
	}
        int i_ce = 0;
        memset(ce, 0, sizeof(ce));
        memset(ctx, 0, sizeof(ctx));
        char *filename;
        filename=canonicalize_file_name(argv[i]); /*alloc filename*/

        char *tmp;
        tmp=sqlite3_mprintf("SELECT DISTINCT filename FROM dvfiles WHERE filename=%Q",filename);
        if(!tmp){
          fprintf(stderr,"No memory for SQL\n"); exit(1);
        }
        sqlite3_stmt *sth;
        rc = sqlite3_prepare_v2(db,tmp,-1,&sth,NULL);
        if( rc != SQLITE_OK ){
          fprintf(stderr, "ERROR preparing %s\n",tmp);
          sqlite3_close(db);
          exit(1);
        }
        if(sqlite3_step(sth) == SQLITE_ROW){
          fprintf(stderr, "filename %s exists in the database, skipping\n",filename);
          continue;
        }
        sqlite3_finalize(sth);
        sqlite3_free(tmp);



        ce[i_ce].cb = &dv_info;
        ctx[i_ce].db = db;
        ctx[i_ce].filename=filename;
        ce[i_ce].ctx=&ctx[i_ce];
        i_ce++;
        SQLITE_EXEC_1(db,"BEGIN TRANSACTION;");
	fail |= dv_stream_wrap(fd, argv[i], 0, ce);
        SQLITE_EXEC_1(db,"END TRANSACTION;");
        free(filename);
	close(fd);
    }
    sqlite3_close(db);

    return fail ? 1 : 0;
}
