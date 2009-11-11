/*
 * $Id: dv2sub.c 22 2008-01-14 09:38:30Z zito $
 *
 * dv2sub.c -- utility for extracting information from raw DV file
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

#include "config.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include <libdv/dv.h>
#include "dvstream.h"


static int verbose_flag = 0;
static int mm_flag = 1;
static unsigned long maxframes = ULONG_MAX;



int dv_stream(int fd, int pass_through_flag, cbent_t cbent[])
{
    dv_decoder_t *dec;
    off_t frame_offset=0;
    if ( (dec = dv_decoder_new(0, 0, 0)) == NULL )
    {
	fprintf(stderr, "dv_decoder_new() returns NULL\n");
	goto err_decoder_new;
    }

    unsigned char *frame;
    if ( (frame = (unsigned char *)malloc(FRAME_SIZE_MAX)) == NULL )
    {
	fprintf(stderr, "malloc() failed: %s\n", strerror(errno));
	goto err_malloc_frame;
    }

    cb_result_enum res = CB_RES_OK;
    size_t rest = 0;
    for(int frameno = 0; frameno < maxframes; frameno++)
    {
	size_t len = rest;
	ssize_t n;
	do
	{
	    n = read(fd, frame + len, FRAME_SIZE_MAX - len);

	    if ( n == (ssize_t)-1 )
	    {
		fprintf(stderr, "read() failed: %s\n", strerror(errno));
		goto err_loop;
	    }
	    len += n;
	}
	while ( n );
	if ( len == 0 )
	    break;
	if ( len < FRAME_SIZE_MIN )
	{
	    fprintf(stderr, "remains only %u bytes, premature EOF?\n",
		    (size_t)len);
	    goto err_loop;
	}
	if ( dv_parse_header(dec, frame) < 0 )
	{
	    fprintf(stderr, "dv_parse_header() failed\n"
		    "Input stream is corrupted or isn't raw DV stream!\n");
	    goto err_loop;
	}
	dv_parse_packs(dec, frame);
	for(cbent_t *ce = cbent; ce->cb != NULL; ce++)
	{
	    res = (*(ce->cb))(frameno, frame_offset, dec, frame, ce->ctx);
	    if ( res != CB_RES_OK )
		goto err_stop;
	}
	size_t frame_size = dv_is_PAL(dec) ? FRAME_SIZE_PAL : FRAME_SIZE_NTSC;
	if ( pass_through_flag )
	{
	    size_t wlen = 0;
	    do
	    {
		ssize_t n = write(1, frame + wlen, frame_size - wlen);
		if ( n == (ssize_t)-1 )
		{
		    fprintf(stderr, "write() failed: %s\n", strerror(errno));
		    goto err_loop;
		}
		wlen += n;
	    }
	    while ( frame_size != wlen );
	}
	rest = FRAME_SIZE_MAX - frame_size;
	memmove(frame, frame + frame_size, rest);
        frame_offset+=frame_size;
    }

    for(cbent_t *ce = cbent; ce->cb != NULL; ce++)
    {
	res = (*(ce->cb))(-1, -1,  NULL, NULL, ce->ctx);
	if ( res != CB_RES_OK )
	    goto err_stop;
    }

err_stop:
    free(frame);
    dv_decoder_free(dec);
    return res == CB_RES_FAIL ? -1 : 0;

err_loop:
    free(frame);
err_malloc_frame:
    dv_decoder_free(dec);
err_decoder_new:
    return -1;
}

#if HAVE_MMAP
int dv_stream_mm(int fd, cbent_t cbent[])
{
    dv_decoder_t *dec;
    if ( (dec = dv_decoder_new(0, 0, 0)) == NULL )
    {
	fprintf(stderr, "dv_decoder_new() returns NULL\n");
	goto err_decoder_new;
    }

    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    if ( page_size == (size_t)-1 )
    {
	fprintf(stderr, "sysconf(_SC_PAGESIZE) returns -1\n");
	goto err_sysconf;
    }

    off_t flen = lseek(fd, 0, SEEK_END);
    if ( flen == (off_t)-1 )
    {
	fprintf(stderr, "lseek() failed: %s\n", strerror(errno));
	goto err_lseek;
    }

    cb_result_enum res = CB_RES_OK;
    unsigned char *mmdata = NULL;
    off_t offset = 0;
    int frameno = 0;
    off_t mmoff = 0;
    int mmlen = 0;
    while ( offset < flen  &&  frameno < maxframes )
    {
	if ( flen - offset < FRAME_SIZE_MIN )
	{
	    fprintf(stderr, "remains only %d bytes, premature EOF?\n",
		    (int)(flen - offset));
	    goto err_loop;
	}
	if ( offset + FRAME_SIZE_MAX > mmoff + mmlen )
	{
	    if ( mmdata )
	    {
		if ( munmap(mmdata, mmlen) )
		{
		    fprintf(stderr, "munmap() failed: %s\n", strerror(errno));
		    goto err_unmap;
		}
	    }
	    mmoff = offset - offset % page_size;
	    mmlen = MIN(MMAP_BLOCK_LEN, flen - offset + page_size);
	    if ( (mmdata = (unsigned char *)mmap(NULL, mmlen,
			    PROT_READ, MAP_SHARED, fd, mmoff)) == NULL )
	    {
		fprintf(stderr, "mmap() failed: %s\n", strerror(errno));
		goto err_mmap;
	    }
	}
	unsigned char *frame = mmdata + (int)(offset - mmoff);
	if ( dv_parse_header(dec, frame) < 0 )
	{
	    fprintf(stderr, "dv_parse_header() failed\n"
		    "Input stream is corrupted or isn't raw DV stream!\n");
	    goto err_loop;
	}
	dv_parse_packs(dec, frame);
	for(cbent_t *ce = cbent; ce->cb != NULL; ce++)
	{
	    res = (*(ce->cb))(frameno, offset, dec, frame, ce->ctx);
	    if ( res != CB_RES_OK )
		goto err_stop;
	}
	offset += dv_is_PAL(dec) ? FRAME_SIZE_PAL : FRAME_SIZE_NTSC;
	frameno++;
    }

    for(cbent_t *ce = cbent; ce->cb != NULL; ce++)
    {
	res = (*(ce->cb))(-1, -1, NULL, NULL, ce->ctx);
	if ( res != CB_RES_OK )
	    goto err_stop;
    }

err_stop:
    if ( mmdata )
	if ( munmap(mmdata, mmlen) )
	{
	    fprintf(stderr, "munmap() failed: %s\n", strerror(errno));
	    goto err_unmap;
	}
    dv_decoder_free(dec);
    return res == CB_RES_FAIL ? -1 : 0;

err_loop:
    if ( mmdata )
	munmap(mmdata, mmlen);
err_mmap:
err_unmap:
err_lseek:
err_sysconf:
    dv_decoder_free(dec);
err_decoder_new:
    return -1;
}
#endif


int dv_stream_wrap(int fd,
	const char *fn,
	int pass_through_flag,
	cbent_t cbent[])
{
    if ( verbose_flag )
    {
	if ( fd )
	    fprintf(stderr, "processing file `%s'...\n", fn);
	else
	    fprintf(stderr, "processing stdin...\n");
    }
    struct stat stat_buf;
    if ( fstat(fd, &stat_buf) )
    {
	if ( fd )
	    fprintf(stderr, "fstat(%d) failed (file `%s'): %s\n",
		    fd, fn, strerror(errno));
	else
	    fprintf(stderr, "fstat(0) failed: %s\n", strerror(errno));
	return -1;
    }
#if HAVE_MMAP
    if ( S_ISREG(stat_buf.st_mode) && mm_flag && !pass_through_flag )
	return dv_stream_mm(fd, cbent);
    else
#endif
	return dv_stream(fd, pass_through_flag, cbent);
}

