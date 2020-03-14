/*
  zip_source_filep.c -- create data source from FILE *
  Copyright (C) 1999-2019 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.

  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "zipint.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_CLONEFILE
#include <sys/attr.h>
#include <sys/clonefile.h>
#define CAN_CLONE
#endif
#ifdef HAVE_FICLONERANGE
#include <linux/fs.h>
#include <sys/ioctl.h>
#define CAN_CLONE
#endif

struct read_file {
    zip_error_t error; /* last error information */
    zip_int64_t supports;

    /* reading */
    char *fname;            /* name of file to read from */
    FILE *f;                /* file to read from */
    struct zip_stat st;     /* stat information passed in */
    zip_error_t stat_error; /* error returned for stat */
    zip_uint64_t start;     /* start offset of data to read */
    zip_uint64_t end;       /* end offset of data to read relative to start, 0 for up to EOF */
    zip_uint64_t current;   /* current offset relative to start (0 is beginning of part we read) */

    /* writing */
    char *tmpname;
    FILE *fout;
};

static zip_int64_t read_file(void *state, void *data, zip_uint64_t len, zip_source_cmd_t cmd);
static int create_temp_output(struct read_file *ctx);
#ifdef CAN_CLONE
static zip_int64_t create_temp_output_cloning(struct read_file *ctx, zip_uint64_t offset);
#endif
static FILE *_zip_fopen(const char *name, bool writeable);
static int _zip_fseek_u(FILE *f, zip_uint64_t offset, int whence, zip_error_t *error);
static int _zip_fseek(FILE *f, zip_int64_t offset, int whence, zip_error_t *error);


ZIP_EXTERN zip_source_t *
zip_source_filep(zip_t *za, FILE *file, zip_uint64_t start, zip_int64_t len) {
    if (za == NULL)
	return NULL;

    return zip_source_filep_create(file, start, len, &za->error);
}


ZIP_EXTERN zip_source_t *
zip_source_filep_create(FILE *file, zip_uint64_t start, zip_int64_t length, zip_error_t *error) {
    if (file == NULL || length < -1) {
	zip_error_set(error, ZIP_ER_INVAL, 0);
	return NULL;
    }

    return _zip_source_file_or_p(NULL, file, start, length, NULL, error);
}


zip_source_t *
_zip_source_file_or_p(const char *fname, FILE *file, zip_uint64_t start, zip_int64_t len, const zip_stat_t *st, zip_error_t *error) {
    struct read_file *ctx;
    zip_source_t *zs;
    struct stat sb;
    bool stat_valid;

    if (file == NULL && fname == NULL) {
	zip_error_set(error, ZIP_ER_INVAL, 0);
	return NULL;
    }

    if (len < 0) {
	len = 0;
    }

    if (start > ZIP_INT64_MAX || start + (zip_uint64_t)len < start) {
	zip_error_set(error, ZIP_ER_INVAL, 0);
	return NULL;
    }

    if ((ctx = (struct read_file *)malloc(sizeof(struct read_file))) == NULL) {
	zip_error_set(error, ZIP_ER_MEMORY, 0);
	return NULL;
    }

    ctx->fname = NULL;
    if (fname) {
	if ((ctx->fname = strdup(fname)) == NULL) {
	    zip_error_set(error, ZIP_ER_MEMORY, 0);
	    free(ctx);
	    return NULL;
	}
    }
    ctx->f = file;
    ctx->start = start;
    ctx->end = (zip_uint64_t)len;
    if (st) {
	memcpy(&ctx->st, st, sizeof(ctx->st));
	ctx->st.name = NULL;
	ctx->st.valid &= ~ZIP_STAT_NAME;
    }
    else {
	zip_stat_init(&ctx->st);
    }

    if (ctx->end > 0) {
	ctx->st.size = ctx->end;
	ctx->st.valid |= ZIP_STAT_SIZE;
    }

    zip_error_init(&ctx->stat_error);

    ctx->tmpname = NULL;
    ctx->fout = NULL;

    zip_error_init(&ctx->error);

    ctx->supports = ZIP_SOURCE_SUPPORTS_READABLE | zip_source_make_command_bitmap(ZIP_SOURCE_SUPPORTS, ZIP_SOURCE_TELL, -1);

    if (ctx->fname) {
	stat_valid = stat(ctx->fname, &sb) >= 0;

	if (!stat_valid) {
	    if (ctx->start == 0 && ctx->end == 0) {
		ctx->supports = ZIP_SOURCE_SUPPORTS_WRITABLE;
	    }
	}
    }
    else {
	stat_valid = fstat(fileno(ctx->f), &sb) >= 0;
    }

    if (!stat_valid) {
	zip_error_set(&ctx->stat_error, ZIP_ER_READ, errno);
    }
    else {
	if ((ctx->st.valid & ZIP_STAT_MTIME) == 0) {
	    ctx->st.mtime = sb.st_mtime;
	    ctx->st.valid |= ZIP_STAT_MTIME;
	}
	if (S_ISREG(sb.st_mode)) {
	    ctx->supports = ZIP_SOURCE_SUPPORTS_SEEKABLE;

	    if (ctx->start + ctx->end > (zip_uint64_t)sb.st_size) {
		zip_error_set(error, ZIP_ER_INVAL, 0);
		free(ctx->fname);
		free(ctx);
		return NULL;
	    }

	    if (ctx->end == 0) {
		ctx->st.size = (zip_uint64_t)sb.st_size - ctx->start;
		ctx->st.valid |= ZIP_STAT_SIZE;

		if (ctx->fname && start == 0) {
		    ctx->supports = ZIP_SOURCE_SUPPORTS_WRITABLE;
		}
	    }
	}
    }

    ctx->supports |= ZIP_SOURCE_MAKE_COMMAND_BITMASK(ZIP_SOURCE_ACCEPT_EMPTY);
#ifdef CAN_CLONE
    if (ctx->supports & ZIP_SOURCE_MAKE_COMMAND_BITMASK(ZIP_SOURCE_BEGIN_WRITE)) {
	ctx->supports |= ZIP_SOURCE_MAKE_COMMAND_BITMASK(ZIP_SOURCE_BEGIN_WRITE_CLONING);
    }
#endif

    if ((zs = zip_source_function_create(read_file, ctx, error)) == NULL) {
	free(ctx->fname);
	free(ctx);
	return NULL;
    }

    return zs;
}


static int
create_temp_output(struct read_file *ctx) {
    char *temp;
    int tfd;
    int mode;
    FILE *tfp;
    struct stat st;

    if ((temp = (char *)malloc(strlen(ctx->fname) + 8)) == NULL) {
	zip_error_set(&ctx->error, ZIP_ER_MEMORY, 0);
	return -1;
    }

    if (stat(ctx->fname, &st) == 0) {
	mode = st.st_mode;
    }
    else {
	mode = -1;
    }

    sprintf(temp, "%s.XXXXXX", ctx->fname);

    if ((tfd = _zip_mkstempm(temp, mode)) == -1) {
	zip_error_set(&ctx->error, ZIP_ER_TMPOPEN, errno);
	free(temp);
	return -1;
    }

    if ((tfp = fdopen(tfd, "r+b")) == NULL) {
	zip_error_set(&ctx->error, ZIP_ER_TMPOPEN, errno);
	close(tfd);
	(void)remove(temp);
	free(temp);
	return -1;
    }

    ctx->fout = tfp;
    ctx->tmpname = temp;

    return 0;
}

#ifdef CAN_CLONE
zip_int64_t static create_temp_output_cloning(struct read_file *ctx, zip_uint64_t offset) {
    char *temp;
    FILE *tfp;

    if (offset > ZIP_OFF_MAX) {
	zip_error_set(&ctx->error, ZIP_ER_SEEK, E2BIG);
	return -1;
    }

    if ((temp = (char *)malloc(strlen(ctx->fname) + 8)) == NULL) {
	zip_error_set(&ctx->error, ZIP_ER_MEMORY, 0);
	return -1;
    }
    sprintf(temp, "%s.XXXXXX", ctx->fname);

#ifdef HAVE_CLONEFILE
#ifndef __clang_analyzer__
    /* we can't use mkstemp, since clonefile insists on creating the file */
    if (mktemp(temp) == NULL) {
	zip_error_set(&ctx->error, ZIP_ER_TMPOPEN, errno);
	free(temp);
	return -1;
    }
#endif

    if (clonefile(ctx->fname, temp, 0) < 0) {
	zip_error_set(&ctx->error, ZIP_ER_TMPOPEN, errno);
	free(temp);
	return -1;
    }
    if ((tfp = _zip_fopen(temp, true)) == NULL) {
	zip_error_set(&ctx->error, ZIP_ER_TMPOPEN, errno);
	(void)remove(temp);
	free(temp);
	return -1;
    }
#else
    {
	int fd;
	struct file_clone_range range;
	struct stat st;

	if (fstat(fileno(ctx->f), &st) < 0) {
	    zip_error_set(&ctx->error, ZIP_ER_TMPOPEN, errno);
	    return -1;
	}

	if ((fd = mkstemp(temp)) < 0) {
	    zip_error_set(&ctx->error, ZIP_ER_TMPOPEN, errno);
	    free(temp);
	    return -1;
	}

	range.src_fd = fileno(ctx->f);
	range.src_offset = 0;
	range.src_length = ((offset + st.st_blksize - 1) / st.st_blksize) * st.st_blksize;
	if (range.src_length > st.st_size) {
	    range.src_length = 0;
	}
	range.dest_offset = 0;
	if (ioctl(fd, FICLONERANGE, &range) < 0) {
	    zip_error_set(&ctx->error, ZIP_ER_TMPOPEN, errno);
	    (void)close(fd);
	    (void)remove(temp);
	    free(temp);
	    return -1;
	}

	if ((tfp = fdopen(fd, "r+b")) == NULL) {
	    zip_error_set(&ctx->error, ZIP_ER_TMPOPEN, errno);
	    (void)close(fd);
	    (void)remove(temp);
	    free(temp);
	    return -1;
	}
    }
#endif

    if (ftruncate(fileno(tfp), (off_t)offset) < 0) {
	(void)fclose(tfp);
	(void)remove(temp);
	free(temp);
	return -1;
    }
    if (fseeko(tfp, (off_t)offset, SEEK_SET) < 0) {
	(void)fclose(tfp);
	(void)remove(temp);
	free(temp);
	zip_error_set(&ctx->error, ZIP_ER_TMPOPEN, errno);
    }

    ctx->fout = tfp;
    ctx->tmpname = temp;

    return 0;
}
#endif


static zip_int64_t
read_file(void *state, void *data, zip_uint64_t len, zip_source_cmd_t cmd) {
    struct read_file *ctx;
    char *buf;
    zip_uint64_t n;
    size_t i;

    ctx = (struct read_file *)state;
    buf = (char *)data;

    switch (cmd) {
    case ZIP_SOURCE_ACCEPT_EMPTY:
	return 0;

    case ZIP_SOURCE_BEGIN_WRITE:
#ifdef _WIN32
	return -1;
#else
	if (ctx->fname == NULL) {
	    zip_error_set(&ctx->error, ZIP_ER_OPNOTSUPP, 0);
	    return -1;
	}
	return create_temp_output(ctx);
#endif

#ifdef CAN_CLONE
    case ZIP_SOURCE_BEGIN_WRITE_CLONING:
	if (ctx->fname == NULL) {
	    zip_error_set(&ctx->error, ZIP_ER_OPNOTSUPP, 0);
	    return -1;
	}
	return create_temp_output_cloning(ctx, len);
#endif

    case ZIP_SOURCE_CLOSE:
	if (ctx->fname) {
	    fclose(ctx->f);
	    ctx->f = NULL;
	}
	return 0;

    case ZIP_SOURCE_COMMIT_WRITE: {
	if (fclose(ctx->fout) < 0) {
	    ctx->fout = NULL;
	    zip_error_set(&ctx->error, ZIP_ER_WRITE, errno);
	}
	ctx->fout = NULL;
	if (rename(ctx->tmpname, ctx->fname) < 0) {
	    zip_error_set(&ctx->error, ZIP_ER_RENAME, errno);
	    return -1;
	}
	free(ctx->tmpname);
	ctx->tmpname = NULL;
	return 0;
    }

    case ZIP_SOURCE_ERROR:
	return zip_error_to_data(&ctx->error, data, len);

    case ZIP_SOURCE_FREE:
	free(ctx->fname);
	free(ctx->tmpname);
	if (ctx->f)
	    fclose(ctx->f);
	free(ctx);
	return 0;

    case ZIP_SOURCE_OPEN:
	if (ctx->fname) {
	    if ((ctx->f = _zip_fopen(ctx->fname, false)) == NULL) {
		zip_error_set(&ctx->error, ZIP_ER_OPEN, errno);
		return -1;
	    }
	}

	if (ctx->start > 0) {
	    if (_zip_fseek_u(ctx->f, ctx->start, SEEK_SET, &ctx->error) < 0) {
		/* TODO: skip by reading */
		return -1;
	    }
	}
	ctx->current = 0;
	return 0;

    case ZIP_SOURCE_READ:
	if (ctx->end > 0) {
	    n = ctx->end - ctx->current;
	    if (n > len) {
		n = len;
	    }
	}
	else {
	    n = len;
	}

	if (n > SIZE_MAX)
	    n = SIZE_MAX;

	if ((i = fread(buf, 1, (size_t)n, ctx->f)) == 0) {
	    if (ferror(ctx->f)) {
		zip_error_set(&ctx->error, ZIP_ER_READ, errno);
		return -1;
	    }
	}
	ctx->current += i;

	return (zip_int64_t)i;

    case ZIP_SOURCE_REMOVE:
	if (remove(ctx->fname) < 0) {
	    zip_error_set(&ctx->error, ZIP_ER_REMOVE, errno);
	    return -1;
	}
	return 0;

    case ZIP_SOURCE_ROLLBACK_WRITE:
	if (ctx->fout) {
	    fclose(ctx->fout);
	    ctx->fout = NULL;
	}
	(void)remove(ctx->tmpname);
	free(ctx->tmpname);
	ctx->tmpname = NULL;
	return 0;

    case ZIP_SOURCE_SEEK: {
	zip_int64_t new_current;
	int need_seek;
	zip_source_args_seek_t *args = ZIP_SOURCE_GET_ARGS(zip_source_args_seek_t, data, len, &ctx->error);

	if (args == NULL)
	    return -1;

	need_seek = 1;

	switch (args->whence) {
	case SEEK_SET:
	    new_current = args->offset;
	    break;

	case SEEK_END:
	    if (ctx->end == 0) {
		if (_zip_fseek(ctx->f, args->offset, SEEK_END, &ctx->error) < 0) {
		    return -1;
		}
		if ((new_current = ftello(ctx->f)) < 0) {
		    zip_error_set(&ctx->error, ZIP_ER_SEEK, errno);
		    return -1;
		}
		new_current -= (zip_int64_t)ctx->start;
		need_seek = 0;
	    }
	    else {
		new_current = (zip_int64_t)ctx->end + args->offset;
	    }
	    break;

	case SEEK_CUR:
	    new_current = (zip_int64_t)ctx->current + args->offset;
	    break;

	default:
	    zip_error_set(&ctx->error, ZIP_ER_INVAL, 0);
	    return -1;
	}

	if (new_current < 0 || (ctx->end != 0 && (zip_uint64_t)new_current > ctx->end) || (zip_uint64_t)new_current + ctx->start < ctx->start) {
	    zip_error_set(&ctx->error, ZIP_ER_INVAL, 0);
	    return -1;
	}

	ctx->current = (zip_uint64_t)new_current;

	if (need_seek) {
	    if (_zip_fseek_u(ctx->f, ctx->current + ctx->start, SEEK_SET, &ctx->error) < 0) {
		return -1;
	    }
	}
	return 0;
    }

    case ZIP_SOURCE_SEEK_WRITE: {
	zip_source_args_seek_t *args;

	args = ZIP_SOURCE_GET_ARGS(zip_source_args_seek_t, data, len, &ctx->error);
	if (args == NULL) {
	    return -1;
	}

	if (_zip_fseek(ctx->fout, args->offset, args->whence, &ctx->error) < 0) {
	    return -1;
	}
	return 0;
    }

    case ZIP_SOURCE_STAT: {
	if (len < sizeof(ctx->st))
	    return -1;

	if (zip_error_code_zip(&ctx->stat_error) != 0) {
	    zip_error_set(&ctx->error, zip_error_code_zip(&ctx->stat_error), zip_error_code_system(&ctx->stat_error));
	    return -1;
	}

	memcpy(data, &ctx->st, sizeof(ctx->st));
	return sizeof(ctx->st);
    }

    case ZIP_SOURCE_SUPPORTS:
	return ctx->supports;

    case ZIP_SOURCE_TELL:
	return (zip_int64_t)ctx->current;

    case ZIP_SOURCE_TELL_WRITE: {
	off_t ret = ftello(ctx->fout);

	if (ret < 0) {
	    zip_error_set(&ctx->error, ZIP_ER_TELL, errno);
	    return -1;
	}
	return ret;
    }

    case ZIP_SOURCE_WRITE: {
	size_t ret;

	clearerr(ctx->fout);
	ret = fwrite(data, 1, len, ctx->fout);
	if (ret != len || ferror(ctx->fout)) {
	    zip_error_set(&ctx->error, ZIP_ER_WRITE, errno);
	    return -1;
	}

	return (zip_int64_t)ret;
    }

    default:
	zip_error_set(&ctx->error, ZIP_ER_OPNOTSUPP, 0);
	return -1;
    }
}


static int
_zip_fseek_u(FILE *f, zip_uint64_t offset, int whence, zip_error_t *error) {
    if (offset > ZIP_INT64_MAX) {
	zip_error_set(error, ZIP_ER_SEEK, EOVERFLOW);
	return -1;
    }
    return _zip_fseek(f, (zip_int64_t)offset, whence, error);
}


static int
_zip_fseek(FILE *f, zip_int64_t offset, int whence, zip_error_t *error) {
    if (offset > ZIP_FSEEK_MAX || offset < ZIP_FSEEK_MIN) {
	zip_error_set(error, ZIP_ER_SEEK, EOVERFLOW);
	return -1;
    }
    if (fseeko(f, (off_t)offset, whence) < 0) {
	zip_error_set(error, ZIP_ER_SEEK, errno);
	return -1;
    }
    return 0;
}


/*
 * fopen replacement that sets the close-on-exec flag
 * some implementations support an fopen 'e' flag for that,
 * but e.g. macOS doesn't.
 */
static FILE *
_zip_fopen(const char *name, bool writeable)
{
    int fd;
    int flags;
    FILE *fp;

    flags = O_CLOEXEC;
    if (writeable) {
	flags |= O_RDWR;
    }
    else {
	flags |= O_RDONLY;
    }

    /* mode argument needed on Windows */
    if ((fd = open(name, flags, 0666)) < 0) {
	return NULL;
    }
    if ((fp = fdopen(fd, writeable ? "r+b" : "rb")) == NULL) {
	return NULL;
    }
    return fp;
}
