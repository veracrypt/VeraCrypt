#include <stdio.h>
#include <windows.h>

#define WSIZE	0x8000		// Window size
#define ZCONST	const
#define OF(p)	p

typedef unsigned long	ulg;
typedef unsigned char	uch;
typedef unsigned short	ush;
typedef void			zvoid;

typedef struct huft 
{
	uch b, e;
	union 
	{
		ush n;
		struct huft *t;
	}v;
};

typedef struct 
{
	uch		*inptr, *outbufptr;
	int		incnt;
	int		outCounter;

	struct huft *fixed_tl;
	struct huft *fixed_td;
	int fixed_bl, fixed_bd;

	unsigned bk, wp;
	ulg		bb;
} G_struct;

#define __GPRO	void
#define __GPRO__
#define __G
#define __G__
#define __GDEF


#define FLUSH(cnt) { memcpy (G.outbufptr, redirSlide, cnt); G.outbufptr += cnt; G.outCounter += cnt; }
#define NEXTBYTE	(((G.incnt--) >= 0) ? (*G.inptr++) : EOF)


int huft_free(struct huft *t);
int huft_build(__GDEF ZCONST unsigned *b, unsigned n, unsigned s, ZCONST ush *d, ZCONST ush *e, struct huft **t, int *m);

int DecompressDeflatedData (char *out, char *in, int inLength);
