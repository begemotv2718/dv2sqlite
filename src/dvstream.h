#define MMAP_BLOCK_LEN	    (16 * 1024 * 1024)

#ifndef MIN
#define MIN(a, b)   ( (a) < (b) ? (a) : (b) )
#endif

#ifndef MAX
#define MAX(a, b)   ( (a) > (b) ? (a) : (b) )
#endif

#define FRAME_SIZE_PAL	144000
#define FRAME_SIZE_NTSC	120000

#define FRAME_SIZE_MIN	MIN(FRAME_SIZE_PAL, FRAME_SIZE_NTSC)
#define FRAME_SIZE_MAX	MAX(FRAME_SIZE_PAL, FRAME_SIZE_NTSC)


typedef enum
{
    CB_RES_OK   =  1,
    CB_RES_FAIL = -1,
    CB_RES_STOP =  0
} cb_result_enum;

typedef cb_result_enum (* callback_t)(int, off_t, dv_decoder_t *,
				      unsigned char *, void *);

typedef struct cbent_st
{
    callback_t cb;
    void  *ctx;
} cbent_t;

int dv_stream(int fd, int pass_through_flag, cbent_t cbent[]);
#if HAVE_MMAP
int dv_stream_mm(int fd, cbent_t cbent[]);
#endif
int dv_stream_wrap(int fd,
	const char *fn,
	int pass_through_flag,
	cbent_t cbent[]);
