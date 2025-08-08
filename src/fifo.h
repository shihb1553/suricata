#ifndef __FIFO_H__
#define __FIFO_H__


struct fifo {
	unsigned char *buffer;	/* the buffer holding the data */
	unsigned int size;	/* the size of the allocated buffer */
	unsigned int in;	/* data is added at offset (in % size) */
	unsigned int out;	/* data is extracted from off. (out % size) */
};

struct fifo *fifo_alloc(unsigned int);
unsigned int fifo_put(struct fifo *, void *, unsigned int);
unsigned int fifo_get(struct fifo *, void *, unsigned int);
void fifo_free(struct fifo *);

static inline unsigned int fifo_len(struct fifo *fifo)
{
	return fifo->in - fifo->out;
}

static inline unsigned int fifo_room(struct fifo *fifo)
{
	return fifo->size - fifo->in + fifo->out;
}

#endif
