#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>

#include "fifo.h"

struct fifo *fifo_alloc(unsigned int size)
{
	struct fifo *fifo;

	fifo = malloc(sizeof(struct fifo));
	if (!fifo)
		return NULL;

	fifo->buffer = malloc(size);
	fifo->size = size;
	fifo->in = fifo->out = 0;

	return fifo;
}

void fifo_free(struct fifo *fifo)
{
	free(fifo->buffer);
	free(fifo);
}

unsigned int fifo_put(struct fifo *fifo, void *buffer, unsigned int len)
{
	unsigned int l;

	len = MIN(len, fifo_room(fifo));

	/* first put the data starting from fifo->in to buffer end */
	l = MIN(len, fifo->size - (fifo->in & (fifo->size - 1)));
	memcpy(fifo->buffer + (fifo->in & (fifo->size - 1)), buffer, l);

	/* then put the rest (if any) at the beginning of the buffer */
	memcpy(fifo->buffer, buffer + l, len - l);

	/*
	 * Ensure that we add the bytes to the fifo -before-
	 * we update the fifo->in index.
	 */

	fifo->in += len;

	return len;
}

unsigned int fifo_get(struct fifo *fifo, void *buf, unsigned int len)
{
	len = MIN(len, fifo->in - fifo->out);

	if (buf) {
		unsigned int l;

		/*
		 * first get the data from fifo->out until the end of the buffer
		 */
		l = MIN(len, fifo->size - (fifo->out & (fifo->size - 1)));
		memcpy(buf, fifo->buffer + (fifo->out & (fifo->size - 1)), l);

		/*
		 * then get the rest (if any) from the beginning of the buffer
		 */
		memcpy(buf + l, fifo->buffer, len - l);
	}

	fifo->out += len;

	//if (fifo->in == fifo->out)
		//fifo->in = fifo->out = 0;

	return len;
}
