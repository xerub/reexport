#ifndef BBUFFER_H
#define BBUFFER_H

/* Get a r/w/x binary buffer, at the given location if provided */
void *bbuffer(void *loc, size_t sz);
int xbbuffer(void *loc, size_t sz);
void unbbuffer(void *loc, size_t sz);

#endif
