/*
 * blktrace output analysis: generate a timeline & gather statistics
 *
 * Copyright (C) 2022 Andrew Zhu <mrju.email@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "globals.h"

int do_x2q(const char *name)
{
	int fd, ret;
	struct stat buf;
	uint64_t total_bytes;
	unsigned long depth = 512;
	struct blk_io_trace *t, *__t;
	void *start, *from, *to;

	fd = open(name, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "open %s failed.\n", name);
		ret = fd;
		goto err0;
	}

	ret = fstat(fd, &buf);
	if (ret < 0) {
		fprintf(stderr, "fstat %s failed.\n", name);
		goto err1;
	}

	start = mmap(NULL, buf.st_size,
			PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (start == MAP_FAILED) {
		fprintf(stderr, "mmap failed.\n");
		ret = -ENOMEM;
		goto err1;
	}

	for_each_trace(t, start, start + buf.st_size) {
		if (__trace_action(t) == __BLK_TA_QUEUE) {
			from = (void *) __next_trace(t);
			to = __scan_depth_end(t, start + buf.st_size, depth);
			for_each_trace(__t, from, to) {
				if (__trace_action(__t) == __BLK_TA_SPLIT
						&& (t->sector == __t->sector)) {
					total_bytes = t->bytes;
					t->bytes = __t->bytes;
					__t->sector = __t->sector + (__t->bytes >> 9);
					__t->bytes = total_bytes - t->bytes;
					__t->action &= ~BLK_TA_MASK;
					__t->action |= __BLK_TA_QUEUE;
					break;
				}
			}
		}
	}

	munmap(start, (size_t) (start + buf.st_size));
	close(fd);

	return 0;

err1:
	close(fd);

err0:
	return ret;
}
