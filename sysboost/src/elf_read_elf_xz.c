/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <lzma.h>

#include "elf_read_elf.h"
#include <si_log.h>

static void xz_uncompress_log_err(lzma_ret ret)
{
	switch (ret) {
	case LZMA_MEM_ERROR:
		SI_LOG_ERR("xz: %s\n", strerror(ENOMEM));
		break;
	case LZMA_FORMAT_ERROR:
		SI_LOG_ERR("xz: File format not recognized\n");
		break;
	case LZMA_OPTIONS_ERROR:
		SI_LOG_ERR("xz: Unsupported compression options\n");
		break;
	case LZMA_DATA_ERROR:
		SI_LOG_ERR("xz: File is corrupt\n");
		break;
	case LZMA_BUF_ERROR:
		SI_LOG_ERR("xz: Unexpected end of input\n");
		break;
	default:
		SI_LOG_ERR("xz: Internal error (bug)\n");
		break;
	}
}

static int xz_uncompress(lzma_stream *strm, elf_file_t *ef)
{
	uint8_t in_buf[BUFSIZ], out_buf[BUFSIZ];
	lzma_action action = LZMA_RUN;
	lzma_ret ret;
	void *p = NULL;
	size_t total = 0;

	strm->avail_in  = 0;
	strm->next_out  = out_buf;
	strm->avail_out = sizeof(out_buf);

	while (true) {
		if (strm->avail_in == 0) {
			ssize_t rdret = read(ef->fd, in_buf, sizeof(in_buf));
			if (rdret < 0) {
				ret = -errno;
				goto out;
			}
			strm->next_in  = in_buf;
			strm->avail_in = rdret;
			if (rdret == 0)
				action = LZMA_FINISH;
		}
		ret = lzma_code(strm, action);
		if (strm->avail_out == 0 || ret != LZMA_OK) {
			size_t write_size = BUFSIZ - strm->avail_out;
			char *tmp = realloc(p, total + write_size);
			if (tmp == NULL) {
				ret = -errno;
				goto out;
			}
			memcpy(tmp + total, out_buf, write_size);
			total += write_size;
			p = tmp;
			strm->next_out = out_buf;
			strm->avail_out = BUFSIZ;
		}
		if (ret == LZMA_STREAM_END)
			break;
		if (ret != LZMA_OK) {
			xz_uncompress_log_err(ret);
			ret = -EINVAL;
			goto out;
		}
	}
	ef->hdr = p;
	ef->length = total;
	return 0;
 out:
	free(p);
	return ret;
}

int elf_load_xz(elf_file_t *ef)
{
	lzma_stream strm = LZMA_STREAM_INIT;
	lzma_ret lzret;
	int ret;

	lzret = lzma_stream_decoder(&strm, UINT64_MAX, LZMA_CONCATENATED);
	if (lzret == LZMA_MEM_ERROR) {
		SI_LOG_ERR("xz: %s\n", strerror(ENOMEM));
		return -ENOMEM;
	} else if (lzret != LZMA_OK) {
		SI_LOG_ERR("xz: Internal error (bug)\n");
		return -EINVAL;
	}
	ret = xz_uncompress(&strm, ef);
	lzma_end(&strm);
	return ret;
}

void elf_unload_xz(elf_file_t *ef)
{
	if (!ef->hdr)
		return;
	free(ef->hdr);
}

static const char magic_xz[] = {0xfd, '7', 'z', 'X', 'Z', 0};

bool elf_is_xz_file(elf_file_t *ef)
{
	if (memcmp(ef->hdr, magic_xz, sizeof(magic_xz)) != 0) {
		return false;
	}
	return true;
}
