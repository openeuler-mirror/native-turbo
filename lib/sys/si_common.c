/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "si_common.h"

// basename will change string, si_basename do not change string
const char *si_basename(const char *path)
{
	// find last / to get basename
	const char *bname = rindex(path, '/');
	if (bname == NULL) {
		bname = path;
	} else {
		bname = bname + 1;
	}

	return bname;
}
