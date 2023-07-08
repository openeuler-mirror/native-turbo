// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
//
// native-turbo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

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
