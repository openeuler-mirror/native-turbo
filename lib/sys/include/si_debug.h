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

#ifndef _SI_DEBUG_H
#define _SI_DEBUG_H

// format must end with \n, force printf send to console
#define si_panic(...) si_panic_(__func__, __VA_ARGS__, "dummy")
#define si_panic_(func, format, ...) __si_panic(func, format, __VA_ARGS__)

void __si_panic(const char *funcname, const char *format, ...);

#endif /* _SI_DEBUG_H */
