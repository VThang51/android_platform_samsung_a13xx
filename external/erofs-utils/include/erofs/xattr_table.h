/**
 * @file xattr_table.h
 * @brief
 * @author Egor Uleyskiy (e.uleyskiy@samsung.com)
 * @version 0.1
 * @date Created 6 14, 2016
 * @par In Samsung Ukraine R&D Center (SRK) under a contract between
 * @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine) and
 * @par "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
 * @par Copyright: (c) Samsung Electronics Co, Ltd 2016. All rights reserved.
**/

#ifndef XATTR_TABLE_H
#define XATTR_TABLE_H

#include <stddef.h>
#include <stdint.h>

#define XATTR_TABLE_ITEM_MAX_LEN 600
#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_PROCA
void *xattr_table_open(const char *file_path);
int xattr_table_add(void *table, const char *filepath, const char *name, const void *data, size_t len);
int xattr_table_setup(void *table, const char *filepath, unsigned int *index, char *kvbuf, unsigned int len[2]);
void xattr_table_close(void *table);
#else
static inline void *xattr_table_open(const char *file_path)
{
    (void)file_path;
    return NULL;
}

static inline int xattr_table_add(void *table, const char *filepath, const char *name, const void *data, size_t len)
{
    (void)table;
    (void)filepath;
    (void)name;
    (void)data;
    (void)len;
    return 0;
}

int xattr_table_setup(void *table, const char *filepath, unsigned int *index, char *kvbuf, unsigned int len[2])
{
    (void)table;
    (void)filepath;
    (void)index;
    (void)kvbuf;
    (void)len;
    return 0;
}

static inline void xattr_table_close(void *table)
{
    (void)table;
}
#endif  // CONFIG_PROCA

#ifdef __cplusplus
}
#endif

#endif // XATTR_TABLE_H
