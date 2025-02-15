#ifndef _AIC_LIST_H_
#define _AIC_LIST_H_
#include <stddef.h>
#include "compiler.h"

#define _2offsetof(type, member) ((long) &((type *) 0)->member)
//#define list_for_each_entry(pos, head, member)
//#define list_for_each_entry_safe(pos, n, head, member)

#if 0//!defined(__ICCARM__)
#define container_of(ptr, type, member) ({        \
    const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
    (type *)( (char *)__mptr - _2offsetof(type,member) );})

#define list_entry(ptr, type, member) \
    container_of(ptr, type, member)

#define list_for_each_entry_safe(pos, n, head, member)        \
    for (pos = list_entry((head)->next, typeof(*pos), member),    \
    n = list_entry(pos->member.next, typeof(*pos), member);    \
         &pos->member != (head);             \
         pos = n, n = list_entry(n->member.next, typeof(*n), member))

#define list_for_each_entry(pos, head, member)        \
        for (pos = list_entry((head)->next, typeof(*pos), member);  \
             &pos->member != (head);    \
             pos = list_entry(pos->member.next, typeof(*pos), member))
//#else /////////////////
#endif

#ifndef container_of
#define container_of(ptr, type, member) (        \
    (type *)( (char *)(ptr) - _2offsetof(type,member) ))
#endif

#ifdef PLATFORM_ALLWIN_RT_THREAD
#include <aw_list.h>
#else
#define list_entry(ptr, type, member) \
    container_of(ptr, type, member)

/**
 * list_first_entry - get the first element from a list
 * \param    ptr:    the list head to take the element from.
 * \param    type:   the type of the struct this is embedded in.
 * \param    member: the name of the list_struct within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_first_entry(ptr, type, member) \
        list_entry((ptr)->next, type, member)

#define list_next_entry(pos, member) \
    list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_for_each_entry_safe(pos, n, head, member)          \
    for (pos = list_first_entry(head, typeof(*pos), member),    \
        n = list_next_entry(pos, member);                       \
         &pos->member != (head);                              \
         pos = n, n = list_next_entry(n, member))

#define list_for_each_entry(pos, head, member)        \
        for (pos = list_entry((head)->next, rwnx_cmd, member);  \
             &pos->member != (head);    \
             pos = list_entry(pos->member.next, rwnx_cmd, member))

#define list_for_each_entry_continue(pos, head, member)                \
    for (pos = list_next_entry(pos, member);            \
         &pos->member != (head);                    \
         pos = list_next_entry(pos, member))

struct list_head {
    struct list_head *next, *prev;
};

static __INLINE void INIT_LIST_HEAD(struct list_head *list)
{
    list->next = list;
    list->prev = list;
}

static __INLINE void __list_add(struct list_head *new,
              struct list_head *prev,
              struct list_head *next)
{
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}

static __INLINE void list_add_tail(struct list_head *new, struct list_head *head)
{
    __list_add(new, head->prev, head);
}

static __INLINE void list_add(struct list_head *new, struct list_head *head)
{
    __list_add(new, head, head->next);
}

static __INLINE void __list_del(struct list_head * prev, struct list_head * next)
{
    next->prev = prev;
    prev->next = next;
}

static __INLINE void list_del(struct list_head *entry)
{
    __list_del(entry->prev, entry->next);
    entry->next = NULL;
    entry->prev = NULL;
}

static __INLINE int list_empty(const struct list_head *head)
{
    return head->next == head;
}

static __INLINE void list_del_init(struct list_head *entry)
{
    list_del(entry);
    INIT_LIST_HEAD(entry);
}
#endif

#endif /* _AIC_LIST_H_ */
