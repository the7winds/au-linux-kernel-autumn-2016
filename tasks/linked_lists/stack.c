#include "stack.h"

#include <linux/gfp.h>
#include <linux/slab.h>

stack_entry_t* create_stack_entry(void *data)
{
    stack_entry_t* entry = kmalloc(sizeof(stack_entry_t), GFP_KERNEL);
    if (entry != NULL) {
        entry->data = data;
    }
    return entry;
}

void delete_stack_entry(stack_entry_t *entry)
{
    kfree(entry);
}

void stack_push(struct list_head *stack, stack_entry_t *entry)
{
    list_add(&entry->lh, stack);
}

stack_entry_t* stack_pop(struct list_head *stack)
{
    struct list_head* top = stack->next;
    list_del(top);
    return (stack_entry_t*) top;
}
