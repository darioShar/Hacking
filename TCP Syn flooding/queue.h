#ifndef QUEUE_H
#define QUEUE_H

// File for queues of buffer. Only one round of malloc to avoid memory fragmentation

typedef struct node{
    void* buf;
    void* next;
    void* prev;
} node;

int queue_max_size;
int queue_actual_size;
node* queue_actual_node;

int queue_is_allocated;

/* returns 0 if succesful, else -1 */
int create_queue_buffer(int queue_size, int buffer_size);

/* returns 0 if successful, -1 otherwise*/
int enqueue_buffer(node* n);

/* return NULL if error */
node* dequeue_buffer();

void free_queue_buffer();

#endif