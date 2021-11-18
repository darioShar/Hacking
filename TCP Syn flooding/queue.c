#include "queue.h"
#include <stdlib.h>
#include <assert.h>

int queue_is_allocated = 0;
node* queue_actual_node = NULL;


void delete_queue_from_node(node* n) {
    while (n) {
        free(n->buf);
        node* prev = n->prev;
        free(n);
        n = prev;
    }
}

int initialize_nodes(int buffer_size) {
    queue_actual_size = 0;

    node* prev = NULL;
    queue_actual_node = malloc(sizeof(node));

    while (queue_actual_size < queue_max_size && queue_actual_node != NULL) {
        queue_actual_node->prev = prev;
        queue_actual_node->buf = malloc(buffer_size);
        if (queue_actual_node->buf == NULL) {
            delete_queue_from_node(prev);
            free(queue_actual_node);
            queue_actual_node = NULL;
            queue_actual_size = 0;
            queue_is_allocated = 0;
            return -1;
        }
        prev = queue_actual_node;
        queue_actual_size++;
        queue_actual_node->next = malloc(sizeof(node));
        queue_actual_node = queue_actual_node->next;
    }
    queue_actual_node->prev = prev;
    queue_actual_node->buf = malloc(buffer_size);
    queue_is_allocated = 1;
    return 0;
}

/* returns 0 if succesful, else -1 */
int create_queue_buffer(int queue_size, int buffer_size) {
    if (queue_is_allocated)
        free_queue_buffer();
    
    queue_max_size = queue_size;
    return initialize_nodes(buffer_size);
}

/* returns 0 if successful, -1 otherwise*/
int enqueue_buffer(node* n) {
    if (queue_actual_size < queue_max_size) {
        queue_actual_size++;
        queue_actual_node->next = n;
        n->prev = queue_actual_node;
        queue_actual_node = n;
        return 0;
    }
    
    return -1;
}

/* return NULL if error */
node* dequeue_buffer() {
    if (queue_actual_size == 0)
        return NULL;
    node* n = queue_actual_node;
    queue_actual_node = queue_actual_node->prev;
    queue_actual_size--;
    return n;
}

/* Attention : all nodes must be present when freeing queue */
void free_queue_buffer() {
    assert(queue_actual_size == queue_max_size && queue_is_allocated);
    delete_queue_from_node(queue_actual_node);
    queue_is_allocated = 0;
    queue_actual_size = 0;
    queue_actual_node = NULL;
}