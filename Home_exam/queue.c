#include "queue.h" //queue,node
#include <stdio.h>
#include <stdlib.h>

Queue *create_queue()
{
    Queue *queue = (Queue *)malloc(sizeof(Queue));
    if (queue == NULL)
    {
        perror("queue");
        return NULL;
    }
    queue->head = NULL;
    queue->tail = NULL;
    return queue;
}

int enqueue(Queue *queue, void *data)
{
    if (queue == NULL)
    {
        perror("queue doesn't exist");
        return -1;
    }
    Node *node = (Node *)malloc(sizeof(Node));
    if (node == NULL)
    {
        perror("malloc failed for node");
        return -1;
    }
    node->data = data;
    node->next = NULL;
    if (queue != NULL && queue->head != NULL)
    {
        // queue has atleast one element
        // append the new node to the tail
        // then move the tail and point it to the newly added node
        queue->tail->next = node;
        queue->tail = node;
    }
    if (queue != NULL && queue->tail == NULL && queue->head == NULL)
    {
        // queue is empty
        queue->tail = node;
        queue->head = node;
    }

    return 0;
}

// deque returns the data from the head of the queue
// res is passed to store the data from the queue (memory for the res should be allocated in the calling process)
int dequeue(Queue *queue, int *res)
{
    Node *temp;
    if (queue == NULL)
    {
        perror("queue doesn't exist");
        *res = -1;
        return -1;
    }
    if (queue->head == NULL)
    {
        perror("queue doesn't have any elements");
        *res = -1;
        return -1;
    }
    int data = *(int *)queue->head->data;
    *res = data;

    // move the head to the next element and free the node pointed by the head
    temp = queue->head;
    queue->head = queue->head->next;
    if (queue->head == NULL)
    {
        // when the last element is deleted adjust the tail pointer
        queue->tail = NULL;
    }
    free(temp);
    return 0;
}

int print_elements(Queue *queue)
{

    if (queue == NULL || queue->head == NULL)
    {
        perror("queue is empty");
        return -1;
    }
    Node *node = queue->head;
    printf("elements are : ");
    while (node != NULL)
    {
        printf("%d \t", *(int *)node->data);
        node = node->next;
    }
    printf("\n");
    return 0;
}

void destroy_queue(Queue *queue)
{
    Node *temp;
    if (queue != NULL && queue->head != NULL)
    {
        temp = queue->head;
        for (; temp != NULL;)
        {
            queue->head = temp->next;
            free(temp);
            temp = queue->head;
        }
    }
    free(queue);
    printf("\n queue destroyed successfully");
}