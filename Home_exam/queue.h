//
// Created by praveen on 9/29/21.
//

#ifndef QUEUE_H
#define QUEUE_H
#include <stdio.h>
#include <stdlib.h> //free, malloc
typedef struct Node
{
    struct Node *next;
    void *data;
} Node;

typedef struct Queue
{
    Node *head;
    Node *tail;
} Queue;

// creates new queue and with no element
Queue *create_queue();

// adds new element to the queue and adjusts the tail after adding the new element
int enqueue(Queue *queue, void *data);

// removes the first element from the queue and adjusts the head
int dequeue(Queue *queue, int *res);

// iterate through head and prints the element
int print_elements(Queue *queue);

// iterates through head and frees the node ( frees the queue struct in the end as well)
void destroy_queue(Queue *queue);

#endif // QUEUE_H