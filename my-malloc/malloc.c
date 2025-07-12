
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <stdint.h>
#include <string.h>

#define ALIGNMENT 16
typedef char ALIGN[ALIGNMENT];


//+++++++++++++++++++++++++++++++++++++++++
//+++++++++++   THREAD SAFETY +++++++++++++
//+++++++++++++++++++++++++++++++++++++++++
static CRITICAL_SECTION global_malloc_lock; 
static int lock_initialized = 0; 

void init_allocator_lock(){
    if (!lock_initialized){
        InitializeCriticalSection(&global_malloc_lock);
        lock_initialized = 1; 
    }
}





//+++++++++++++++++++++++++++++++++++++++++
//+++++++++++++ MEMORY BLOCK ++++++++++++++
//+++++++++++++++++++++++++++++++++++++++++

// a new type called header_t that is always at least 16 bytes :D
typedef union header{
    struct{
        size_t size;
        unsigned is_free;
        union header* next; 
    }s;
    ALIGN stub;
} header_t; 

static header_t* head = NULL, *tail = NULL;

header_t* get_free_block(size_t size){
    header_t* curr = head; 
    while (curr){
        // if the current block is 1) free AND 2) the size is at least as big as we want. Then allocate 
        if (curr->s.is_free && curr->s.size >= size)
            return curr;
        curr = curr->s.next; // keep mooving to the next block
    }
    return NULL; // found no space
}

void* request_memory_from_os(size_t size){
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

//+++++++++++++++++++++++++++++++++++++++++
//+++++++++++  MALLOC HEADERS +++++++++++++
//+++++++++++++++++++++++++++++++++++++++++

void* malloc(size_t size){
    size_t total_size;
    void* block; // this is a raw pointer that is returned by the OS (VirtualAlloc)
    header_t* header; // pointer to our metadata header 

    if (!size) return NULL; // if malloc(0), return NULL

    init_allocator_lock();
    EnterCriticalSection(&global_malloc_lock);

    header = get_free_block(size);
    if (header){ // if we find a spot,
        header->s.is_free = 0;
        LeaveCriticalSection(&global_malloc_lock);
        
        // header is a pointer to the start of the header
        // sizeof(header) points to the  start of that
        // header + 1 is litteraly the beginning of the actual data (block)
        // (void *) cast to a void pointer, so the user can assign any pointer to it.
        return (void*)(header+1); 
    }
     
    total_size = sizeof(header_t) + size;
    block = request_memory_from_os(total_size);
    if (block == NULL){
        LeaveCriticalSection(&global_malloc_lock);
        return NULL;
    }

    header = (header_t*)block;
    header->s.size = size;
    header->s.is_free = 0;
    header->s.next = NULL;

    if (!head) head = header;
    if (tail) tail->s.next = header;
    tail = header;

    LeaveCriticalSection(&global_malloc_lock);
    return (void*)(header + 1);
}


void free(void* block){
    if (!block) return;
    init_allocator_lock();
    EnterCriticalSection(&global_malloc_lock);

    header_t* header = (header_t*) block - 1;
    header->s.is_free = 1;

    if (header == tail){
        if (head == tail) {head = tail = NULL;}
        else{
            header_t* tmp = head;
            while (tmp->s.next && tmp->s.next != tail){
                tmp = tmp->s.next;
            }
            tmp->s.next = NULL;
            tail = tmp;
        }
        VirtualFree(header, 0, MEM_RELEASE);
    }
    LeaveCriticalSection(&global_malloc_lock);
}

// calloc is utilized to initialize to 0 Num elements, each of size Nsize
void * calloc(size_t num, size_t nsize){
    if (!num || !nsize) return NULL;
    size_t size = num *nsize;

    if (nsize != size / num) return NULL;

    void* block = malloc(size);
    if (!block) return NULL;
    memset(block, 0, size); 
    return block;
}

void* realloc(void* block, size_t size){
    if (!block) return malloc(size);
    if (!size){
        free(block);
        return NULL;
    }

    header_t* header = (header_t*)block-1;
    if (header->s.size >= size)
        return block;
    void* new_block = malloc(size);
    if (!new_block) return NULL;

    memcpy(new_block, block, header->s.size);
    free(block);
    return new_block;
}

int main() {
    char* ptr = (char*)malloc(100);
    strcpy(ptr, "Custom malloc is working on Windows!");
    printf("%s\n", ptr);
    return 0;
}
