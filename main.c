#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "storage.h"
#include "server.h"
#include "ds/ds_bst.h"
#include "ds/ds_heap.h"

int main(int argc, char* argv[]) {
    srand((unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)&argc);
    int port = 8080;
    if (argc > 1) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) port = 8080;
    }

    printf("=================================================================\n");
    printf("   LIBRARY MANAGEMENT SYSTEM - DATA STRUCTURES MICRO PROJECT    \n");
    printf("=================================================================\n");
    printf("Initializing Data Structures in C...\n");

    storage_init();
    storage_load_all();

    printf("  [OK] Doubly Linked List : Book records loaded (%d books)\n", g_state.books.count);
    printf("  [OK] Binary Search Tree : Barcode/ID indexing active (BST size: %d)\n", bst_size(g_state.book_bst));
    printf("  [OK] Hash Table Chaining: Member accounts (%d) & session tokens\n", g_state.members.count);
    printf("  [OK] FIFO Queues        : Waitlists per book active\n");
    printf("  [OK] LIFO Stack         : Undo history stack initialized\n");
    printf("  [OK] Min-Heap PQ        : Overdue & due-soon priority queue (%d items)\n", heap_size(&g_state.overdue_heap));
    printf("  [OK] Sorting Algorithms : Merge Sort & Quick Sort ready\n");
    printf("  [OK] Persistence Layer  : File storage active in data/ directory\n");
    printf("-----------------------------------------------------------------\n");
    printf("Default Administrator credentials created on first run:\n");
    printf("  Role     : Administrator\n");
    printf("  Username : admin\n");
    printf("  Password : AdminPassword123!\n");
    printf("-----------------------------------------------------------------\n");

    server_start(port);
    return 0;
}
