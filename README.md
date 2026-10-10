# Library Management System (Data Structures Micro Project)

A complete, production-grade Library Management System implemented in pure C for core data structures and logic, featuring an integrated high-performance Winsock2 HTTP server and a modern, responsive web user interface.

Runs end-to-end with **one build/run command**.

---

## Data Structures Implemented in C

All core business logic operates on fundamental data structures implemented from scratch in C:

1. **Doubly Linked List** (`src/ds/ds_linkedlist.c`, `src/ds/ds_linkedlist.h`)
   - Holds master book records in memory with bidirectional navigation (`prev` and `next` pointers).
   - Allows O(1) insertions at head or tail and deletions without contiguous array shifting.

2. **Hash Table with Chaining** (`src/ds/ds_hashtable.c`, `src/ds/ds_hashtable.h`)
   - O(1) average lookup for member accounts (keyed by Member ID and Username) using the `djb2` polynomial hashing algorithm.
   - Separate chaining collision resolution using linked list buckets.
   - Manages active cryptographic session tokens for role-based authorization on every route.

3. **Binary Search Tree (BST)** (`src/ds/ds_bst.c`, `src/ds/ds_bst.h`)
   - Indexes all books by Barcode / Book ID for rapid O(log N) lookup during physical barcode scanning and checkout.
   - Synchronized with the Doubly Linked List on additions and deletions.

4. **FIFO Queue** (`src/ds/ds_queue.c`, `src/ds/ds_queue.h`)
   - Manages waitlists per book. When zero copies are available, members join the FIFO queue.
   - When a copy is returned, the next member in line is automatically dequeued and assigned.

5. **LIFO Stack** (`src/ds/ds_stack.c`, `src/ds/ds_stack.h`)
   - Tracks recent librarian actions (issue, return, add book, edit).
   - Popping from the stack reverts the last action to its previous state with full rollback support.

6. **Min-Heap (Priority Queue)** (`src/ds/ds_heap.c`, `src/ds/ds_heap.h`)
   - Organizes overdue and due-soon circulation records.
   - The root of the min-heap always contains the earliest due date (most overdue book first), powering automated fine alerts.

7. **Merge Sort & Quick Sort** (`src/ds/ds_sort.c`, `src/ds/ds_sort.h`)
   - Dynamic catalog sorting by Title, Author, Year, or Popularity (borrow count).
   - Implemented in C with algorithm selection and execution benchmark timings in microseconds returned directly to the UI.

8. **File Persistence** (`src/storage.c`, `src/storage.h`)
   - Persists all states to `data/*.json` so data survives system restarts.

---

## One-Click Build and Run

### Windows Command Prompt / Batch
Double-click `run.bat` or run:
```cmd
run.bat
```

### Windows PowerShell
```powershell
.\run.ps1
```

### Standard Make (MinGW)
```bash
make run
```

The script automatically detects GCC (checks PATH, CodeBlocks, or MSYS64), compiles and executes the unit test suite (`bin/test_ds.exe`), compiles the HTTP server (`bin/server.exe`), starts the server on port `8080`, and opens your default browser to `http://localhost:8080/login.html`.

---

## Default Administrator Credentials

As required, exactly **one default admin account** is created on first launch:

- **Username**: `admin`
- **Password**: `AdminPassword123!`
- **Role**: `Administrator`
- **Member ID**: `ADM-001`

*(All passwords are cryptographically salted and hashed using SHA-256).*

---

## Roles and Access Control

| Role | Default Dashboard | Key Capabilities |
|---|---|---|
| **Administrator** | `/admin.html` | User management, approve member self-registrations, set library rules (fine rate, loan period, max books), view audit logs, one-click backup and restore. |
| **Librarian** | `/librarian.html` | Catalog management, multi-book issue sessions, return processing with automatic waitlist assignment, overdue min-heap viewer, undo stack, barcode label printing. |
| **Member** | `/member.html` | Search catalog with Merge/Quick Sort, view active loans, renew books, join waitlist queues, view personalized recommendations based on past borrowing, check reading stats, view library ID card. |
| **Gate / Security** | `/gate.html` | Scan member barcode once to log ENTRY, scan again to log EXIT (with duration calculated), live "Currently Inside" roster and count. |

---

## Verification & Full Test Workflow

1. **Verify Data Structures**: Run `bin/test_ds.exe` to see all 28 automated C test assertions pass.
2. **Log in as Administrator**:
   - Navigate to `http://localhost:8080/login.html`.
   - Select the **Admin** tab. Enter `admin` / `AdminPassword123!`.
   - Go to **User Management** &rarr; **Add User Account** to create a Librarian (`librarian` / `LibPass123!`) and a Member (`john` / `Member123!`).
3. **Test Member Self-Registration & Approval**:
   - On the login page, click **Register here** to submit a new member registration.
   - In the Admin portal under **Pending Approvals**, click **Approve**.
4. **Test Librarian Circulation & Scanning**:
   - Log in as `librarian`.
   - Under **Book Catalog**, click **+ Add New Book** to add a book (e.g., `Algorithms in C`).
   - Under **Issue & Return**, enter the Member ID, scan the book barcode, and click **Confirm Issue**.
   - Process a return: scan the book barcode to see automatic overdue fine calculation and waitlist auto-assignment.
   - Click **Undo Last Action** to pop from the LIFO Stack and revert the operation.
5. **Test Min-Heap Overdue Alerts**:
   - Open **Overdue Alerts** to view records extracted in priority order (most overdue at root).
6. **Test Gate / Security Kiosk**:
   - Log in as `gate` (or create a Gate user under Admin).
   - Enter/scan a Member ID: shows green **ENTRY RECORDED** (+1 inside count).
   - Scan the same Member ID again: shows blue **EXIT RECORDED** with duration spent inside (-1 inside count).
7. **Test Backup & Restore**:
   - In Admin, click **Download System Backup** to download the JSON archive.
   - Test restoring using **Restore From File**.

---

## Project Folder Structure

```
ds-micro project/
├── bin/                    # Compiled binaries (server.exe, test_ds.exe)
├── data/                   # File persistence storage (JSON databases)
├── src/
│   ├── main.c              # Server entry point & startup diagnostics
│   ├── server.c / .h       # Multi-threaded Winsock2 HTTP server
│   ├── http.c / .h         # HTTP request parser & static file server
│   ├── api.c / .h          # REST API routing & business logic
│   ├── auth.c / .h         # SHA-256 hashing, salting, lockout & sessions
│   ├── storage.c / .h      # JSON file persistence, backup & restore
│   ├── cJSON.c / .h        # ANSI C JSON library
│   ├── models.h            # Domain models & enum definitions
│   └── ds/
│       ├── ds_linkedlist.c / .h  # Doubly linked list (books)
│       ├── ds_hashtable.c / .h   # Hash table with chaining (members, sessions)
│       ├── ds_bst.c / .h         # Binary search tree (barcode lookup)
│       ├── ds_queue.c / .h       # FIFO queue (waitlist per book)
│       ├── ds_stack.c / .h       # LIFO stack (undo actions)
│       ├── ds_heap.c / .h        # Min-heap priority queue (overdue alerts)
│       └── ds_sort.c / .h        # Merge sort & Quick sort algorithms
├── web/
│   ├── index.html          # Redirect to login
│   ├── login.html          # Standalone centered login page
│   ├── admin.html          # Administrator dashboard
│   ├── librarian.html      # Librarian portal
│   ├── member.html         # Member self-service portal
│   ├── gate.html           # Gate / Security kiosk
│   ├── css/
│   │   ├── styles.css      # Design system, dark/light themes, responsiveness
│   │   └── print.css       # Barcode label sheet print styles
│   └── js/
│       ├── app.js          # Client utilities, theme, session timeout, modals
│       ├── scanner.js      # USB hardware & camera barcode scanner
│       ├── login.js        # Login controller, 2FA, lockout timer
│       ├── admin.js        # Admin controller (metrics, users, rules)
│       ├── librarian.js    # Librarian controller (catalog, circulation, undo)
│       ├── member.js       # Member controller (catalog sort, loans, stats)
│       └── gate.js         # Gate controller (entry/exit, live roster)
├── test/
│   └── test_ds.c           # Comprehensive unit test suite in C
├── Makefile                # MinGW Makefile
├── run.bat                 # One-click Windows CMD runner
├── run.ps1                 # One-click PowerShell runner
└── README.md               # Project documentation
```
