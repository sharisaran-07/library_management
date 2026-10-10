#ifndef MODELS_H
#define MODELS_H

#include <time.h>

#define MAX_ID_LEN 32
#define MAX_NAME_LEN 128
#define MAX_STR_LEN 256
#define MAX_TEXT_LEN 512
#define HASH_SALT_LEN 32
#define TOKEN_LEN 64

typedef enum {
    ROLE_ADMIN = 0,
    ROLE_LIBRARIAN = 1,
    ROLE_MEMBER = 2,
    ROLE_GATE = 3
} UserRole;

typedef enum {
    MBR_STATUS_ACTIVE = 0,
    MBR_STATUS_PENDING = 1,
    MBR_STATUS_DEACTIVATED = 2
} MemberStatus;

typedef enum {
    ISSUE_ACTIVE = 0,
    ISSUE_RETURNED = 1,
    ISSUE_LOST = 2
} IssueStatus;

typedef enum {
    ACTION_NONE = 0,
    ACTION_ISSUE = 1,
    ACTION_RETURN = 2,
    ACTION_RENEW = 3,
    ACTION_ADD_BOOK = 4,
    ACTION_EDIT_BOOK = 5,
    ACTION_DELETE_BOOK = 6,
    ACTION_PAY_FINE = 7,
    ACTION_LOST_BOOK = 8
} ActionType;

/* FIFO Queue Node for Waitlist */
typedef struct WaitlistNode {
    char member_id[MAX_ID_LEN];
    char member_name[MAX_NAME_LEN];
    time_t requested_at;
    struct WaitlistNode* next;
} WaitlistNode;

typedef struct {
    WaitlistNode* front;
    WaitlistNode* rear;
    int size;
} WaitlistQueue;

/* Book structure */
typedef struct Book {
    char id[MAX_ID_LEN];            /* Primary key and Barcode string, e.g. BK-1001 */
    char isbn[MAX_ID_LEN];
    char title[MAX_NAME_LEN];
    char author[MAX_NAME_LEN];
    char category[MAX_NAME_LEN];
    char shelf[MAX_ID_LEN];
    int total_copies;
    int available_copies;
    int publication_year;
    int borrow_count;
    char cover_url[MAX_STR_LEN];
    char ebook_url[MAX_TEXT_LEN];   /* Free digital copy / open online textbook URL */
    WaitlistQueue waitlist;         /* FIFO Queue */
} Book;

/* Doubly Linked List Node for Books */
typedef struct BookNode {
    Book book;
    struct BookNode* prev;
    struct BookNode* next;
} BookNode;

typedef struct {
    BookNode* head;
    BookNode* tail;
    int count;
} BookList;

/* BST Node for Book Lookup by ID/Barcode */
typedef struct BSTNode {
    char key[MAX_ID_LEN];           /* Book ID / barcode */
    Book* book_ref;                 /* Points directly to Book in Doubly Linked List */
    struct BSTNode* left;
    struct BSTNode* right;
} BSTNode;

/* Member structure */
typedef struct Member {
    char id[MAX_ID_LEN];            /* Member ID and Barcode, e.g. MEM-101 */
    char username[MAX_ID_LEN];
    char full_name[MAX_NAME_LEN];
    char email[MAX_STR_LEN];
    char phone[MAX_ID_LEN];
    char password_hash[128];
    char salt[HASH_SALT_LEN];
    UserRole role;
    MemberStatus status;
    int failed_attempts;
    time_t lockout_until;
    int must_change_password;
    int two_factor_enabled;
    char two_factor_secret[16];
    time_t created_at;
} Member;

/* Hash Table Node for Member (Separate Chaining) */
typedef struct MemberHashNode {
    Member member;
    struct MemberHashNode* next;
} MemberHashNode;

typedef struct {
    MemberHashNode** buckets;
    int capacity;
    int count;
} MemberHashTable;

/* Session structure */
typedef struct Session {
    char token[TOKEN_LEN];
    char user_id[MAX_ID_LEN];
    char username[MAX_ID_LEN];
    UserRole role;
    char device[MAX_STR_LEN];
    time_t created_at;
    time_t expires_at;
} Session;

/* Hash Table Node for Sessions */
typedef struct SessionHashNode {
    Session session;
    struct SessionHashNode* next;
} SessionHashNode;

typedef struct {
    SessionHashNode** buckets;
    int capacity;
    int count;
} SessionHashTable;

/* Issue Record */
typedef struct IssueRecord {
    char id[MAX_ID_LEN];
    char book_id[MAX_ID_LEN];
    char book_title[MAX_NAME_LEN];
    char member_id[MAX_ID_LEN];
    char member_name[MAX_NAME_LEN];
    time_t issue_date;
    time_t due_date;
    time_t return_date;
    IssueStatus status;
    int renewal_count;
    double fine_amount;
    int fine_paid;                  /* 1 = paid, 0 = unpaid */
    double replacement_fee;
} IssueRecord;

/* Action Record for LIFO Undo Stack */
typedef struct ActionRecord {
    ActionType type;
    char action_name[64];
    char target_id[MAX_ID_LEN];     /* Book ID, Issue ID, or Member ID */
    char member_id[MAX_ID_LEN];
    time_t timestamp;
    char performed_by[MAX_ID_LEN];
    char snapshot_data[1024];       /* Saved JSON state for reversing */
} ActionRecord;

/* Stack Node */
typedef struct ActionStackNode {
    ActionRecord record;
    struct ActionStackNode* next;
} ActionStackNode;

typedef struct {
    ActionStackNode* top;
    int count;
} ActionStack;

/* Min-Heap Element for Overdue / Due-Soon alerts */
typedef struct {
    char issue_id[MAX_ID_LEN];
    char book_id[MAX_ID_LEN];
    char book_title[MAX_NAME_LEN];
    char member_id[MAX_ID_LEN];
    char member_name[MAX_NAME_LEN];
    time_t due_date;                /* Heap key: lowest value = most overdue */
    int days_overdue;
    double fine_amount;
} HeapItem;

typedef struct {
    HeapItem* items;
    int capacity;
    int size;
} MinHeap;

/* System Settings */
typedef struct {
    char library_name[MAX_NAME_LEN];
    int loan_period_days;
    double fine_rate_per_day;
    int max_books_per_member;
    int renewal_limit;
    int two_factor_admin_enabled;
    char theme[16];
} SystemSettings;

/* Audit Log */
typedef struct {
    char id[MAX_ID_LEN];
    time_t timestamp;
    char username[MAX_ID_LEN];
    UserRole role;
    char action[64];
    char details[MAX_TEXT_LEN];
} AuditLog;

/* Gate Entry/Exit */
typedef struct {
    char id[MAX_ID_LEN];
    char member_id[MAX_ID_LEN];
    char member_name[MAX_NAME_LEN];
    time_t entry_time;
    time_t exit_time;
    int is_inside;                  /* 1 = inside, 0 = exited */
    int duration_minutes;
} GateEntry;

/* Book Request / Feedback */
typedef struct {
    char id[MAX_ID_LEN];
    char member_id[MAX_ID_LEN];
    char member_name[MAX_NAME_LEN];
    char title[MAX_NAME_LEN];
    char author[MAX_NAME_LEN];
    char notes[MAX_TEXT_LEN];
    char status[32];                /* PENDING, APPROVED, REJECTED */
    time_t created_at;
} BookRequest;

/* Announcement */
typedef struct {
    char id[MAX_ID_LEN];
    char title[MAX_NAME_LEN];
    char message[MAX_TEXT_LEN];
    char author[MAX_NAME_LEN];
    time_t created_at;
} Announcement;

/* Login History */
typedef struct {
    char id[MAX_ID_LEN];
    char username[MAX_ID_LEN];
    time_t timestamp;
    char device[MAX_STR_LEN];
    int success;
} LoginHistory;

#endif
