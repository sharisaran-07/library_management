#ifndef STORAGE_H
#define STORAGE_H

#include "models.h"
#include "cJSON.h"

#define MAX_ISSUES 1024
#define MAX_AUDIT_LOGS 2048
#define MAX_GATE_ENTRIES 1024
#define MAX_REQUESTS 512
#define MAX_ANNOUNCEMENTS 128
#define MAX_LOGIN_HISTORY 1024

typedef struct {
    BookList books;
    BSTNode* book_bst;              /* Barcode/ID fast lookup tree */
    MemberHashTable members;
    SessionHashTable sessions;
    ActionStack undo_stack;
    MinHeap overdue_heap;           /* Overdue / Due-Soon priority queue */
    SystemSettings settings;
    
    IssueRecord issues[MAX_ISSUES];
    int issue_count;

    AuditLog audit_logs[MAX_AUDIT_LOGS];
    int audit_count;

    GateEntry gate_entries[MAX_GATE_ENTRIES];
    int gate_count;

    BookRequest requests[MAX_REQUESTS];
    int request_count;

    Announcement announcements[MAX_ANNOUNCEMENTS];
    int announcement_count;

    LoginHistory login_history[MAX_LOGIN_HISTORY];
    int login_history_count;
} AppState;

extern AppState g_state;

void storage_init(void);
void storage_load_all(void);
void storage_save_all(void);

void storage_save_books(void);
void storage_load_books(void);

void storage_save_members(void);
void storage_load_members(void);

void storage_save_issues(void);
void storage_load_issues(void);

void storage_save_settings(void);
void storage_load_settings(void);

void storage_save_audit(void);
void storage_load_audit(void);

void storage_save_gate(void);
void storage_load_gate(void);

void storage_save_requests(void);
void storage_load_requests(void);

void storage_save_announcements(void);
void storage_load_announcements(void);

void storage_save_login_history(void);
void storage_load_login_history(void);

void add_audit_log(const char* username, UserRole role, const char* action, const char* details);
void add_login_history(const char* username, const char* device, int success);

/* Heap rebuild from active issues */
void rebuild_overdue_heap(void);

/* Backup and Restore */
char* storage_export_backup_json(void);
int storage_import_backup_json(const char* json_str);

#endif
