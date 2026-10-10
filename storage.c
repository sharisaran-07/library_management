#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include "storage.h"
#include "auth.h"
#include "ds/ds_linkedlist.h"
#include "ds/ds_bst.h"
#include "ds/ds_hashtable.h"
#include "ds/ds_queue.h"
#include "ds/ds_stack.h"
#include "ds/ds_heap.h"

AppState g_state;

static char* read_file_to_string(const char* filepath) {
    FILE* f = fopen(filepath, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len < 0) { fclose(f); return NULL; }

    char* buffer = (char*)malloc(len + 1);
    if (!buffer) { fclose(f); return NULL; }
    size_t read_bytes = fread(buffer, 1, len, f);
    buffer[read_bytes] = '\0';
    fclose(f);
    return buffer;
}

static int write_string_to_file(const char* filepath, const char* str) {
    FILE* f = fopen(filepath, "wb");
    if (!f) return 0;
    size_t len = strlen(str);
    size_t written = fwrite(str, 1, len, f);
    fclose(f);
    return (written == len);
}

void storage_init(void) {
    memset(&g_state, 0, sizeof(AppState));
    book_list_init(&g_state.books);
    g_state.book_bst = NULL;
    member_ht_init(&g_state.members, 64);
    session_ht_init(&g_state.sessions, 128);
    stack_init(&g_state.undo_stack);
    heap_init(&g_state.overdue_heap, 128);

    /* Default settings */
    snprintf(g_state.settings.library_name, sizeof(g_state.settings.library_name), "Metropolitan Central Library");
    g_state.settings.loan_period_days = 14;
    g_state.settings.fine_rate_per_day = 1.00;
    g_state.settings.max_books_per_member = 5;
    g_state.settings.renewal_limit = 2;
    g_state.settings.two_factor_admin_enabled = 0;
    snprintf(g_state.settings.theme, sizeof(g_state.settings.theme), "dark");

    #if defined(_WIN32)
    mkdir("data");
    #else
    mkdir("data", 0755);
    #endif
}

void rebuild_overdue_heap(void) {
    heap_free(&g_state.overdue_heap);
    heap_init(&g_state.overdue_heap, 128);

    time_t now = time(NULL);
    for (int i = 0; i < g_state.issue_count; i++) {
        IssueRecord* issue = &g_state.issues[i];
        if (issue->status == ISSUE_ACTIVE) {
            HeapItem item;
            memset(&item, 0, sizeof(HeapItem));
            snprintf(item.issue_id, sizeof(item.issue_id), "%s", issue->id);
            snprintf(item.book_id, sizeof(item.book_id), "%s", issue->book_id);
            snprintf(item.book_title, sizeof(item.book_title), "%s", issue->book_title);
            snprintf(item.member_id, sizeof(item.member_id), "%s", issue->member_id);
            snprintf(item.member_name, sizeof(item.member_name), "%s", issue->member_name);
            item.due_date = issue->due_date;

            if (now > issue->due_date) {
                int seconds_overdue = (int)(now - issue->due_date);
                item.days_overdue = (seconds_overdue / 86400) + 1;
                item.fine_amount = item.days_overdue * g_state.settings.fine_rate_per_day;
                issue->fine_amount = item.fine_amount;
            } else {
                item.days_overdue = 0;
                item.fine_amount = 0.0;
            }

            heap_insert(&g_state.overdue_heap, item);
        }
    }
}

void storage_load_settings(void) {
    char* content = read_file_to_string("data/settings.json");
    if (!content) return;
    cJSON* root = cJSON_Parse(content);
    free(content);
    if (!root) return;

    cJSON* item = cJSON_GetObjectItem(root, "library_name");
    if (item && item->valuestring) snprintf(g_state.settings.library_name, sizeof(g_state.settings.library_name), "%s", item->valuestring);

    item = cJSON_GetObjectItem(root, "loan_period_days");
    if (item) g_state.settings.loan_period_days = item->valueint;

    item = cJSON_GetObjectItem(root, "fine_rate_per_day");
    if (item) g_state.settings.fine_rate_per_day = item->valuedouble;

    item = cJSON_GetObjectItem(root, "max_books_per_member");
    if (item) g_state.settings.max_books_per_member = item->valueint;

    item = cJSON_GetObjectItem(root, "renewal_limit");
    if (item) g_state.settings.renewal_limit = item->valueint;

    item = cJSON_GetObjectItem(root, "two_factor_admin_enabled");
    if (item) g_state.settings.two_factor_admin_enabled = item->valueint;

    item = cJSON_GetObjectItem(root, "theme");
    if (item && item->valuestring) snprintf(g_state.settings.theme, sizeof(g_state.settings.theme), "%s", item->valuestring);

    cJSON_Delete(root);
}

void storage_save_settings(void) {
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "library_name", g_state.settings.library_name);
    cJSON_AddNumberToObject(root, "loan_period_days", g_state.settings.loan_period_days);
    cJSON_AddNumberToObject(root, "fine_rate_per_day", g_state.settings.fine_rate_per_day);
    cJSON_AddNumberToObject(root, "max_books_per_member", g_state.settings.max_books_per_member);
    cJSON_AddNumberToObject(root, "renewal_limit", g_state.settings.renewal_limit);
    cJSON_AddNumberToObject(root, "two_factor_admin_enabled", g_state.settings.two_factor_admin_enabled);
    cJSON_AddStringToObject(root, "theme", g_state.settings.theme);

    char* rendered = cJSON_Print(root);
    if (rendered) {
        write_string_to_file("data/settings.json", rendered);
        free(rendered);
    }
    cJSON_Delete(root);
}

void storage_load_members(void) {
    char* content = read_file_to_string("data/members.json");
    if (!content) {
        /* First run: Create ONLY default admin account */
        Member admin;
        memset(&admin, 0, sizeof(Member));
        snprintf(admin.id, sizeof(admin.id), "ADM-001");
        snprintf(admin.username, sizeof(admin.username), "admin");
        snprintf(admin.full_name, sizeof(admin.full_name), "System Administrator");
        snprintf(admin.email, sizeof(admin.email), "admin@library.local");
        snprintf(admin.phone, sizeof(admin.phone), "0000000000");
        admin.role = ROLE_ADMIN;
        admin.status = MBR_STATUS_ACTIVE;
        admin.must_change_password = 0;
        admin.two_factor_enabled = 0;
        admin.created_at = time(NULL);

        generate_salt(admin.salt, 16);
        hash_password("AdminPassword123!", admin.salt, admin.password_hash);

        member_ht_insert(&g_state.members, &admin);
        storage_save_members();
        return;
    }

    cJSON* root = cJSON_Parse(content);
    free(content);
    if (!root || !cJSON_IsArray(root)) return;

    int size = cJSON_GetArraySize(root);
    for (int i = 0; i < size; i++) {
        cJSON* obj = cJSON_GetArrayItem(root, i);
        if (!obj) continue;
        Member m;
        memset(&m, 0, sizeof(Member));

        cJSON* it = cJSON_GetObjectItem(obj, "id");
        if (it && it->valuestring) snprintf(m.id, sizeof(m.id), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "username");
        if (it && it->valuestring) snprintf(m.username, sizeof(m.username), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "full_name");
        if (it && it->valuestring) snprintf(m.full_name, sizeof(m.full_name), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "email");
        if (it && it->valuestring) snprintf(m.email, sizeof(m.email), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "phone");
        if (it && it->valuestring) snprintf(m.phone, sizeof(m.phone), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "password_hash");
        if (it && it->valuestring) snprintf(m.password_hash, sizeof(m.password_hash), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "salt");
        if (it && it->valuestring) snprintf(m.salt, sizeof(m.salt), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "role");
        if (it) m.role = (UserRole)it->valueint;

        it = cJSON_GetObjectItem(obj, "status");
        if (it) m.status = (MemberStatus)it->valueint;

        it = cJSON_GetObjectItem(obj, "failed_attempts");
        if (it) m.failed_attempts = it->valueint;

        it = cJSON_GetObjectItem(obj, "lockout_until");
        if (it) m.lockout_until = (time_t)it->valuedouble;

        it = cJSON_GetObjectItem(obj, "must_change_password");
        if (it) m.must_change_password = it->valueint;

        it = cJSON_GetObjectItem(obj, "two_factor_enabled");
        if (it) m.two_factor_enabled = it->valueint;

        it = cJSON_GetObjectItem(obj, "two_factor_secret");
        if (it && it->valuestring) snprintf(m.two_factor_secret, sizeof(m.two_factor_secret), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "created_at");
        if (it) m.created_at = (time_t)it->valuedouble;

        member_ht_insert(&g_state.members, &m);
    }
    cJSON_Delete(root);
}

void storage_save_members(void) {
    cJSON* root = cJSON_CreateArray();
    int count = 0;
    Member** list = member_ht_to_array(&g_state.members, &count);
    if (list) {
        for (int i = 0; i < count; i++) {
            Member* m = list[i];
            cJSON* obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "id", m->id);
            cJSON_AddStringToObject(obj, "username", m->username);
            cJSON_AddStringToObject(obj, "full_name", m->full_name);
            cJSON_AddStringToObject(obj, "email", m->email);
            cJSON_AddStringToObject(obj, "phone", m->phone);
            cJSON_AddStringToObject(obj, "password_hash", m->password_hash);
            cJSON_AddStringToObject(obj, "salt", m->salt);
            cJSON_AddNumberToObject(obj, "role", m->role);
            cJSON_AddNumberToObject(obj, "status", m->status);
            cJSON_AddNumberToObject(obj, "failed_attempts", m->failed_attempts);
            cJSON_AddNumberToObject(obj, "lockout_until", (double)m->lockout_until);
            cJSON_AddNumberToObject(obj, "must_change_password", m->must_change_password);
            cJSON_AddNumberToObject(obj, "two_factor_enabled", m->two_factor_enabled);
            cJSON_AddStringToObject(obj, "two_factor_secret", m->two_factor_secret);
            cJSON_AddNumberToObject(obj, "created_at", (double)m->created_at);
            cJSON_AddItemToArray(root, obj);
        }
        free(list);
    }

    char* rendered = cJSON_Print(root);
    if (rendered) {
        write_string_to_file("data/members.json", rendered);
        free(rendered);
    }
    cJSON_Delete(root);
}

void storage_load_books(void) {
    char* content = read_file_to_string("data/books.json");
    if (!content) return;
    cJSON* root = cJSON_Parse(content);
    free(content);
    if (!root || !cJSON_IsArray(root)) return;

    int size = cJSON_GetArraySize(root);
    for (int i = 0; i < size; i++) {
        cJSON* obj = cJSON_GetArrayItem(root, i);
        if (!obj) continue;
        Book b;
        memset(&b, 0, sizeof(Book));
        queue_init(&b.waitlist);

        cJSON* it = cJSON_GetObjectItem(obj, "id");
        if (it && it->valuestring) snprintf(b.id, sizeof(b.id), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "isbn");
        if (it && it->valuestring) snprintf(b.isbn, sizeof(b.isbn), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "title");
        if (it && it->valuestring) snprintf(b.title, sizeof(b.title), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "author");
        if (it && it->valuestring) snprintf(b.author, sizeof(b.author), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "category");
        if (it && it->valuestring) snprintf(b.category, sizeof(b.category), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "shelf");
        if (it && it->valuestring) snprintf(b.shelf, sizeof(b.shelf), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "total_copies");
        if (it) b.total_copies = it->valueint;

        it = cJSON_GetObjectItem(obj, "available_copies");
        if (it) b.available_copies = it->valueint;

        it = cJSON_GetObjectItem(obj, "publication_year");
        if (it) b.publication_year = it->valueint;

        it = cJSON_GetObjectItem(obj, "borrow_count");
        if (it) b.borrow_count = it->valueint;

        it = cJSON_GetObjectItem(obj, "cover_url");
        if (it && it->valuestring) snprintf(b.cover_url, sizeof(b.cover_url), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "ebook_url");
        if (it && it->valuestring) snprintf(b.ebook_url, sizeof(b.ebook_url), "%s", it->valuestring);

        /* Waitlist queue loading */
        cJSON* w_arr = cJSON_GetObjectItem(obj, "waitlist");
        if (w_arr && cJSON_IsArray(w_arr)) {
            int w_size = cJSON_GetArraySize(w_arr);
            for (int w = 0; w < w_size; w++) {
                cJSON* w_item = cJSON_GetArrayItem(w_arr, w);
                cJSON* wid = cJSON_GetObjectItem(w_item, "member_id");
                cJSON* wname = cJSON_GetObjectItem(w_item, "member_name");
                if (wid && wid->valuestring) {
                    enqueue(&b.waitlist, wid->valuestring, wname ? wname->valuestring : "");
                }
            }
        }

        BookNode* node = book_list_insert_tail(&g_state.books, &b);
        if (node) {
            bst_insert(&g_state.book_bst, node->book.id, &node->book);
        }
    }
    cJSON_Delete(root);
}

void storage_save_books(void) {
    cJSON* root = cJSON_CreateArray();
    BookNode* curr = g_state.books.head;
    while (curr) {
        cJSON* obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "id", curr->book.id);
        cJSON_AddStringToObject(obj, "isbn", curr->book.isbn);
        cJSON_AddStringToObject(obj, "title", curr->book.title);
        cJSON_AddStringToObject(obj, "author", curr->book.author);
        cJSON_AddStringToObject(obj, "category", curr->book.category);
        cJSON_AddStringToObject(obj, "shelf", curr->book.shelf);
        cJSON_AddNumberToObject(obj, "total_copies", curr->book.total_copies);
        cJSON_AddNumberToObject(obj, "available_copies", curr->book.available_copies);
        cJSON_AddNumberToObject(obj, "publication_year", curr->book.publication_year);
        cJSON_AddNumberToObject(obj, "borrow_count", curr->book.borrow_count);
        cJSON_AddStringToObject(obj, "cover_url", curr->book.cover_url);
        cJSON_AddStringToObject(obj, "ebook_url", curr->book.ebook_url);

        /* Waitlist array */
        cJSON* w_arr = cJSON_CreateArray();
        WaitlistNode* wn = curr->book.waitlist.front;
        while (wn) {
            cJSON* w_item = cJSON_CreateObject();
            cJSON_AddStringToObject(w_item, "member_id", wn->member_id);
            cJSON_AddStringToObject(w_item, "member_name", wn->member_name);
            cJSON_AddNumberToObject(w_item, "requested_at", (double)wn->requested_at);
            cJSON_AddItemToArray(w_arr, w_item);
            wn = wn->next;
        }
        cJSON_AddItemToObject(obj, "waitlist", w_arr);

        cJSON_AddItemToArray(root, obj);
        curr = curr->next;
    }

    char* rendered = cJSON_Print(root);
    if (rendered) {
        write_string_to_file("data/books.json", rendered);
        free(rendered);
    }
    cJSON_Delete(root);
}

void storage_load_issues(void) {
    char* content = read_file_to_string("data/issues.json");
    if (!content) return;
    cJSON* root = cJSON_Parse(content);
    free(content);
    if (!root || !cJSON_IsArray(root)) return;

    g_state.issue_count = 0;
    int size = cJSON_GetArraySize(root);
    if (size > MAX_ISSUES) size = MAX_ISSUES;

    for (int i = 0; i < size; i++) {
        cJSON* obj = cJSON_GetArrayItem(root, i);
        if (!obj) continue;
        IssueRecord* rec = &g_state.issues[g_state.issue_count];
        memset(rec, 0, sizeof(IssueRecord));

        cJSON* it = cJSON_GetObjectItem(obj, "id");
        if (it && it->valuestring) snprintf(rec->id, sizeof(rec->id), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "book_id");
        if (it && it->valuestring) snprintf(rec->book_id, sizeof(rec->book_id), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "book_title");
        if (it && it->valuestring) snprintf(rec->book_title, sizeof(rec->book_title), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "member_id");
        if (it && it->valuestring) snprintf(rec->member_id, sizeof(rec->member_id), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "member_name");
        if (it && it->valuestring) snprintf(rec->member_name, sizeof(rec->member_name), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "issue_date");
        if (it) rec->issue_date = (time_t)it->valuedouble;

        it = cJSON_GetObjectItem(obj, "due_date");
        if (it) rec->due_date = (time_t)it->valuedouble;

        it = cJSON_GetObjectItem(obj, "return_date");
        if (it) rec->return_date = (time_t)it->valuedouble;

        it = cJSON_GetObjectItem(obj, "status");
        if (it) rec->status = (IssueStatus)it->valueint;

        it = cJSON_GetObjectItem(obj, "renewal_count");
        if (it) rec->renewal_count = it->valueint;

        it = cJSON_GetObjectItem(obj, "fine_amount");
        if (it) rec->fine_amount = it->valuedouble;

        it = cJSON_GetObjectItem(obj, "fine_paid");
        if (it) rec->fine_paid = it->valueint;

        it = cJSON_GetObjectItem(obj, "replacement_fee");
        if (it) rec->replacement_fee = it->valuedouble;

        g_state.issue_count++;
    }
    cJSON_Delete(root);
}

void storage_save_issues(void) {
    cJSON* root = cJSON_CreateArray();
    for (int i = 0; i < g_state.issue_count; i++) {
        IssueRecord* rec = &g_state.issues[i];
        cJSON* obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "id", rec->id);
        cJSON_AddStringToObject(obj, "book_id", rec->book_id);
        cJSON_AddStringToObject(obj, "book_title", rec->book_title);
        cJSON_AddStringToObject(obj, "member_id", rec->member_id);
        cJSON_AddStringToObject(obj, "member_name", rec->member_name);
        cJSON_AddNumberToObject(obj, "issue_date", (double)rec->issue_date);
        cJSON_AddNumberToObject(obj, "due_date", (double)rec->due_date);
        cJSON_AddNumberToObject(obj, "return_date", (double)rec->return_date);
        cJSON_AddNumberToObject(obj, "status", rec->status);
        cJSON_AddNumberToObject(obj, "renewal_count", rec->renewal_count);
        cJSON_AddNumberToObject(obj, "fine_amount", rec->fine_amount);
        cJSON_AddNumberToObject(obj, "fine_paid", rec->fine_paid);
        cJSON_AddNumberToObject(obj, "replacement_fee", rec->replacement_fee);
        cJSON_AddItemToArray(root, obj);
    }

    char* rendered = cJSON_Print(root);
    if (rendered) {
        write_string_to_file("data/issues.json", rendered);
        free(rendered);
    }
    cJSON_Delete(root);
}

void storage_load_audit(void) {
    char* content = read_file_to_string("data/audit.json");
    if (!content) return;
    cJSON* root = cJSON_Parse(content);
    free(content);
    if (!root || !cJSON_IsArray(root)) return;

    g_state.audit_count = 0;
    int size = cJSON_GetArraySize(root);
    if (size > MAX_AUDIT_LOGS) size = MAX_AUDIT_LOGS;

    for (int i = 0; i < size; i++) {
        cJSON* obj = cJSON_GetArrayItem(root, i);
        if (!obj) continue;
        AuditLog* a = &g_state.audit_logs[g_state.audit_count];
        memset(a, 0, sizeof(AuditLog));

        cJSON* it = cJSON_GetObjectItem(obj, "id");
        if (it && it->valuestring) snprintf(a->id, sizeof(a->id), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "timestamp");
        if (it) a->timestamp = (time_t)it->valuedouble;

        it = cJSON_GetObjectItem(obj, "username");
        if (it && it->valuestring) snprintf(a->username, sizeof(a->username), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "role");
        if (it) a->role = (UserRole)it->valueint;

        it = cJSON_GetObjectItem(obj, "action");
        if (it && it->valuestring) snprintf(a->action, sizeof(a->action), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "details");
        if (it && it->valuestring) snprintf(a->details, sizeof(a->details), "%s", it->valuestring);

        g_state.audit_count++;
    }
    cJSON_Delete(root);
}

void storage_save_audit(void) {
    cJSON* root = cJSON_CreateArray();
    for (int i = 0; i < g_state.audit_count; i++) {
        AuditLog* a = &g_state.audit_logs[i];
        cJSON* obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "id", a->id);
        cJSON_AddNumberToObject(obj, "timestamp", (double)a->timestamp);
        cJSON_AddStringToObject(obj, "username", a->username);
        cJSON_AddNumberToObject(obj, "role", a->role);
        cJSON_AddStringToObject(obj, "action", a->action);
        cJSON_AddStringToObject(obj, "details", a->details);
        cJSON_AddItemToArray(root, obj);
    }

    char* rendered = cJSON_Print(root);
    if (rendered) {
        write_string_to_file("data/audit.json", rendered);
        free(rendered);
    }
    cJSON_Delete(root);
}

void add_audit_log(const char* username, UserRole role, const char* action, const char* details) {
    if (g_state.audit_count >= MAX_AUDIT_LOGS) {
        /* Shift left to keep recent logs */
        memmove(&g_state.audit_logs[0], &g_state.audit_logs[1], sizeof(AuditLog) * (MAX_AUDIT_LOGS - 1));
        g_state.audit_count = MAX_AUDIT_LOGS - 1;
    }

    AuditLog* log = &g_state.audit_logs[g_state.audit_count++];
    memset(log, 0, sizeof(AuditLog));
    snprintf(log->id, sizeof(log->id), "LOG-%ld-%d", (long)time(NULL), rand() % 1000);
    log->timestamp = time(NULL);
    snprintf(log->username, sizeof(log->username), "%s", username ? username : "system");
    log->role = role;
    snprintf(log->action, sizeof(log->action), "%s", action ? action : "");
    snprintf(log->details, sizeof(log->details), "%s", details ? details : "");

    storage_save_audit();
}

void storage_load_gate(void) {
    char* content = read_file_to_string("data/gate.json");
    if (!content) return;
    cJSON* root = cJSON_Parse(content);
    free(content);
    if (!root || !cJSON_IsArray(root)) return;

    g_state.gate_count = 0;
    int size = cJSON_GetArraySize(root);
    if (size > MAX_GATE_ENTRIES) size = MAX_GATE_ENTRIES;

    for (int i = 0; i < size; i++) {
        cJSON* obj = cJSON_GetArrayItem(root, i);
        if (!obj) continue;
        GateEntry* ge = &g_state.gate_entries[g_state.gate_count];
        memset(ge, 0, sizeof(GateEntry));

        cJSON* it = cJSON_GetObjectItem(obj, "id");
        if (it && it->valuestring) snprintf(ge->id, sizeof(ge->id), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "member_id");
        if (it && it->valuestring) snprintf(ge->member_id, sizeof(ge->member_id), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "member_name");
        if (it && it->valuestring) snprintf(ge->member_name, sizeof(ge->member_name), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "entry_time");
        if (it) ge->entry_time = (time_t)it->valuedouble;

        it = cJSON_GetObjectItem(obj, "exit_time");
        if (it) ge->exit_time = (time_t)it->valuedouble;

        it = cJSON_GetObjectItem(obj, "is_inside");
        if (it) ge->is_inside = it->valueint;

        it = cJSON_GetObjectItem(obj, "duration_minutes");
        if (it) ge->duration_minutes = it->valueint;

        g_state.gate_count++;
    }
    cJSON_Delete(root);
}

void storage_save_gate(void) {
    cJSON* root = cJSON_CreateArray();
    for (int i = 0; i < g_state.gate_count; i++) {
        GateEntry* ge = &g_state.gate_entries[i];
        cJSON* obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "id", ge->id);
        cJSON_AddStringToObject(obj, "member_id", ge->member_id);
        cJSON_AddStringToObject(obj, "member_name", ge->member_name);
        cJSON_AddNumberToObject(obj, "entry_time", (double)ge->entry_time);
        cJSON_AddNumberToObject(obj, "exit_time", (double)ge->exit_time);
        cJSON_AddNumberToObject(obj, "is_inside", ge->is_inside);
        cJSON_AddNumberToObject(obj, "duration_minutes", ge->duration_minutes);
        cJSON_AddItemToArray(root, obj);
    }

    char* rendered = cJSON_Print(root);
    if (rendered) {
        write_string_to_file("data/gate.json", rendered);
        free(rendered);
    }
    cJSON_Delete(root);
}

void storage_load_requests(void) {
    char* content = read_file_to_string("data/requests.json");
    if (!content) return;
    cJSON* root = cJSON_Parse(content);
    free(content);
    if (!root || !cJSON_IsArray(root)) return;

    g_state.request_count = 0;
    int size = cJSON_GetArraySize(root);
    if (size > MAX_REQUESTS) size = MAX_REQUESTS;

    for (int i = 0; i < size; i++) {
        cJSON* obj = cJSON_GetArrayItem(root, i);
        if (!obj) continue;
        BookRequest* req = &g_state.requests[g_state.request_count];
        memset(req, 0, sizeof(BookRequest));

        cJSON* it = cJSON_GetObjectItem(obj, "id");
        if (it && it->valuestring) snprintf(req->id, sizeof(req->id), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "member_id");
        if (it && it->valuestring) snprintf(req->member_id, sizeof(req->member_id), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "member_name");
        if (it && it->valuestring) snprintf(req->member_name, sizeof(req->member_name), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "title");
        if (it && it->valuestring) snprintf(req->title, sizeof(req->title), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "author");
        if (it && it->valuestring) snprintf(req->author, sizeof(req->author), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "notes");
        if (it && it->valuestring) snprintf(req->notes, sizeof(req->notes), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "status");
        if (it && it->valuestring) snprintf(req->status, sizeof(req->status), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "created_at");
        if (it) req->created_at = (time_t)it->valuedouble;

        g_state.request_count++;
    }
    cJSON_Delete(root);
}

void storage_save_requests(void) {
    cJSON* root = cJSON_CreateArray();
    for (int i = 0; i < g_state.request_count; i++) {
        BookRequest* req = &g_state.requests[i];
        cJSON* obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "id", req->id);
        cJSON_AddStringToObject(obj, "member_id", req->member_id);
        cJSON_AddStringToObject(obj, "member_name", req->member_name);
        cJSON_AddStringToObject(obj, "title", req->title);
        cJSON_AddStringToObject(obj, "author", req->author);
        cJSON_AddStringToObject(obj, "notes", req->notes);
        cJSON_AddStringToObject(obj, "status", req->status);
        cJSON_AddNumberToObject(obj, "created_at", (double)req->created_at);
        cJSON_AddItemToArray(root, obj);
    }

    char* rendered = cJSON_Print(root);
    if (rendered) {
        write_string_to_file("data/requests.json", rendered);
        free(rendered);
    }
    cJSON_Delete(root);
}

void storage_load_announcements(void) {
    char* content = read_file_to_string("data/announcements.json");
    if (!content) return;
    cJSON* root = cJSON_Parse(content);
    free(content);
    if (!root || !cJSON_IsArray(root)) return;

    g_state.announcement_count = 0;
    int size = cJSON_GetArraySize(root);
    if (size > MAX_ANNOUNCEMENTS) size = MAX_ANNOUNCEMENTS;

    for (int i = 0; i < size; i++) {
        cJSON* obj = cJSON_GetArrayItem(root, i);
        if (!obj) continue;
        Announcement* a = &g_state.announcements[g_state.announcement_count];
        memset(a, 0, sizeof(Announcement));

        cJSON* it = cJSON_GetObjectItem(obj, "id");
        if (it && it->valuestring) snprintf(a->id, sizeof(a->id), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "title");
        if (it && it->valuestring) snprintf(a->title, sizeof(a->title), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "message");
        if (it && it->valuestring) snprintf(a->message, sizeof(a->message), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "author");
        if (it && it->valuestring) snprintf(a->author, sizeof(a->author), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "created_at");
        if (it) a->created_at = (time_t)it->valuedouble;

        g_state.announcement_count++;
    }
    cJSON_Delete(root);
}

void storage_save_announcements(void) {
    cJSON* root = cJSON_CreateArray();
    for (int i = 0; i < g_state.announcement_count; i++) {
        Announcement* a = &g_state.announcements[i];
        cJSON* obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "id", a->id);
        cJSON_AddStringToObject(obj, "title", a->title);
        cJSON_AddStringToObject(obj, "message", a->message);
        cJSON_AddStringToObject(obj, "author", a->author);
        cJSON_AddNumberToObject(obj, "created_at", (double)a->created_at);
        cJSON_AddItemToArray(root, obj);
    }

    char* rendered = cJSON_Print(root);
    if (rendered) {
        write_string_to_file("data/announcements.json", rendered);
        free(rendered);
    }
    cJSON_Delete(root);
}

void storage_load_login_history(void) {
    char* content = read_file_to_string("data/login_history.json");
    if (!content) return;
    cJSON* root = cJSON_Parse(content);
    free(content);
    if (!root || !cJSON_IsArray(root)) return;

    g_state.login_history_count = 0;
    int size = cJSON_GetArraySize(root);
    if (size > MAX_LOGIN_HISTORY) size = MAX_LOGIN_HISTORY;

    for (int i = 0; i < size; i++) {
        cJSON* obj = cJSON_GetArrayItem(root, i);
        if (!obj) continue;
        LoginHistory* lh = &g_state.login_history[g_state.login_history_count];
        memset(lh, 0, sizeof(LoginHistory));

        cJSON* it = cJSON_GetObjectItem(obj, "id");
        if (it && it->valuestring) snprintf(lh->id, sizeof(lh->id), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "username");
        if (it && it->valuestring) snprintf(lh->username, sizeof(lh->username), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "device");
        if (it && it->valuestring) snprintf(lh->device, sizeof(lh->device), "%s", it->valuestring);

        it = cJSON_GetObjectItem(obj, "timestamp");
        if (it) lh->timestamp = (time_t)it->valuedouble;

        it = cJSON_GetObjectItem(obj, "success");
        if (it) lh->success = it->valueint;

        g_state.login_history_count++;
    }
    cJSON_Delete(root);
}

void storage_save_login_history(void) {
    cJSON* root = cJSON_CreateArray();
    for (int i = 0; i < g_state.login_history_count; i++) {
        LoginHistory* lh = &g_state.login_history[i];
        cJSON* obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "id", lh->id);
        cJSON_AddStringToObject(obj, "username", lh->username);
        cJSON_AddStringToObject(obj, "device", lh->device);
        cJSON_AddNumberToObject(obj, "timestamp", (double)lh->timestamp);
        cJSON_AddNumberToObject(obj, "success", lh->success);
        cJSON_AddItemToArray(root, obj);
    }

    char* rendered = cJSON_Print(root);
    if (rendered) {
        write_string_to_file("data/login_history.json", rendered);
        free(rendered);
    }
    cJSON_Delete(root);
}

void add_login_history(const char* username, const char* device, int success) {
    if (g_state.login_history_count >= MAX_LOGIN_HISTORY) {
        memmove(&g_state.login_history[0], &g_state.login_history[1], sizeof(LoginHistory) * (MAX_LOGIN_HISTORY - 1));
        g_state.login_history_count = MAX_LOGIN_HISTORY - 1;
    }

    LoginHistory* lh = &g_state.login_history[g_state.login_history_count++];
    memset(lh, 0, sizeof(LoginHistory));
    snprintf(lh->id, sizeof(lh->id), "LH-%ld-%d", (long)time(NULL), rand() % 1000);
    snprintf(lh->username, sizeof(lh->username), "%s", username ? username : "unknown");
    snprintf(lh->device, sizeof(lh->device), "%s", device ? device : "Unknown Browser");
    lh->timestamp = time(NULL);
    lh->success = success;

    storage_save_login_history();
}

void storage_load_all(void) {
    storage_load_settings();
    storage_load_members();
    storage_load_books();
    storage_load_issues();
    storage_load_audit();
    storage_load_gate();
    storage_load_requests();
    storage_load_announcements();
    storage_load_login_history();

    rebuild_overdue_heap();
}

void storage_save_all(void) {
    storage_save_settings();
    storage_save_members();
    storage_save_books();
    storage_save_issues();
    storage_save_audit();
    storage_save_gate();
    storage_save_requests();
    storage_save_announcements();
    storage_save_login_history();
}

char* storage_export_backup_json(void) {
    cJSON* root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "exported_at", (double)time(NULL));

    /* Attach files directly or serialized state */
    char* b = read_file_to_string("data/books.json");
    if (b) { cJSON* j = cJSON_Parse(b); free(b); if (j) cJSON_AddItemToObject(root, "books", j); }

    char* m = read_file_to_string("data/members.json");
    if (m) { cJSON* j = cJSON_Parse(m); free(m); if (j) cJSON_AddItemToObject(root, "members", j); }

    char* is = read_file_to_string("data/issues.json");
    if (is) { cJSON* j = cJSON_Parse(is); free(is); if (j) cJSON_AddItemToObject(root, "issues", j); }

    char* s = read_file_to_string("data/settings.json");
    if (s) { cJSON* j = cJSON_Parse(s); free(s); if (j) cJSON_AddItemToObject(root, "settings", j); }

    char* a = read_file_to_string("data/audit.json");
    if (a) { cJSON* j = cJSON_Parse(a); free(a); if (j) cJSON_AddItemToObject(root, "audit", j); }

    char* g = read_file_to_string("data/gate.json");
    if (g) { cJSON* j = cJSON_Parse(g); free(g); if (j) cJSON_AddItemToObject(root, "gate", j); }

    char* req = read_file_to_string("data/requests.json");
    if (req) { cJSON* j = cJSON_Parse(req); free(req); if (j) cJSON_AddItemToObject(root, "requests", j); }

    char* ann = read_file_to_string("data/announcements.json");
    if (ann) { cJSON* j = cJSON_Parse(ann); free(ann); if (j) cJSON_AddItemToObject(root, "announcements", j); }

    char* str = cJSON_Print(root);
    cJSON_Delete(root);
    return str;
}

int storage_import_backup_json(const char* json_str) {
    if (!json_str) return 0;
    cJSON* root = cJSON_Parse(json_str);
    if (!root) return 0;

    cJSON* item = cJSON_GetObjectItem(root, "books");
    if (item) { char* s = cJSON_Print(item); write_string_to_file("data/books.json", s); free(s); }

    item = cJSON_GetObjectItem(root, "members");
    if (item) { char* s = cJSON_Print(item); write_string_to_file("data/members.json", s); free(s); }

    item = cJSON_GetObjectItem(root, "issues");
    if (item) { char* s = cJSON_Print(item); write_string_to_file("data/issues.json", s); free(s); }

    item = cJSON_GetObjectItem(root, "settings");
    if (item) { char* s = cJSON_Print(item); write_string_to_file("data/settings.json", s); free(s); }

    item = cJSON_GetObjectItem(root, "audit");
    if (item) { char* s = cJSON_Print(item); write_string_to_file("data/audit.json", s); free(s); }

    item = cJSON_GetObjectItem(root, "gate");
    if (item) { char* s = cJSON_Print(item); write_string_to_file("data/gate.json", s); free(s); }

    item = cJSON_GetObjectItem(root, "requests");
    if (item) { char* s = cJSON_Print(item); write_string_to_file("data/requests.json", s); free(s); }

    item = cJSON_GetObjectItem(root, "announcements");
    if (item) { char* s = cJSON_Print(item); write_string_to_file("data/announcements.json", s); free(s); }

    cJSON_Delete(root);

    /* Reload everything in memory */
    book_list_free(&g_state.books);
    bst_free(g_state.book_bst);
    g_state.book_bst = NULL;
    member_ht_free(&g_state.members);
    member_ht_init(&g_state.members, 64);

    storage_load_all();
    return 1;
}
