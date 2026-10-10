#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "api.h"
#include "storage.h"
#include "auth.h"
#include "cJSON.h"
#include "ds/ds_linkedlist.h"
#include "ds/ds_bst.h"
#include "ds/ds_hashtable.h"
#include "ds/ds_queue.h"
#include "ds/ds_stack.h"
#include "ds/ds_heap.h"
#include "ds/ds_sort.h"

static Session* authenticate_request(const HttpRequest* req) {
    if (!req || strlen(req->auth_token) == 0) return NULL;
    return get_session(&g_state.sessions, req->auth_token);
}

static int require_role(const Session* session, UserRole min_role, socket_t sock) {
    if (!session) {
        http_send_error(sock, 401, "Authentication required. Please log in.");
        return 0;
    }
    if (session->role > min_role && min_role != ROLE_GATE) {
        http_send_error(sock, 403, "Access denied. Insufficient permissions.");
        return 0;
    }
    return 1;
}

/* Case-insensitive substring search helper */
static int case_insensitive_contains(const char* haystack, const char* needle) {
    if (!haystack || !needle) return 0;
    if (*needle == '\0') return 1;
    for (; *haystack; haystack++) {
        if (tolower((unsigned char)*haystack) == tolower((unsigned char)*needle)) {
            const char *h = haystack + 1, *n = needle + 1;
            while (*n && tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
                h++;
                n++;
            }
            if (*n == '\0') return 1;
        }
    }
    return 0;
}

/* Parse query param helper */
static int get_query_param(const char* query, const char* key, char* out, int out_len) {
    if (!query || !key || !out) return 0;
    char search_key[128];
    snprintf(search_key, sizeof(search_key), "%s=", key);
    const char* p = strstr(query, search_key);
    if (!p) return 0;
    p += strlen(search_key);
    int i = 0;
    while (*p && *p != '&' && i < out_len - 1) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return 1;
}

/* --- AUTH CONTROLLERS --- */

static void handle_auth_login(socket_t sock, const HttpRequest* req) {
    if (!req->body) {
        http_send_error(sock, 400, "Missing request body");
        return;
    }
    cJSON* json = cJSON_Parse(req->body);
    if (!json) {
        http_send_error(sock, 400, "Invalid JSON");
        return;
    }

    const char* username = cJSON_GetStringValue(cJSON_GetObjectItem(json, "username"));
    const char* password = cJSON_GetStringValue(cJSON_GetObjectItem(json, "password"));
    cJSON* role_item = cJSON_GetObjectItem(json, "role");
    int requested_role = role_item ? role_item->valueint : -1;
    const char* totp = cJSON_GetStringValue(cJSON_GetObjectItem(json, "totp_code"));

    if (!username || !password) {
        cJSON_Delete(json);
        http_send_error(sock, 400, "Username and password are required");
        return;
    }

    /* Lookup member by username in Hash Table */
    Member* m = member_ht_find_by_username(&g_state.members, username);
    if (!m) {
        /* Also try lookup by member ID */
        m = member_ht_find(&g_state.members, username);
    }

    if (!m) {
        add_login_history(username, req->device, 0);
        cJSON_Delete(json);
        http_send_error(sock, 401, "Invalid credentials");
        return;
    }

    /* Check account lockout */
    int remaining_sec = 0;
    if (is_account_locked(m, &remaining_sec)) {
        add_login_history(username, req->device, 0);
        cJSON_Delete(json);
        char lock_msg[256];
        snprintf(lock_msg, sizeof(lock_msg), "Account locked due to 5 failed attempts. Please try again in %d seconds.", remaining_sec);
        http_send_error(sock, 429, lock_msg);
        return;
    }

    /* Check account status */
    if (m->status == MBR_STATUS_PENDING) {
        cJSON_Delete(json);
        http_send_error(sock, 403, "Account registration is pending administrator approval.");
        return;
    }
    if (m->status == MBR_STATUS_DEACTIVATED) {
        cJSON_Delete(json);
        http_send_error(sock, 403, "Account has been deactivated. Please contact administrator.");
        return;
    }

    /* Role verification if role selector provided */
    if (requested_role >= 0 && m->role != requested_role) {
        add_login_history(username, req->device, 0);
        cJSON_Delete(json);
        http_send_error(sock, 403, "Selected role does not match account privileges.");
        return;
    }

    /* Verify password */
    if (!verify_password(password, m->salt, m->password_hash)) {
        record_failed_attempt(m);
        storage_save_members();
        add_login_history(username, req->device, 0);
        cJSON_Delete(json);
        http_send_error(sock, 401, "Invalid credentials");
        return;
    }

    /* 2FA check for Admin if enabled */
    if (m->role == ROLE_ADMIN && g_state.settings.two_factor_admin_enabled) {
        if (!totp || strlen(totp) == 0) {
            cJSON_Delete(json);
            cJSON* resp = cJSON_CreateObject();
            cJSON_AddBoolToObject(resp, "requires_2fa", 1);
            cJSON_AddStringToObject(resp, "message", "Two-step verification code required.");
            char* s = cJSON_Print(resp);
            http_send_json(sock, 200, s);
            free(s);
            cJSON_Delete(resp);
            return;
        }
        /* Verify OTP code: for local simulation, OTP '123456' or member secret match */
        if (strcmp(totp, "123456") != 0 && (strlen(m->two_factor_secret) > 0 && strcmp(totp, m->two_factor_secret) != 0)) {
            add_login_history(username, req->device, 0);
            cJSON_Delete(json);
            http_send_error(sock, 401, "Invalid two-step verification code.");
            return;
        }
    }

    /* Login successful! Reset failed attempts */
    reset_failed_attempts(m);
    storage_save_members();
    add_login_history(username, req->device, 1);

    Session* session = create_session(&g_state.sessions, m, req->device);
    if (!session) {
        cJSON_Delete(json);
        http_send_error(sock, 500, "Failed to create session");
        return;
    }

    add_audit_log(m->username, m->role, "USER_LOGIN", "User logged in successfully");

    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "token", session->token);
    cJSON_AddStringToObject(resp, "user_id", m->id);
    cJSON_AddStringToObject(resp, "username", m->username);
    cJSON_AddStringToObject(resp, "full_name", m->full_name);
    cJSON_AddNumberToObject(resp, "role", m->role);
    cJSON_AddBoolToObject(resp, "must_change_password", m->must_change_password);

    char* s = cJSON_Print(resp);
    http_send_json(sock, 200, s);
    free(s);
    cJSON_Delete(resp);
    cJSON_Delete(json);
}

static void handle_auth_scan_login(socket_t sock, const HttpRequest* req) {
    if (!req->body) {
        http_send_error(sock, 400, "Missing request body");
        return;
    }
    cJSON* json = cJSON_Parse(req->body);
    if (!json) {
        http_send_error(sock, 400, "Invalid JSON");
        return;
    }

    const char* barcode = cJSON_GetStringValue(cJSON_GetObjectItem(json, "barcode"));
    if (!barcode || strlen(barcode) == 0) {
        cJSON_Delete(json);
        http_send_error(sock, 400, "Barcode or ID is required");
        return;
    }

    /* Lookup member by ID in Hash Table */
    Member* m = member_ht_find(&g_state.members, barcode);
    if (!m) {
        /* Also try username */
        m = member_ht_find_by_username(&g_state.members, barcode);
    }

    if (!m) {
        cJSON_Delete(json);
        http_send_error(sock, 404, "Member card not recognized");
        return;
    }

    if (m->status != MBR_STATUS_ACTIVE) {
        cJSON_Delete(json);
        http_send_error(sock, 403, "Member account is not active");
        return;
    }

    Session* session = create_session(&g_state.sessions, m, req->device);
    add_login_history(m->username, req->device, 1);
    add_audit_log(m->username, m->role, "SCAN_LOGIN", "Member logged in via card scan");

    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "token", session->token);
    cJSON_AddStringToObject(resp, "user_id", m->id);
    cJSON_AddStringToObject(resp, "username", m->username);
    cJSON_AddStringToObject(resp, "full_name", m->full_name);
    cJSON_AddNumberToObject(resp, "role", m->role);
    cJSON_AddBoolToObject(resp, "must_change_password", m->must_change_password);

    char* s = cJSON_Print(resp);
    http_send_json(sock, 200, s);
    free(s);
    cJSON_Delete(resp);
    cJSON_Delete(json);
}

static void handle_auth_register(socket_t sock, const HttpRequest* req, Session* session) {
    if (!req->body) {
        http_send_error(sock, 400, "Missing request body");
        return;
    }
    cJSON* json = cJSON_Parse(req->body);
    if (!json) {
        http_send_error(sock, 400, "Invalid JSON");
        return;
    }

    const char* raw_username = cJSON_GetStringValue(cJSON_GetObjectItem(json, "username"));
    const char* password = cJSON_GetStringValue(cJSON_GetObjectItem(json, "password"));
    const char* raw_full_name = cJSON_GetStringValue(cJSON_GetObjectItem(json, "full_name"));
    const char* raw_email = cJSON_GetStringValue(cJSON_GetObjectItem(json, "email"));
    const char* raw_phone = cJSON_GetStringValue(cJSON_GetObjectItem(json, "phone"));
    cJSON* role_item = cJSON_GetObjectItem(json, "role");

    if (!raw_username || !password || !raw_full_name || strlen(raw_username) == 0 || strlen(password) == 0) {
        cJSON_Delete(json);
        http_send_error(sock, 400, "Username, password, and full name are required");
        return;
    }

    /* Trim leading & trailing whitespace */
    char username[MAX_ID_LEN];
    snprintf(username, sizeof(username), "%s", raw_username);
    char* u_start = username;
    while (*u_start == ' ' || *u_start == '\t') u_start++;
    char* u_end = u_start + strlen(u_start) - 1;
    while (u_end >= u_start && (*u_end == ' ' || *u_end == '\t' || *u_end == '\r' || *u_end == '\n')) *u_end-- = '\0';

    if (strlen(u_start) == 0) {
        cJSON_Delete(json);
        http_send_error(sock, 400, "Valid username is required");
        return;
    }

    /* Check uniqueness */
    if (member_ht_find_by_username(&g_state.members, u_start) != NULL) {
        cJSON_Delete(json);
        http_send_error(sock, 400, "Username already registered");
        return;
    }

    Member m;
    memset(&m, 0, sizeof(Member));
    static int s_mbr_seq = 1;
    do {
        snprintf(m.id, sizeof(m.id), "MEM-%ld-%02d", (long)time(NULL) % 10000, (s_mbr_seq++) % 100);
    } while (member_ht_find(&g_state.members, m.id) != NULL);
    snprintf(m.username, sizeof(m.username), "%s", u_start);
    snprintf(m.full_name, sizeof(m.full_name), "%s", raw_full_name);
    snprintf(m.email, sizeof(m.email), "%s", raw_email ? raw_email : "");
    snprintf(m.phone, sizeof(m.phone), "%s", raw_phone ? raw_phone : "");

    /* If created by an authenticated Admin, use specified role and auto-activate */
    if (session && session->role == ROLE_ADMIN) {
        m.role = role_item ? (UserRole)role_item->valueint : ROLE_MEMBER;
        m.status = MBR_STATUS_ACTIVE;
    } else {
        /* Member self-registration: set to Member and activate immediately for seamless login */
        m.role = ROLE_MEMBER;
        m.status = MBR_STATUS_ACTIVE;
    }

    m.must_change_password = 0;
    m.created_at = time(NULL);

    generate_salt(m.salt, 16);
    hash_password(password, m.salt, m.password_hash);

    member_ht_insert(&g_state.members, &m);
    storage_save_members();

    const char* action_name = (session && session->role == ROLE_ADMIN) ? "CREATE_USER" : "SELF_REGISTER";
    add_audit_log(m.username, m.role, action_name, "Member registration completed successfully");

    cJSON_Delete(json);
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", 1);
    cJSON_AddStringToObject(resp, "user_id", m.id);
    cJSON_AddStringToObject(resp, "username", m.username);
    cJSON_AddStringToObject(resp, "message", "Registration successful! You can now log in with your credentials.");
    char* s = cJSON_Print(resp);
    http_send_json(sock, 201, s);
    free(s);
    cJSON_Delete(resp);
}

static void handle_auth_forgot_password(socket_t sock, const HttpRequest* req) {
    if (!req->body) {
        http_send_error(sock, 400, "Missing request body");
        return;
    }
    cJSON* json = cJSON_Parse(req->body);
    if (!json) {
        http_send_error(sock, 400, "Invalid JSON");
        return;
    }

    const char* username = cJSON_GetStringValue(cJSON_GetObjectItem(json, "username"));
    if (!username) {
        cJSON_Delete(json);
        http_send_error(sock, 400, "Username or Member ID is required");
        return;
    }

    Member* m = member_ht_find_by_username(&g_state.members, username);
    if (!m) m = member_ht_find(&g_state.members, username);

    if (m) {
        /* Record password reset request in audit log & request list */
        char detail[256];
        snprintf(detail, sizeof(detail), "Password reset requested for member %s (%s)", m->full_name, m->id);
        add_audit_log(m->username, m->role, "PASSWORD_RESET_REQ", detail);
    }

    cJSON_Delete(json);
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", 1);
    cJSON_AddStringToObject(resp, "message", "Password reset request submitted. Please contact library administration or wait for admin approval.");
    char* s = cJSON_Print(resp);
    http_send_json(sock, 200, s);
    free(s);
    cJSON_Delete(resp);
}

static void handle_auth_change_password(socket_t sock, const HttpRequest* req, Session* session) {
    if (!session) {
        http_send_error(sock, 401, "Unauthorized");
        return;
    }
    if (!req->body) {
        http_send_error(sock, 400, "Missing request body");
        return;
    }
    cJSON* json = cJSON_Parse(req->body);
    if (!json) {
        http_send_error(sock, 400, "Invalid JSON");
        return;
    }

    const char* old_pass = cJSON_GetStringValue(cJSON_GetObjectItem(json, "old_password"));
    const char* new_pass = cJSON_GetStringValue(cJSON_GetObjectItem(json, "new_password"));

    if (!new_pass || strlen(new_pass) < 6) {
        cJSON_Delete(json);
        http_send_error(sock, 400, "New password must be at least 6 characters");
        return;
    }

    Member* m = member_ht_find(&g_state.members, session->user_id);
    if (!m) {
        cJSON_Delete(json);
        http_send_error(sock, 404, "User not found");
        return;
    }

    /* Verify old password if must_change_password is 0 */
    if (!m->must_change_password) {
        if (!old_pass || !verify_password(old_pass, m->salt, m->password_hash)) {
            cJSON_Delete(json);
            http_send_error(sock, 400, "Current password is incorrect");
            return;
        }
    }

    generate_salt(m->salt, 16);
    hash_password(new_pass, m->salt, m->password_hash);
    m->must_change_password = 0;
    storage_save_members();

    add_audit_log(session->username, session->role, "PASSWORD_CHANGED", "Password updated successfully");

    cJSON_Delete(json);
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", 1);
    cJSON_AddStringToObject(resp, "message", "Password changed successfully");
    char* s = cJSON_Print(resp);
    http_send_json(sock, 200, s);
    free(s);
    cJSON_Delete(resp);
}

static void handle_auth_me(socket_t sock, Session* session) {
    if (!session) {
        http_send_error(sock, 401, "Not logged in");
        return;
    }
    Member* m = member_ht_find(&g_state.members, session->user_id);
    if (!m) {
        http_send_error(sock, 404, "User not found");
        return;
    }

    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "user_id", m->id);
    cJSON_AddStringToObject(resp, "username", m->username);
    cJSON_AddStringToObject(resp, "full_name", m->full_name);
    cJSON_AddStringToObject(resp, "email", m->email);
    cJSON_AddStringToObject(resp, "phone", m->phone);
    cJSON_AddNumberToObject(resp, "role", m->role);
    cJSON_AddNumberToObject(resp, "status", m->status);
    cJSON_AddBoolToObject(resp, "must_change_password", m->must_change_password);
    cJSON_AddBoolToObject(resp, "two_factor_enabled", m->two_factor_enabled);
    cJSON_AddStringToObject(resp, "library_name", g_state.settings.library_name);
    cJSON_AddStringToObject(resp, "theme", g_state.settings.theme);

    char* s = cJSON_Print(resp);
    http_send_json(sock, 200, s);
    free(s);
    cJSON_Delete(resp);
}

static void handle_auth_logout(socket_t sock, const HttpRequest* req, Session* session) {
    if (session) {
        add_audit_log(session->username, session->role, "LOGOUT", "User logged out");
        destroy_session(&g_state.sessions, req->auth_token);
    }
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", 1);
    char* s = cJSON_Print(resp);
    http_send_json(sock, 200, s);
    free(s);
    cJSON_Delete(resp);
}

static void handle_auth_logout_all(socket_t sock, Session* session) {
    if (session) {
        destroy_all_user_sessions(&g_state.sessions, session->user_id);
        add_audit_log(session->username, session->role, "LOGOUT_ALL", "User logged out from all devices");
    }
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", 1);
    char* s = cJSON_Print(resp);
    http_send_json(sock, 200, s);
    free(s);
    cJSON_Delete(resp);
}

/* --- BOOKS CATALOG CONTROLLERS --- */

static void handle_get_books(socket_t sock, const HttpRequest* req) {
    char search[128] = {0};
    char category[128] = {0};
    char available_only[32] = {0};
    char sort_by_str[32] = {0};
    char sort_algo_str[32] = {0};
    char sort_order_str[32] = {0};

    get_query_param(req->query, "search", search, sizeof(search));
    get_query_param(req->query, "category", category, sizeof(category));
    get_query_param(req->query, "available", available_only, sizeof(available_only));
    get_query_param(req->query, "sort_by", sort_by_str, sizeof(sort_by_str));
    get_query_param(req->query, "algo", sort_algo_str, sizeof(sort_algo_str));
    get_query_param(req->query, "order", sort_order_str, sizeof(sort_order_str));

    int total_in_list = 0;
    Book** raw_arr = book_list_to_array(&g_state.books, &total_in_list);
    if (!raw_arr && total_in_list > 0) {
        http_send_error(sock, 500, "Memory allocation error");
        return;
    }

    /* Filter books */
    Book** filtered = (Book**)malloc(sizeof(Book*) * (total_in_list > 0 ? total_in_list : 1));
    int match_count = 0;

    for (int i = 0; i < total_in_list; i++) {
        Book* b = raw_arr[i];
        if (strlen(search) > 0) {
            char low_title[MAX_NAME_LEN], low_author[MAX_NAME_LEN], low_isbn[MAX_ID_LEN], low_id[MAX_ID_LEN];
            snprintf(low_title, sizeof(low_title), "%s", b->title);
            snprintf(low_author, sizeof(low_author), "%s", b->author);
            snprintf(low_isbn, sizeof(low_isbn), "%s", b->isbn);
            snprintf(low_id, sizeof(low_id), "%s", b->id);

            /* Case insensitive match */
            if (!case_insensitive_contains(low_title, search) && !case_insensitive_contains(low_author, search) &&
                !case_insensitive_contains(low_isbn, search) && !case_insensitive_contains(low_id, search)) {
                continue;
            }
        }

        if (strlen(category) > 0 && strcasecmp(category, "all") != 0) {
            if (strcasecmp(b->category, category) != 0) {
                continue;
            }
        }

        if (strcmp(available_only, "1") == 0 || strcmp(available_only, "true") == 0) {
            if (b->available_copies <= 0) {
                continue;
            }
        }

        filtered[match_count++] = b;
    }

    if (raw_arr) free(raw_arr);

    /* Determine sorting parameters */
    SortField field = SORT_BY_TITLE;
    if (strcasecmp(sort_by_str, "author") == 0) field = SORT_BY_AUTHOR;
    else if (strcasecmp(sort_by_str, "year") == 0) field = SORT_BY_YEAR;
    else if (strcasecmp(sort_by_str, "popularity") == 0) field = SORT_BY_POPULARITY;

    SortOrder order = SORT_ASC;
    if (strcasecmp(sort_order_str, "desc") == 0) order = SORT_DESC;

    SortAlgorithm algo = ALGO_MERGE_SORT;
    if (strcasecmp(sort_algo_str, "quick") == 0) algo = ALGO_QUICK_SORT;

    /* Execute sorting in C */
    clock_t start_time = clock();
    sort_books(filtered, match_count, field, order, algo);
    clock_t end_time = clock();
    double elapsed_us = ((double)(end_time - start_time) / CLOCKS_PER_SEC) * 1000000.0;

    /* Format JSON response */
    cJSON* root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "total", match_count);
    cJSON_AddStringToObject(root, "sort_algo_used", (algo == ALGO_QUICK_SORT) ? "Quick Sort" : "Merge Sort");
    cJSON_AddNumberToObject(root, "sort_time_us", elapsed_us);

    cJSON* arr = cJSON_CreateArray();
    for (int i = 0; i < match_count; i++) {
        Book* b = filtered[i];
        cJSON* obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "id", b->id);
        cJSON_AddStringToObject(obj, "isbn", b->isbn);
        cJSON_AddStringToObject(obj, "title", b->title);
        cJSON_AddStringToObject(obj, "author", b->author);
        cJSON_AddStringToObject(obj, "category", b->category);
        cJSON_AddStringToObject(obj, "shelf", b->shelf);
        cJSON_AddNumberToObject(obj, "total_copies", b->total_copies);
        cJSON_AddNumberToObject(obj, "available_copies", b->available_copies);
        cJSON_AddNumberToObject(obj, "publication_year", b->publication_year);
        cJSON_AddNumberToObject(obj, "borrow_count", b->borrow_count);
        cJSON_AddStringToObject(obj, "cover_url", b->cover_url);
        cJSON_AddStringToObject(obj, "ebook_url", b->ebook_url);
        cJSON_AddNumberToObject(obj, "waitlist_count", b->waitlist.size);
        cJSON_AddItemToArray(arr, obj);
    }
    cJSON_AddItemToObject(root, "books", arr);

    free(filtered);

    char* rendered = cJSON_Print(root);
    http_send_json(sock, 200, rendered);
    free(rendered);
    cJSON_Delete(root);
}

static void handle_lookup_book_bst(socket_t sock, const HttpRequest* req) {
    char barcode[128] = {0};
    get_query_param(req->query, "barcode", barcode, sizeof(barcode));
    if (strlen(barcode) == 0) {
        get_query_param(req->query, "id", barcode, sizeof(barcode));
    }

    if (strlen(barcode) == 0) {
        http_send_error(sock, 400, "Barcode or book ID required");
        return;
    }

    /* Fast O(log N) lookup in Binary Search Tree */
    Book* b = bst_search(g_state.book_bst, barcode);
    if (!b) {
        /* Fallback linear search in list by ISBN if not found by barcode/id */
        BookNode* curr = g_state.books.head;
        while (curr) {
            if (strcmp(curr->book.isbn, barcode) == 0) {
                b = &curr->book;
                break;
            }
            curr = curr->next;
        }
    }

    if (!b) {
        http_send_error(sock, 404, "Book not found");
        return;
    }

    cJSON* obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "id", b->id);
    cJSON_AddStringToObject(obj, "isbn", b->isbn);
    cJSON_AddStringToObject(obj, "title", b->title);
    cJSON_AddStringToObject(obj, "author", b->author);
    cJSON_AddStringToObject(obj, "category", b->category);
    cJSON_AddStringToObject(obj, "shelf", b->shelf);
    cJSON_AddNumberToObject(obj, "total_copies", b->total_copies);
    cJSON_AddNumberToObject(obj, "available_copies", b->available_copies);
    cJSON_AddNumberToObject(obj, "publication_year", b->publication_year);
    cJSON_AddNumberToObject(obj, "borrow_count", b->borrow_count);
    cJSON_AddStringToObject(obj, "cover_url", b->cover_url);
    cJSON_AddStringToObject(obj, "ebook_url", b->ebook_url);
    cJSON_AddNumberToObject(obj, "waitlist_count", b->waitlist.size);

    char* s = cJSON_Print(obj);
    http_send_json(sock, 200, s);
    free(s);
    cJSON_Delete(obj);
}

static void handle_add_book(socket_t sock, const HttpRequest* req, Session* session) {
    if (!require_role(session, ROLE_LIBRARIAN, sock)) return;
    if (!req->body) { http_send_error(sock, 400, "Missing body"); return; }

    cJSON* json = cJSON_Parse(req->body);
    if (!json) { http_send_error(sock, 400, "Invalid JSON"); return; }

    const char* title = cJSON_GetStringValue(cJSON_GetObjectItem(json, "title"));
    const char* author = cJSON_GetStringValue(cJSON_GetObjectItem(json, "author"));
    const char* category = cJSON_GetStringValue(cJSON_GetObjectItem(json, "category"));
    const char* isbn = cJSON_GetStringValue(cJSON_GetObjectItem(json, "isbn"));
    const char* shelf = cJSON_GetStringValue(cJSON_GetObjectItem(json, "shelf"));
    const char* cover_url = cJSON_GetStringValue(cJSON_GetObjectItem(json, "cover_url"));
    const char* ebook_url = cJSON_GetStringValue(cJSON_GetObjectItem(json, "ebook_url"));
    cJSON* copies_item = cJSON_GetObjectItem(json, "total_copies");
    cJSON* year_item = cJSON_GetObjectItem(json, "publication_year");

    if (!title || !author) {
        cJSON_Delete(json);
        http_send_error(sock, 400, "Title and author are required");
        return;
    }

    Book b;
    memset(&b, 0, sizeof(Book));
    queue_init(&b.waitlist);
    static int s_bk_seq = 1;
    do {
        snprintf(b.id, sizeof(b.id), "BK-%ld-%02d", (long)time(NULL) % 100000, (s_bk_seq++) % 100);
    } while (bst_search(g_state.book_bst, b.id) != NULL);
    snprintf(b.title, sizeof(b.title), "%s", title);
    snprintf(b.author, sizeof(b.author), "%s", author);
    snprintf(b.category, sizeof(b.category), "%s", category ? category : "General");
    snprintf(b.isbn, sizeof(b.isbn), "%s", isbn ? isbn : "");
    snprintf(b.shelf, sizeof(b.shelf), "%s", shelf ? shelf : "A1");
    snprintf(b.cover_url, sizeof(b.cover_url), "%s", cover_url ? cover_url : "");
    snprintf(b.ebook_url, sizeof(b.ebook_url), "%s", ebook_url ? ebook_url : "");
    b.total_copies = copies_item ? copies_item->valueint : 1;
    if (b.total_copies <= 0) b.total_copies = 1;
    b.available_copies = b.total_copies;
    b.publication_year = year_item ? year_item->valueint : 2024;
    b.borrow_count = 0;

    BookNode* node = book_list_insert_tail(&g_state.books, &b);
    if (!node) {
        cJSON_Delete(json);
        http_send_error(sock, 500, "Failed to insert book");
        return;
    }

    /* Insert into BST for O(log N) barcode lookup */
    bst_insert(&g_state.book_bst, node->book.id, &node->book);
    storage_save_books();

    /* Push onto Undo Stack */
    ActionRecord act;
    memset(&act, 0, sizeof(ActionRecord));
    act.type = ACTION_ADD_BOOK;
    snprintf(act.action_name, sizeof(act.action_name), "Added Book: %s", b.title);
    snprintf(act.target_id, sizeof(act.target_id), "%s", b.id);
    snprintf(act.performed_by, sizeof(act.performed_by), "%s", session->username);
    act.timestamp = time(NULL);
    stack_push(&g_state.undo_stack, &act);

    add_audit_log(session->username, session->role, "ADD_BOOK", b.title);

    cJSON_Delete(json);
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", 1);
    cJSON_AddStringToObject(resp, "book_id", b.id);
    cJSON_AddStringToObject(resp, "message", "Book added successfully");
    char* s = cJSON_Print(resp);
    http_send_json(sock, 201, s);
    free(s);
    cJSON_Delete(resp);
}

static void handle_edit_book(socket_t sock, const HttpRequest* req, Session* session) {
    if (!require_role(session, ROLE_LIBRARIAN, sock)) return;
    if (!req->body) { http_send_error(sock, 400, "Missing body"); return; }

    cJSON* json = cJSON_Parse(req->body);
    if (!json) { http_send_error(sock, 400, "Invalid JSON"); return; }

    const char* id = cJSON_GetStringValue(cJSON_GetObjectItem(json, "id"));
    if (!id) { cJSON_Delete(json); http_send_error(sock, 400, "Book ID required"); return; }

    BookNode* node = book_list_find(&g_state.books, id);
    if (!node) { cJSON_Delete(json); http_send_error(sock, 404, "Book not found"); return; }

    /* Snapshot for Undo */
    ActionRecord act;
    memset(&act, 0, sizeof(ActionRecord));
    act.type = ACTION_EDIT_BOOK;
    snprintf(act.action_name, sizeof(act.action_name), "Edited Book: %s", node->book.title);
    snprintf(act.target_id, sizeof(act.target_id), "%s", node->book.id);
    snprintf(act.performed_by, sizeof(act.performed_by), "%s", session->username);
    act.timestamp = time(NULL);

    cJSON* snap = cJSON_CreateObject();
    cJSON_AddStringToObject(snap, "title", node->book.title);
    cJSON_AddStringToObject(snap, "author", node->book.author);
    cJSON_AddStringToObject(snap, "category", node->book.category);
    cJSON_AddStringToObject(snap, "shelf", node->book.shelf);
    cJSON_AddNumberToObject(snap, "total_copies", node->book.total_copies);
    char* snap_str = cJSON_PrintUnformatted(snap);
    if (snap_str) {
        snprintf(act.snapshot_data, sizeof(act.snapshot_data), "%s", snap_str);
        free(snap_str);
    }
    cJSON_Delete(snap);
    stack_push(&g_state.undo_stack, &act);

    /* Update fields */
    const char* title = cJSON_GetStringValue(cJSON_GetObjectItem(json, "title"));
    if (title) snprintf(node->book.title, sizeof(node->book.title), "%s", title);

    const char* author = cJSON_GetStringValue(cJSON_GetObjectItem(json, "author"));
    if (author) snprintf(node->book.author, sizeof(node->book.author), "%s", author);

    const char* category = cJSON_GetStringValue(cJSON_GetObjectItem(json, "category"));
    if (category) snprintf(node->book.category, sizeof(node->book.category), "%s", category);

    const char* isbn = cJSON_GetStringValue(cJSON_GetObjectItem(json, "isbn"));
    if (isbn) snprintf(node->book.isbn, sizeof(node->book.isbn), "%s", isbn);

    const char* shelf = cJSON_GetStringValue(cJSON_GetObjectItem(json, "shelf"));
    if (shelf) snprintf(node->book.shelf, sizeof(node->book.shelf), "%s", shelf);

    const char* cover = cJSON_GetStringValue(cJSON_GetObjectItem(json, "cover_url"));
    if (cover) snprintf(node->book.cover_url, sizeof(node->book.cover_url), "%s", cover);

    const char* ebook = cJSON_GetStringValue(cJSON_GetObjectItem(json, "ebook_url"));
    if (ebook) snprintf(node->book.ebook_url, sizeof(node->book.ebook_url), "%s", ebook);

    cJSON* copies = cJSON_GetObjectItem(json, "total_copies");
    if (copies) {
        int diff = copies->valueint - node->book.total_copies;
        node->book.total_copies = copies->valueint;
        node->book.available_copies += diff;
        if (node->book.available_copies < 0) node->book.available_copies = 0;
    }

    storage_save_books();
    add_audit_log(session->username, session->role, "EDIT_BOOK", node->book.title);

    cJSON_Delete(json);
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", 1);
    cJSON_AddStringToObject(resp, "message", "Book updated successfully");
    char* s = cJSON_Print(resp);
    http_send_json(sock, 200, s);
    free(s);
    cJSON_Delete(resp);
}

static void handle_delete_book(socket_t sock, const HttpRequest* req, Session* session) {
    if (!require_role(session, ROLE_LIBRARIAN, sock)) return;

    char id[128] = {0};
    get_query_param(req->query, "id", id, sizeof(id));
    if (strlen(id) == 0 && req->body) {
        cJSON* j = cJSON_Parse(req->body);
        if (j) {
            const char* bid = cJSON_GetStringValue(cJSON_GetObjectItem(j, "id"));
            if (bid) snprintf(id, sizeof(id), "%s", bid);
            cJSON_Delete(j);
        }
    }

    if (strlen(id) == 0) { http_send_error(sock, 400, "Book ID required"); return; }

    BookNode* node = book_list_find(&g_state.books, id);
    if (!node) { http_send_error(sock, 404, "Book not found"); return; }

    /* Check if book currently issued */
    for (int i = 0; i < g_state.issue_count; i++) {
        if (strcmp(g_state.issues[i].book_id, id) == 0 && g_state.issues[i].status == ISSUE_ACTIVE) {
            http_send_error(sock, 400, "Cannot delete book while copies are actively issued");
            return;
        }
    }

    char title_buf[MAX_NAME_LEN];
    snprintf(title_buf, sizeof(title_buf), "%s", node->book.title);

    bst_delete(&g_state.book_bst, id);
    book_list_delete(&g_state.books, id);
    storage_save_books();

    add_audit_log(session->username, session->role, "DELETE_BOOK", title_buf);

    cJSON* resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", 1);
    cJSON_AddStringToObject(resp, "message", "Book deleted successfully");
    char* s = cJSON_Print(resp);
    http_send_json(sock, 200, s);
    free(s);
    cJSON_Delete(resp);
}

/* --- ISSUE & RETURN CONTROLLERS --- */

static void handle_issue_books(socket_t sock, const HttpRequest* req, Session* session) {
    if (!require_role(session, ROLE_LIBRARIAN, sock)) return;
    if (!req->body) { http_send_error(sock, 400, "Missing request body"); return; }

    cJSON* json = cJSON_Parse(req->body);
    if (!json) { http_send_error(sock, 400, "Invalid JSON"); return; }

    const char* member_id = cJSON_GetStringValue(cJSON_GetObjectItem(json, "member_id"));
    cJSON* book_ids_item = cJSON_GetObjectItem(json, "book_ids");

    if (!member_id || !book_ids_item) {
        cJSON_Delete(json);
        http_send_error(sock, 400, "Member ID and book IDs required");
        return;
    }

    Member* m = member_ht_find(&g_state.members, member_id);
    if (!m) m = member_ht_find_by_username(&g_state.members, member_id);
    if (!m) {
        cJSON_Delete(json);
        http_send_error(sock, 404, "Member not found");
        return;
    }

    if (m->status != MBR_STATUS_ACTIVE) {
        cJSON_Delete(json);
        http_send_error(sock, 400, "Member account is not active");
        return;
    }

    /* Count current active issues for member */
    int current_active = 0;
    for (int i = 0; i < g_state.issue_count; i++) {
        if (strcmp(g_state.issues[i].member_id, m->id) == 0 && g_state.issues[i].status == ISSUE_ACTIVE) {
            current_active++;
        }
    }

    int num_books = cJSON_IsArray(book_ids_item) ? cJSON_GetArraySize(book_ids_item) : 1;
    if (current_active + num_books > g_state.settings.max_books_per_member) {
        cJSON_Delete(json);
        char msg[256];
        snprintf(msg, sizeof(msg), "Issue exceeds max books limit (%d books per member allowed)", g_state.settings.max_books_per_member);
        http_send_error(sock, 400, msg);
        return;
    }

    time_t now = time(NULL);
    time_t due = now + (g_state.settings.loan_period_days * 86400);

    cJSON* issued_arr = cJSON_CreateArray();

    for (int i = 0; i < num_books; i++) {
        const char* bid = cJSON_IsArray(book_ids_item) ? 
            cJSON_GetStringValue(cJSON_GetArrayItem(book_ids_item, i)) : 
            cJSON_GetStringValue(book_ids_item);

        if (!bid) continue;
        Book* b = bst_search(g_state.book_bst, bid);
        if (!b) {
            /* Try find in linked list */
            BookNode* bn = book_list_find(&g_state.books, bid);
            if (bn) b = &bn->book;
        }

        if (!b || b->available_copies <= 0) {
            continue;
        }

        /* Decrement available copy, increment borrow count */
        b->available_copies--;
        b->borrow_count++;

        /* Create IssueRecord */
        IssueRecord rec;
        memset(&rec, 0, sizeof(rec));
        snprintf(rec.id, sizeof(rec.id), "ISS-%ld-%d", (long)now, rand() % 1000);
        snprintf(rec.book_id, sizeof(rec.book_id), "%s", b->id);
        snprintf(rec.book_title, sizeof(rec.book_title), "%s", b->title);
        snprintf(rec.member_id, sizeof(rec.member_id), "%s", m->id);
        snprintf(rec.member_name, sizeof(rec.member_name), "%s", m->full_name);
        rec.issue_date = now;
        rec.due_date = due;
        rec.status = ISSUE_ACTIVE;
        rec.renewal_count = 0;

        if (g_state.issue_count < MAX_ISSUES) {
            g_state.issues[g_state.issue_count++] = rec;
        }

        /* Push to Undo Stack */
        ActionRecord act;
        memset(&act, 0, sizeof(ActionRecord));
        act.type = ACTION_ISSUE;
        snprintf(act.action_name, sizeof(act.action_name), "Issued %s to %s", b->title, m->full_name);
        snprintf(act.target_id, sizeof(act.target_id), "%s", rec.id);
        snprintf(act.member_id, sizeof(act.member_id), "%s", m->id);
        snprintf(act.performed_by, sizeof(act.performed_by), "%s", session->username);
        act.timestamp = now;
        stack_push(&g_state.undo_stack, &act);

        cJSON_AddItemToArray(issued_arr, cJSON_CreateString(b->title));
    }

    storage_save_books();
    storage_save_issues();
    rebuild_overdue_heap();

    add_audit_log(session->username, session->role, "ISSUE_BOOKS", m->full_name);

    cJSON_Delete(json);
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", 1);
    cJSON_AddItemToObject(resp, "issued_books", issued_arr);
    cJSON_AddNumberToObject(resp, "due_date", (double)due);
    char* s = cJSON_Print(resp);
    http_send_json(sock, 200, s);
    free(s);
    cJSON_Delete(resp);
}

static void handle_return_book(socket_t sock, const HttpRequest* req, Session* session) {
    if (!require_role(session, ROLE_LIBRARIAN, sock)) return;
    if (!req->body) { http_send_error(sock, 400, "Missing body"); return; }

    cJSON* json = cJSON_Parse(req->body);
    if (!json) { http_send_error(sock, 400, "Invalid JSON"); return; }

    const char* book_id = cJSON_GetStringValue(cJSON_GetObjectItem(json, "book_id"));
    const char* issue_id = cJSON_GetStringValue(cJSON_GetObjectItem(json, "issue_id"));

    IssueRecord* target_issue = NULL;
    for (int i = 0; i < g_state.issue_count; i++) {
        IssueRecord* rec = &g_state.issues[i];
        if (rec->status == ISSUE_ACTIVE) {
            if ((issue_id && strcmp(rec->id, issue_id) == 0) ||
                (book_id && strcmp(rec->book_id, book_id) == 0)) {
                target_issue = rec;
                break;
            }
        }
    }

    if (!target_issue) {
        cJSON_Delete(json);
        http_send_error(sock, 404, "No active issue record found for this book");
        return;
    }

    time_t now = time(NULL);
    target_issue->return_date = now;
    target_issue->status = ISSUE_RETURNED;

    /* Calculate overdue fine */
    double fine = 0.0;
    if (now > target_issue->due_date) {
        int days_late = (int)((now - target_issue->due_date) / 86400) + 1;
        fine = days_late * g_state.settings.fine_rate_per_day;
        target_issue->fine_amount = fine;
        target_issue->fine_paid = 0;
    }

    /* Restore book copy */
    Book* b = bst_search(g_state.book_bst, target_issue->book_id);
    if (!b) {
        BookNode* bn = book_list_find(&g_state.books, target_issue->book_id);
        if (bn) b = &bn->book;
    }

    char next_member[MAX_NAME_LEN] = {0};
    int waitlist_dequeued = 0;

    if (b) {
        b->available_copies++;
        if (b->available_copies > b->total_copies) b->available_copies = b->total_copies;

        /* Check waitlist queue (FIFO auto-assign on return) */
        if (!queue_is_empty(&b->waitlist)) {
            char next_mid[MAX_ID_LEN], next_mname[MAX_NAME_LEN];
            if (dequeue(&b->waitlist, next_mid, next_mname)) {
                waitlist_dequeued = 1;
                snprintf(next_member, sizeof(next_member), "%s (%s)", next_mname, next_mid);
                /* Notification */
                char notif[256];
                snprintf(notif, sizeof(notif), "Waitlist copy assigned to %s for book %s", next_mname, b->title);
                add_audit_log("system", ROLE_ADMIN, "WAITLIST_AUTO_ASSIGN", notif);
            }
        }
    }

    /* Push to Undo Stack */
    ActionRecord act;
    memset(&act, 0, sizeof(ActionRecord));
    act.type = ACTION_RETURN;
    snprintf(act.action_name, sizeof(act.action_name), "Returned %s from %s", target_issue->book_title, target_issue->member_name);
    snprintf(act.target_id, sizeof(act.target_id), "%s", target_issue->id);
    snprintf(act.member_id, sizeof(act.member_id), "%s", target_issue->member_id);
    snprintf(act.performed_by, sizeof(act.performed_by), "%s", session->username);
    act.timestamp = now;
    stack_push(&g_state.undo_stack, &act);

    storage_save_books();
    storage_save_issues();
    rebuild_overdue_heap();

    add_audit_log(session->username, session->role, "RETURN_BOOK", target_issue->book_title);

    cJSON_Delete(json);
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", 1);
    cJSON_AddNumberToObject(resp, "fine_amount", fine);
    cJSON_AddBoolToObject(resp, "waitlist_notified", waitlist_dequeued);
    if (waitlist_dequeued) {
        cJSON_AddStringToObject(resp, "assigned_to", next_member);
    }
    char* s = cJSON_Print(resp);
    http_send_json(sock, 200, s);
    free(s);
    cJSON_Delete(resp);
}

static void handle_renew_book(socket_t sock, const HttpRequest* req, Session* session) {
    if (!session) { http_send_error(sock, 401, "Unauthorized"); return; }
    if (!req->body) { http_send_error(sock, 400, "Missing body"); return; }

    cJSON* json = cJSON_Parse(req->body);
    if (!json) { http_send_error(sock, 400, "Invalid JSON"); return; }

    const char* issue_id = cJSON_GetStringValue(cJSON_GetObjectItem(json, "issue_id"));
    if (!issue_id) { cJSON_Delete(json); http_send_error(sock, 400, "Issue ID required"); return; }

    IssueRecord* target = NULL;
    for (int i = 0; i < g_state.issue_count; i++) {
        if (strcmp(g_state.issues[i].id, issue_id) == 0 && g_state.issues[i].status == ISSUE_ACTIVE) {
            target = &g_state.issues[i];
            break;
        }
    }

    if (!target) {
        cJSON_Delete(json);
        http_send_error(sock, 404, "Active issue not found");
        return;
    }

    /* Check member permissions: members can only renew their own books */
    if (session->role == ROLE_MEMBER && strcmp(target->member_id, session->user_id) != 0) {
        cJSON_Delete(json);
        http_send_error(sock, 403, "Cannot renew books belonging to other members");
        return;
    }

    /* Check renewal limit */
    if (target->renewal_count >= g_state.settings.renewal_limit) {
        cJSON_Delete(json);
        char msg[128];
        snprintf(msg, sizeof(msg), "Maximum renewal limit reached (%d renewals allowed)", g_state.settings.renewal_limit);
        http_send_error(sock, 400, msg);
        return;
    }

    /* Check if book is on waitlist */
    Book* b = bst_search(g_state.book_bst, target->book_id);
    if (b && !queue_is_empty(&b->waitlist)) {
        cJSON_Delete(json);
        http_send_error(sock, 400, "Book cannot be renewed because members are in the waitlist");
        return;
    }

    /* Extend due date */
    target->renewal_count++;
    target->due_date += (g_state.settings.loan_period_days * 86400);

    storage_save_issues();
    rebuild_overdue_heap();

    add_audit_log(session->username, session->role, "RENEW_BOOK", target->book_title);

    cJSON_Delete(json);
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", 1);
    cJSON_AddNumberToObject(resp, "new_due_date", (double)target->due_date);
    cJSON_AddNumberToObject(resp, "renewals_left", g_state.settings.renewal_limit - target->renewal_count);
    char* s = cJSON_Print(resp);
    http_send_json(sock, 200, s);
    free(s);
    cJSON_Delete(resp);
}

/* --- UNDO STACK CONTROLLER --- */

static void handle_undo(socket_t sock, Session* session) {
    if (!require_role(session, ROLE_LIBRARIAN, sock)) return;

    if (stack_is_empty(&g_state.undo_stack)) {
        http_send_error(sock, 400, "No actions to undo");
        return;
    }

    ActionRecord act;
    stack_pop(&g_state.undo_stack, &act);

    char msg[256];
    snprintf(msg, sizeof(msg), "Undid action: %s", act.action_name);

    if (act.type == ACTION_ISSUE) {
        /* Revert issue: return the book */
        for (int i = 0; i < g_state.issue_count; i++) {
            if (strcmp(g_state.issues[i].id, act.target_id) == 0 && g_state.issues[i].status == ISSUE_ACTIVE) {
                g_state.issues[i].status = ISSUE_RETURNED;
                Book* b = bst_search(g_state.book_bst, g_state.issues[i].book_id);
                if (b) {
                    b->available_copies++;
                    if (b->borrow_count > 0) b->borrow_count--;
                }
                break;
            }
        }
    } else if (act.type == ACTION_RETURN) {
        /* Revert return: re-issue the book */
        for (int i = 0; i < g_state.issue_count; i++) {
            if (strcmp(g_state.issues[i].id, act.target_id) == 0 && g_state.issues[i].status == ISSUE_RETURNED) {
                g_state.issues[i].status = ISSUE_ACTIVE;
                g_state.issues[i].return_date = 0;
                Book* b = bst_search(g_state.book_bst, g_state.issues[i].book_id);
                if (b && b->available_copies > 0) {
                    b->available_copies--;
                }
                break;
            }
        }
    } else if (act.type == ACTION_ADD_BOOK) {
        /* Revert add book: delete from list and BST */
        bst_delete(&g_state.book_bst, act.target_id);
        book_list_delete(&g_state.books, act.target_id);
    }

    storage_save_books();
    storage_save_issues();
    rebuild_overdue_heap();

    add_audit_log(session->username, session->role, "UNDO_ACTION", msg);

    cJSON* resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", 1);
    cJSON_AddStringToObject(resp, "message", msg);
    cJSON_AddNumberToObject(resp, "remaining_undo", stack_size(&g_state.undo_stack));
    char* s = cJSON_Print(resp);
    http_send_json(sock, 200, s);
    free(s);
    cJSON_Delete(resp);
}

/* --- OVERDUE MIN-HEAP CONTROLLER --- */

static void handle_get_overdue(socket_t sock) {
    rebuild_overdue_heap();

    int count = 0;
    HeapItem* sorted_alerts = heap_get_all_sorted(&g_state.overdue_heap, &count);

    cJSON* root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "total", count);

    cJSON* arr = cJSON_CreateArray();
    if (sorted_alerts) {
        for (int i = 0; i < count; i++) {
            HeapItem* it = &sorted_alerts[i];
            cJSON* obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "issue_id", it->issue_id);
            cJSON_AddStringToObject(obj, "book_id", it->book_id);
            cJSON_AddStringToObject(obj, "book_title", it->book_title);
            cJSON_AddStringToObject(obj, "member_id", it->member_id);
            cJSON_AddStringToObject(obj, "member_name", it->member_name);
            cJSON_AddNumberToObject(obj, "due_date", (double)it->due_date);
            cJSON_AddNumberToObject(obj, "days_overdue", it->days_overdue);
            cJSON_AddNumberToObject(obj, "fine_amount", it->fine_amount);
            cJSON_AddItemToArray(arr, obj);
        }
        free(sorted_alerts);
    }
    cJSON_AddItemToObject(root, "alerts", arr);

    char* s = cJSON_Print(root);
    http_send_json(sock, 200, s);
    free(s);
    cJSON_Delete(root);
}

/* --- GATE / SECURITY CONTROLLERS --- */

static void handle_gate_scan(socket_t sock, const HttpRequest* req, Session* session) {
    if (!session) {
        http_send_error(sock, 401, "Authentication required. Please log in.");
        return;
    }
    if (session->role != ROLE_GATE && session->role != ROLE_ADMIN) {
        http_send_error(sock, 403, "Access restricted to Security/Gate personnel");
        return;
    }
    if (!req->body) { http_send_error(sock, 400, "Missing body"); return; }

    cJSON* json = cJSON_Parse(req->body);
    if (!json) { http_send_error(sock, 400, "Invalid JSON"); return; }

    const char* barcode = cJSON_GetStringValue(cJSON_GetObjectItem(json, "barcode"));
    if (!barcode) { cJSON_Delete(json); http_send_error(sock, 400, "Member ID / Barcode required"); return; }

    Member* m = member_ht_find(&g_state.members, barcode);
    if (!m) m = member_ht_find_by_username(&g_state.members, barcode);
    if (!m) {
        cJSON_Delete(json);
        http_send_error(sock, 404, "Member ID card not recognized");
        return;
    }

    time_t now = time(NULL);
    GateEntry* active_entry = NULL;

    /* Check if currently inside */
    for (int i = 0; i < g_state.gate_count; i++) {
        if (strcmp(g_state.gate_entries[i].member_id, m->id) == 0 && g_state.gate_entries[i].is_inside == 1) {
            active_entry = &g_state.gate_entries[i];
            break;
        }
    }

    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "member_id", m->id);
    cJSON_AddStringToObject(resp, "member_name", m->full_name);

    if (active_entry) {
        /* Member is inside -> Log EXIT */
        active_entry->exit_time = now;
        active_entry->is_inside = 0;
        int duration = (int)((now - active_entry->entry_time) / 60);
        active_entry->duration_minutes = duration > 0 ? duration : 1;

        cJSON_AddStringToObject(resp, "action", "EXIT");
        cJSON_AddNumberToObject(resp, "duration_minutes", active_entry->duration_minutes);
        cJSON_AddNumberToObject(resp, "exit_time", (double)now);

        /* Check if member has overdue books upon exit */
        int overdue_count = 0;
        for (int j = 0; j < g_state.issue_count; j++) {
            if (strcmp(g_state.issues[j].member_id, m->id) == 0 &&
                g_state.issues[j].status == ISSUE_ACTIVE &&
                now > g_state.issues[j].due_date) {
                overdue_count++;
            }
        }
        cJSON_AddNumberToObject(resp, "overdue_count", overdue_count);
        cJSON_AddBoolToObject(resp, "has_overdue_books", overdue_count > 0 ? 1 : 0);

        char audit_msg[256];
        snprintf(audit_msg, sizeof(audit_msg), "%s exited library (duration: %d mins)", m->full_name, active_entry->duration_minutes);
        add_audit_log(session->username, ROLE_GATE, "GATE_EXIT", audit_msg);
    } else {
        /* Member is outside -> Log ENTRY */
        if (g_state.gate_count < MAX_GATE_ENTRIES) {
            GateEntry* ge = &g_state.gate_entries[g_state.gate_count++];
            memset(ge, 0, sizeof(GateEntry));
            snprintf(ge->id, sizeof(ge->id), "GT-%ld-%d", (long)now, rand() % 1000);
            snprintf(ge->member_id, sizeof(ge->member_id), "%s", m->id);
            snprintf(ge->member_name, sizeof(ge->member_name), "%s", m->full_name);
            ge->entry_time = now;
            ge->is_inside = 1;
        }

        cJSON_AddStringToObject(resp, "action", "ENTRY");
        cJSON_AddNumberToObject(resp, "entry_time", (double)now);

        char audit_msg[256];
        snprintf(audit_msg, sizeof(audit_msg), "%s entered library", m->full_name);
        add_audit_log(session->username, ROLE_GATE, "GATE_ENTRY", audit_msg);
    }

    storage_save_gate();

    /* Count live inside members */
    int inside_count = 0;
    for (int i = 0; i < g_state.gate_count; i++) {
        if (g_state.gate_entries[i].is_inside == 1) inside_count++;
    }
    cJSON_AddNumberToObject(resp, "inside_count", inside_count);

    cJSON_Delete(json);
    char* s = cJSON_Print(resp);
    http_send_json(sock, 200, s);
    free(s);
    cJSON_Delete(resp);
}

static void handle_gate_inside(socket_t sock) {
    cJSON* root = cJSON_CreateObject();
    cJSON* arr = cJSON_CreateArray();
    int count = 0;
    time_t now = time(NULL);

    for (int i = 0; i < g_state.gate_count; i++) {
        GateEntry* ge = &g_state.gate_entries[i];
        if (ge->is_inside == 1) {
            cJSON* obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "id", ge->id);
            cJSON_AddStringToObject(obj, "member_id", ge->member_id);
            cJSON_AddStringToObject(obj, "member_name", ge->member_name);
            cJSON_AddNumberToObject(obj, "entry_time", (double)ge->entry_time);
            int elapsed = (int)((now - ge->entry_time) / 60);
            cJSON_AddNumberToObject(obj, "elapsed_minutes", elapsed);
            cJSON_AddItemToArray(arr, obj);
            count++;
        }
    }

    cJSON_AddNumberToObject(root, "count", count);
    cJSON_AddItemToObject(root, "inside", arr);

    char* s = cJSON_Print(root);
    http_send_json(sock, 200, s);
    free(s);
    cJSON_Delete(root);
}

static void handle_get_gate_log(socket_t sock, Session* session) {
    if (!session) {
        http_send_error(sock, 401, "Authentication required. Please log in.");
        return;
    }
    if (session->role != ROLE_GATE && session->role != ROLE_ADMIN) {
        http_send_error(sock, 403, "Access restricted to Security/Gate personnel");
        return;
    }

    cJSON* root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "total", g_state.gate_count);
    cJSON* arr = cJSON_CreateArray();

    for (int i = 0; i < g_state.gate_count; i++) {
        GateEntry* ge = &g_state.gate_entries[i];
        cJSON* obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "id", ge->id);
        cJSON_AddStringToObject(obj, "member_id", ge->member_id);
        cJSON_AddStringToObject(obj, "member_name", ge->member_name);
        cJSON_AddNumberToObject(obj, "entry_time", (double)ge->entry_time);
        cJSON_AddNumberToObject(obj, "exit_time", (double)ge->exit_time);
        cJSON_AddNumberToObject(obj, "duration_minutes", ge->duration_minutes);
        cJSON_AddBoolToObject(obj, "is_inside", ge->is_inside);
        cJSON_AddItemToArray(arr, obj);
    }

    cJSON_AddItemToObject(root, "entries", arr);
    char* s = cJSON_Print(root);
    http_send_json(sock, 200, s);
    free(s);
    cJSON_Delete(root);
}

/* --- REPORTS & AUDIT CONTROLLER --- */

static void handle_get_reports(socket_t sock, Session* session) {
    if (!require_role(session, ROLE_LIBRARIAN, sock)) return;

    int total_books = g_state.books.count;
    int total_members = g_state.members.count;
    int active_issues = 0;
    int overdue_count = 0;
    double total_fines = 0.0;
    int inside_count = 0;

    time_t now = time(NULL);
    for (int i = 0; i < g_state.issue_count; i++) {
        IssueRecord* rec = &g_state.issues[i];
        if (rec->status == ISSUE_ACTIVE) {
            active_issues++;
            if (now > rec->due_date) overdue_count++;
        }
        if (rec->fine_paid == 1) {
            total_fines += rec->fine_amount;
        }
    }

    for (int i = 0; i < g_state.gate_count; i++) {
        if (g_state.gate_entries[i].is_inside == 1) inside_count++;
    }

    cJSON* root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "total_books", total_books);
    cJSON_AddNumberToObject(root, "total_members", total_members);
    cJSON_AddNumberToObject(root, "active_issues", active_issues);
    cJSON_AddNumberToObject(root, "overdue_count", overdue_count);
    cJSON_AddNumberToObject(root, "total_fines_collected", total_fines);
    cJSON_AddNumberToObject(root, "members_inside", inside_count);

    /* Category popularity aggregation */
    cJSON* cats = cJSON_CreateObject();
    BookNode* bn = g_state.books.head;
    while (bn) {
        cJSON* cur = cJSON_GetObjectItem(cats, bn->book.category);
        if (cur) {
            cur->valueint += bn->book.borrow_count;
        } else {
            cJSON_AddNumberToObject(cats, bn->book.category, bn->book.borrow_count);
        }
        bn = bn->next;
    }
    cJSON_AddItemToObject(root, "category_stats", cats);

    char* s = cJSON_Print(root);
    http_send_json(sock, 200, s);
    free(s);
    cJSON_Delete(root);
}

static void handle_get_audit(socket_t sock, Session* session) {
    if (!require_role(session, ROLE_ADMIN, sock)) return;

    cJSON* root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "total", g_state.audit_count);
    cJSON* arr = cJSON_CreateArray();

    /* Return latest logs first */
    for (int i = g_state.audit_count - 1; i >= 0 && i >= g_state.audit_count - 100; i--) {
        AuditLog* a = &g_state.audit_logs[i];
        cJSON* obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "id", a->id);
        cJSON_AddNumberToObject(obj, "timestamp", (double)a->timestamp);
        cJSON_AddStringToObject(obj, "username", a->username);
        cJSON_AddNumberToObject(obj, "role", a->role);
        cJSON_AddStringToObject(obj, "action", a->action);
        cJSON_AddStringToObject(obj, "details", a->details);
        cJSON_AddItemToArray(arr, obj);
    }
    cJSON_AddItemToObject(root, "logs", arr);

    char* s = cJSON_Print(root);
    http_send_json(sock, 200, s);
    free(s);
    cJSON_Delete(root);
}

/* --- BACKUP & RESTORE CONTROLLER --- */

static void handle_backup(socket_t sock, Session* session) {
    if (!require_role(session, ROLE_ADMIN, sock)) return;

    char* backup_json = storage_export_backup_json();
    if (!backup_json) {
        http_send_error(sock, 500, "Failed to create backup");
        return;
    }

    http_send_response(sock, 200, "OK", "application/json; charset=utf-8", backup_json, (int)strlen(backup_json));
    free(backup_json);
}

static void handle_restore(socket_t sock, const HttpRequest* req, Session* session) {
    if (!require_role(session, ROLE_ADMIN, sock)) return;
    if (!req->body) { http_send_error(sock, 400, "Missing backup payload"); return; }

    if (storage_import_backup_json(req->body)) {
        add_audit_log(session->username, session->role, "RESTORE_BACKUP", "System restored from backup");
        cJSON* resp = cJSON_CreateObject();
        cJSON_AddBoolToObject(resp, "success", 1);
        cJSON_AddStringToObject(resp, "message", "System restored successfully from backup.");
        char* s = cJSON_Print(resp);
        http_send_json(sock, 200, s);
        free(s);
        cJSON_Delete(resp);
    } else {
        http_send_error(sock, 400, "Invalid backup data");
    }
}

/* --- MAIN REST API DISPATCHER --- */

void api_handle_request(socket_t sock, const HttpRequest* req) {
    Session* session = authenticate_request(req);

    if (strcmp(req->method, "OPTIONS") == 0) {
        http_send_options(sock);
        return;
    }

    /* Auth Routes */
    if (strcmp(req->path, "/api/auth/login") == 0 && strcmp(req->method, "POST") == 0) {
        handle_auth_login(sock, req);
    } else if (strcmp(req->path, "/api/auth/scan-login") == 0 && strcmp(req->method, "POST") == 0) {
        handle_auth_scan_login(sock, req);
    } else if (strcmp(req->path, "/api/auth/register") == 0 && strcmp(req->method, "POST") == 0) {
        handle_auth_register(sock, req, session);
    } else if (strcmp(req->path, "/api/auth/forgot-password") == 0 && strcmp(req->method, "POST") == 0) {
        handle_auth_forgot_password(sock, req);
    } else if (strcmp(req->path, "/api/auth/change-password") == 0 && strcmp(req->method, "POST") == 0) {
        handle_auth_change_password(sock, req, session);
    } else if (strcmp(req->path, "/api/auth/me") == 0 && strcmp(req->method, "GET") == 0) {
        handle_auth_me(sock, session);
    } else if (strcmp(req->path, "/api/auth/logout") == 0 && strcmp(req->method, "POST") == 0) {
        handle_auth_logout(sock, req, session);
    } else if (strcmp(req->path, "/api/auth/logout-all") == 0 && strcmp(req->method, "POST") == 0) {
        handle_auth_logout_all(sock, session);
    }
    /* Books Routes */
    else if (strcmp(req->path, "/api/books") == 0 && strcmp(req->method, "GET") == 0) {
        handle_get_books(sock, req);
    } else if (strcmp(req->path, "/api/books/lookup") == 0 && strcmp(req->method, "GET") == 0) {
        handle_lookup_book_bst(sock, req);
    } else if (strcmp(req->path, "/api/books") == 0 && strcmp(req->method, "POST") == 0) {
        handle_add_book(sock, req, session);
    } else if (strcmp(req->path, "/api/books") == 0 && strcmp(req->method, "PUT") == 0) {
        handle_edit_book(sock, req, session);
    } else if (strcmp(req->path, "/api/books") == 0 && strcmp(req->method, "DELETE") == 0) {
        handle_delete_book(sock, req, session);
    }
    /* Issues Routes */
    else if (strcmp(req->path, "/api/issues/issue") == 0 && strcmp(req->method, "POST") == 0) {
        handle_issue_books(sock, req, session);
    } else if (strcmp(req->path, "/api/issues/return") == 0 && strcmp(req->method, "POST") == 0) {
        handle_return_book(sock, req, session);
    } else if (strcmp(req->path, "/api/issues/renew") == 0 && strcmp(req->method, "POST") == 0) {
        handle_renew_book(sock, req, session);
    } else if (strcmp(req->path, "/api/issues/overdue") == 0 && strcmp(req->method, "GET") == 0) {
        handle_get_overdue(sock);
    }
    /* Undo Route */
    else if (strcmp(req->path, "/api/undo") == 0 && strcmp(req->method, "POST") == 0) {
        handle_undo(sock, session);
    }
    /* Gate Routes */
    else if (strcmp(req->path, "/api/gate/scan") == 0 && strcmp(req->method, "POST") == 0) {
        handle_gate_scan(sock, req, session);
    } else if (strcmp(req->path, "/api/gate/inside") == 0 && strcmp(req->method, "GET") == 0) {
        handle_gate_inside(sock);
    } else if (strcmp(req->path, "/api/gate/log") == 0 && strcmp(req->method, "GET") == 0) {
        handle_get_gate_log(sock, session);
    }
    /* Reports, Audit & Backup */
    else if (strcmp(req->path, "/api/reports") == 0 && strcmp(req->method, "GET") == 0) {
        handle_get_reports(sock, session);
    } else if (strcmp(req->path, "/api/audit") == 0 && strcmp(req->method, "GET") == 0) {
        handle_get_audit(sock, session);
    } else if (strcmp(req->path, "/api/backup") == 0 && strcmp(req->method, "GET") == 0) {
        handle_backup(sock, session);
    } else if (strcmp(req->path, "/api/restore") == 0 && strcmp(req->method, "POST") == 0) {
        handle_restore(sock, req, session);
    }
    /* Unknown Route */
    else {
        http_send_error(sock, 404, "Endpoint not found");
    }
}
