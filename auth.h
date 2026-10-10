#ifndef AUTH_H
#define AUTH_H

#include "models.h"

void sha256_hash(const char* input, char* output_hex);
void generate_salt(char* salt, int length);
void hash_password(const char* password, const char* salt, char* hash_out);
int verify_password(const char* password, const char* salt, const char* hash);
void generate_token(char* token_out, int length);

/* Account lockout management */
int is_account_locked(const Member* member, int* remaining_seconds);
void record_failed_attempt(Member* member);
void reset_failed_attempts(Member* member);

/* Session management */
Session* create_session(SessionHashTable* session_ht, const Member* member, const char* device);
Session* get_session(SessionHashTable* session_ht, const char* token);
void destroy_session(SessionHashTable* session_ht, const char* token);
void destroy_all_user_sessions(SessionHashTable* session_ht, const char* user_id);

#endif
