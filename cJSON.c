#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include "cJSON.h"

static const char *ep;

const char *cJSON_GetErrorPtr(void) {
    return ep;
}

static char *cJSON_strdup(const char *str) {
    size_t len;
    char *copy;
    if (!str) return NULL;
    len = strlen(str) + 1;
    copy = (char*)malloc(len);
    if (!copy) return NULL;
    memcpy(copy, str, len);
    return copy;
}

static cJSON *cJSON_New_Item(void) {
    cJSON* node = (cJSON*)malloc(sizeof(cJSON));
    if (node) {
        memset(node, 0, sizeof(cJSON));
    }
    return node;
}

void cJSON_Delete(cJSON *c) {
    cJSON *next;
    while (c) {
        next = c->next;
        if (!(c->type & cJSON_IsReference) && c->child) cJSON_Delete(c->child);
        if (!(c->type & cJSON_IsReference) && c->valuestring) free(c->valuestring);
        if (!(c->type & cJSON_StringIsConst) && c->string) free(c->string);
        free(c);
        c = next;
    }
}

static const char *parse_value(cJSON *item, const char *value);
static char *print_value(const cJSON *item, int depth, int fmt);

static const char *skip(const char *in) {
    while (in && *in && ((unsigned char)*in <= 32)) in++;
    return in;
}

static const char *parse_string(cJSON *item, const char *str) {
    const char *ptr = str + 1;
    char *ptr2;
    char *out;
    int len = 0;
    if (*str != '\"') { ep = str; return NULL; }

    while (*ptr != '\"' && *ptr && ++len) {
        if (*ptr++ == '\\') ptr++;
    }

    out = (char*)malloc(len + 1);
    if (!out) return NULL;

    ptr = str + 1;
    ptr2 = out;
    while (*ptr != '\"' && *ptr) {
        if (*ptr != '\\') {
            *ptr2++ = *ptr++;
        } else {
            ptr++;
            switch (*ptr) {
                case 'b': *ptr2++ = '\b'; break;
                case 'f': *ptr2++ = '\f'; break;
                case 'n': *ptr2++ = '\n'; break;
                case 'r': *ptr2++ = '\r'; break;
                case 't': *ptr2++ = '\t'; break;
                case '\"': *ptr2++ = '\"'; break;
                case '\\': *ptr2++ = '\\'; break;
                case '/':  *ptr2++ = '/';  break;
                default:   *ptr2++ = *ptr; break;
            }
            ptr++;
        }
    }
    *ptr2 = 0;
    if (*ptr == '\"') ptr++;
    item->valuestring = out;
    item->type = cJSON_String;
    return ptr;
}

static char *print_string_ptr(const char *str) {
    const char *ptr;
    char *ptr2, *out;
    int len = 0;
    unsigned char token;

    if (!str) return cJSON_strdup("\"\"");
    ptr = str;
    while ((token = *ptr) && ++len) {
        if (strchr("\"\\\b\f\n\r\t", token)) len++;
        ptr++;
    }

    out = (char*)malloc(len + 3);
    if (!out) return NULL;

    ptr2 = out;
    ptr = str;
    *ptr2++ = '\"';
    while (*ptr) {
        if ((unsigned char)*ptr > 31 && *ptr != '\"' && *ptr != '\\') {
            *ptr2++ = *ptr++;
        } else {
            *ptr2++ = '\\';
            switch (token = *ptr++) {
                case '\\': *ptr2++ = '\\'; break;
                case '\"': *ptr2++ = '\"'; break;
                case '\b': *ptr2++ = 'b'; break;
                case '\f': *ptr2++ = 'f'; break;
                case '\n': *ptr2++ = 'n'; break;
                case '\r': *ptr2++ = 'r'; break;
                case '\t': *ptr2++ = 't'; break;
                default: sprintf(ptr2, "u%04x", token); ptr2 += 5; break;
            }
        }
    }
    *ptr2++ = '\"';
    *ptr2++ = 0;
    return out;
}

static const char *parse_number(cJSON *item, const char *num) {
    double n = 0;
    char *endptr;
    n = strtod(num, &endptr);
    if (endptr == num) { ep = num; return NULL; }
    item->valuedouble = n;
    item->valueint = (int)n;
    item->type = cJSON_Number;
    return endptr;
}

static char *print_number(const cJSON *item) {
    char *str = (char*)malloc(64);
    if (!str) return NULL;
    if (fabs(((double)item->valueint) - item->valuedouble) <= 1e-9 && item->valuedouble >= -2147483648.0 && item->valuedouble <= 2147483647.0) {
        sprintf(str, "%d", item->valueint);
    } else {
        sprintf(str, "%.6g", item->valuedouble);
    }
    return str;
}

static const char *parse_array(cJSON *item, const char *value) {
    cJSON *child;
    if (*value != '[') { ep = value; return NULL; }

    item->type = cJSON_Array;
    value = skip(value + 1);
    if (*value == ']') return value + 1;

    item->child = child = cJSON_New_Item();
    if (!item->child) return NULL;
    value = skip(parse_value(child, skip(value)));
    if (!value) return NULL;

    while (*value == ',') {
        cJSON *new_item = cJSON_New_Item();
        if (!new_item) return NULL;
        child->next = new_item;
        new_item->prev = child;
        child = new_item;
        value = skip(parse_value(child, skip(value + 1)));
        if (!value) return NULL;
    }

    if (*value == ']') return value + 1;
    ep = value;
    return NULL;
}

static char *print_array(const cJSON *item, int depth, int fmt) {
    char **entries;
    char *out = NULL, *ptr, *ret;
    int len = 5;
    cJSON *child = item->child;
    int numentries = 0, i = 0, fail = 0;

    while (child) numentries++, child = child->next;
    if (!numentries) {
        out = (char*)malloc(3);
        if (out) strcpy(out, "[]");
        return out;
    }

    entries = (char**)calloc(numentries, sizeof(char*));
    if (!entries) return NULL;

    child = item->child;
    while (child) {
        ret = print_value(child, depth + 1, fmt);
        entries[i++] = ret;
        if (ret) len += (int)strlen(ret) + 2 + (fmt ? 1 : 0); else fail = 1;
        child = child->next;
    }

    if (!fail) out = (char*)malloc(len);
    if (!out) fail = 1;

    if (fail) {
        for (i = 0; i < numentries; i++) if (entries[i]) free(entries[i]);
        free(entries);
        return NULL;
    }

    *out = '[';
    ptr = out + 1;
    *ptr = 0;
    for (i = 0; i < numentries; i++) {
        strcpy(ptr, entries[i]);
        ptr += strlen(entries[i]);
        if (i != numentries - 1) {
            *ptr++ = ',';
            if (fmt) *ptr++ = ' ';
            *ptr = 0;
        }
        free(entries[i]);
    }
    free(entries);
    *ptr++ = ']';
    *ptr++ = 0;
    return out;
}

static const char *parse_object(cJSON *item, const char *value) {
    cJSON *child;
    if (*value != '{') { ep = value; return NULL; }

    item->type = cJSON_Object;
    value = skip(value + 1);
    if (*value == '}') return value + 1;

    item->child = child = cJSON_New_Item();
    if (!item->child) return NULL;
    value = skip(parse_string(child, skip(value)));
    if (!value) return NULL;
    child->string = child->valuestring;
    child->valuestring = NULL;
    if (*value != ':') { ep = value; return NULL; }
    value = skip(parse_value(child, skip(value + 1)));
    if (!value) return NULL;

    while (*value == ',') {
        cJSON *new_item = cJSON_New_Item();
        if (!new_item) return NULL;
        child->next = new_item;
        new_item->prev = child;
        child = new_item;
        value = skip(parse_string(child, skip(value + 1)));
        if (!value) return NULL;
        child->string = child->valuestring;
        child->valuestring = NULL;
        if (*value != ':') { ep = value; return NULL; }
        value = skip(parse_value(child, skip(value + 1)));
        if (!value) return NULL;
    }

    if (*value == '}') return value + 1;
    ep = value;
    return NULL;
}

static char *print_object(const cJSON *item, int depth, int fmt) {
    char **entries = NULL, **names = NULL;
    char *out = NULL, *ptr, *ret, *str;
    int len = 7, i = 0, j;
    cJSON *child = item->child;
    int numentries = 0, fail = 0;

    while (child) numentries++, child = child->next;
    if (!numentries) {
        out = (char*)malloc(3);
        if (out) strcpy(out, "{}");
        return out;
    }

    entries = (char**)calloc(numentries, sizeof(char*));
    if (!entries) return NULL;
    names = (char**)calloc(numentries, sizeof(char*));
    if (!names) { free(entries); return NULL; }

    child = item->child;
    depth++;
    while (child) {
        names[i] = str = print_string_ptr(child->string);
        entries[i++] = ret = print_value(child, depth, fmt);
        if (str && ret) len += (int)strlen(ret) + (int)strlen(str) + 2 + (fmt ? 2 : 0); else fail = 1;
        child = child->next;
    }

    if (!fail) out = (char*)malloc(len);
    if (!out) fail = 1;

    if (fail) {
        for (i = 0; i < numentries; i++) {
            if (names[i]) free(names[i]);
            if (entries[i]) free(entries[i]);
        }
        free(names);
        free(entries);
        return NULL;
    }

    *out = '{';
    ptr = out + 1;
    *ptr = 0;
    for (i = 0; i < numentries; i++) {
        strcpy(ptr, names[i]);
        ptr += strlen(names[i]);
        *ptr++ = ':';
        if (fmt) *ptr++ = ' ';
        strcpy(ptr, entries[i]);
        ptr += strlen(entries[i]);
        if (i != numentries - 1) *ptr++ = ',';
        if (fmt) *ptr++ = ' ';
        *ptr = 0;
        free(names[i]);
        free(entries[i]);
    }
    free(names);
    free(entries);
    *ptr++ = '}';
    *ptr++ = 0;
    return out;
}

static const char *parse_value(cJSON *item, const char *value) {
    if (!value) return NULL;
    if (!strncmp(value, "null", 4))  { item->type = cJSON_NULL; return value + 4; }
    if (!strncmp(value, "false", 5)) { item->type = cJSON_False; return value + 5; }
    if (!strncmp(value, "true", 4))  { item->type = cJSON_True; item->valueint = 1; return value + 4; }
    if (*value == '\"')              { return parse_string(item, value); }
    if (*value == '-' || (*value >= '0' && *value <= '9')) { return parse_number(item, value); }
    if (*value == '[')              { return parse_array(item, value); }
    if (*value == '{')              { return parse_object(item, value); }
    ep = value;
    return NULL;
}

static char *print_value(const cJSON *item, int depth, int fmt) {
    char *out = NULL;
    if (!item) return NULL;
    switch ((item->type) & 255) {
        case cJSON_NULL:   out = cJSON_strdup("null"); break;
        case cJSON_False:  out = cJSON_strdup("false"); break;
        case cJSON_True:   out = cJSON_strdup("true"); break;
        case cJSON_Number: out = print_number(item); break;
        case cJSON_String: out = print_string_ptr(item->valuestring); break;
        case cJSON_Array:  out = print_array(item, depth, fmt); break;
        case cJSON_Object: out = print_object(item, depth, fmt); break;
    }
    return out;
}

cJSON *cJSON_Parse(const char *value) {
    cJSON *c = cJSON_New_Item();
    ep = NULL;
    if (!c) return NULL;
    if (!parse_value(c, skip(value))) {
        cJSON_Delete(c);
        return NULL;
    }
    return c;
}

char *cJSON_Print(const cJSON *item) {
    return print_value(item, 0, 1);
}

char *cJSON_PrintUnformatted(const cJSON *item) {
    return print_value(item, 0, 0);
}

int cJSON_GetArraySize(const cJSON *array) {
    cJSON *c = array ? array->child : NULL;
    int i = 0;
    while (c) i++, c = c->next;
    return i;
}

cJSON *cJSON_GetArrayItem(const cJSON *array, int index) {
    cJSON *c = array ? array->child : NULL;
    while (c && index > 0) index--, c = c->next;
    return c;
}

cJSON *cJSON_GetObjectItem(const cJSON * const object, const char * const string) {
    cJSON *c = object ? object->child : NULL;
    while (c && c->string && strcasecmp(c->string, string)) c = c->next;
    return c;
}

cJSON *cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * const string) {
    cJSON *c = object ? object->child : NULL;
    while (c && c->string && strcmp(c->string, string)) c = c->next;
    return c;
}

int cJSON_HasObjectItem(const cJSON *object, const char *string) {
    return cJSON_GetObjectItem(object, string) ? 1 : 0;
}

cJSON *cJSON_CreateNull(void)   { cJSON *item = cJSON_New_Item(); if (item) item->type = cJSON_NULL; return item; }
cJSON *cJSON_CreateTrue(void)   { cJSON *item = cJSON_New_Item(); if (item) { item->type = cJSON_True; item->valueint = 1; } return item; }
cJSON *cJSON_CreateFalse(void)  { cJSON *item = cJSON_New_Item(); if (item) item->type = cJSON_False; return item; }
cJSON *cJSON_CreateBool(int b)  { return b ? cJSON_CreateTrue() : cJSON_CreateFalse(); }
cJSON *cJSON_CreateNumber(double num) {
    cJSON *item = cJSON_New_Item();
    if (item) { item->type = cJSON_Number; item->valuedouble = num; item->valueint = (int)num; }
    return item;
}
cJSON *cJSON_CreateString(const char *string) {
    cJSON *item = cJSON_New_Item();
    if (item) { item->type = cJSON_String; item->valuestring = cJSON_strdup(string); }
    return item;
}
cJSON *cJSON_CreateArray(void)  { cJSON *item = cJSON_New_Item(); if (item) item->type = cJSON_Array; return item; }
cJSON *cJSON_CreateObject(void) { cJSON *item = cJSON_New_Item(); if (item) item->type = cJSON_Object; return item; }

void cJSON_AddItemToArray(cJSON *array, cJSON *item) {
    cJSON *c;
    if (!item || !array) return;
    if (!array->child) {
        array->child = item;
    } else {
        c = array->child;
        while (c && c->next) c = c->next;
        c->next = item;
        item->prev = c;
    }
}

void cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item) {
    if (!item || !object) return;
    if (item->string) free(item->string);
    item->string = cJSON_strdup(string);
    cJSON_AddItemToArray(object, item);
}

void cJSON_DeleteItemFromArray(cJSON *array, int which) {
    cJSON *c = array ? array->child : NULL;
    while (c && which > 0) which--, c = c->next;
    if (!c) return;
    if (c->prev) c->prev->next = c->next;
    if (c->next) c->next->prev = c->prev;
    if (c == array->child) array->child = c->next;
    c->next = c->prev = NULL;
    cJSON_Delete(c);
}

void cJSON_DeleteItemFromObject(cJSON *object, const char *string) {
    cJSON *c = cJSON_GetObjectItem(object, string);
    if (!c) return;
    if (c->prev) c->prev->next = c->next;
    if (c->next) c->next->prev = c->prev;
    if (c == object->child) object->child = c->next;
    c->next = c->prev = NULL;
    cJSON_Delete(c);
}

cJSON *cJSON_AddNullToObject(cJSON * const object, const char * const name) {
    cJSON *null_item = cJSON_CreateNull();
    cJSON_AddItemToObject(object, name, null_item);
    return null_item;
}

cJSON *cJSON_AddTrueToObject(cJSON * const object, const char * const name) {
    cJSON *true_item = cJSON_CreateTrue();
    cJSON_AddItemToObject(object, name, true_item);
    return true_item;
}

cJSON *cJSON_AddFalseToObject(cJSON * const object, const char * const name) {
    cJSON *false_item = cJSON_CreateFalse();
    cJSON_AddItemToObject(object, name, false_item);
    return false_item;
}

cJSON *cJSON_AddBoolToObject(cJSON * const object, const char * const name, const int boolean) {
    cJSON *bool_item = cJSON_CreateBool(boolean);
    cJSON_AddItemToObject(object, name, bool_item);
    return bool_item;
}

cJSON *cJSON_AddNumberToObject(cJSON * const object, const char * const name, const double number) {
    cJSON *num_item = cJSON_CreateNumber(number);
    cJSON_AddItemToObject(object, name, num_item);
    return num_item;
}

cJSON *cJSON_AddStringToObject(cJSON * const object, const char * const name, const char * const string) {
    cJSON *str_item = cJSON_CreateString(string);
    cJSON_AddItemToObject(object, name, str_item);
    return str_item;
}

char *cJSON_GetStringValue(const cJSON * const item) {
    if (!item) return NULL;
    return item->valuestring;
}

double cJSON_GetNumberValue(const cJSON * const item) {
    if (!item) return 0.0;
    return item->valuedouble;
}

int cJSON_IsNull(const cJSON * const item) {
    return (item && (item->type & 255) == cJSON_NULL);
}

int cJSON_IsNumber(const cJSON * const item) {
    return (item && (item->type & 255) == cJSON_Number);
}

int cJSON_IsString(const cJSON * const item) {
    return (item && (item->type & 255) == cJSON_String);
}

int cJSON_IsArray(const cJSON * const item) {
    return (item && (item->type & 255) == cJSON_Array);
}

int cJSON_IsObject(const cJSON * const item) {
    return (item && (item->type & 255) == cJSON_Object);
}

int cJSON_IsTrue(const cJSON * const item) {
    return (item && (item->type & 255) == cJSON_True);
}

int cJSON_IsFalse(const cJSON * const item) {
    return (item && (item->type & 255) == cJSON_False);
}

int cJSON_IsBool(const cJSON * const item) {
    return (item && ((item->type & 255) == cJSON_True || (item->type & 255) == cJSON_False));
}
