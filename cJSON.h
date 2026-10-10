#ifndef CJSON__H
#define CJSON__H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>

#define cJSON_Invalid (0)
#define cJSON_False  (1 << 0)
#define cJSON_True   (1 << 1)
#define cJSON_NULL   (1 << 2)
#define cJSON_Number (1 << 3)
#define cJSON_String (1 << 4)
#define cJSON_Array  (1 << 5)
#define cJSON_Object (1 << 6)
#define cJSON_Raw    (1 << 7)

#define cJSON_IsReference 256
#define cJSON_StringIsConst 512

typedef struct cJSON
{
    struct cJSON *next;
    struct cJSON *prev;
    struct cJSON *child;
    int type;
    char *valuestring;
    int valueint;
    double valuedouble;
    char *string;
} cJSON;

cJSON *cJSON_Parse(const char *value);
char  *cJSON_Print(const cJSON *item);
char  *cJSON_PrintUnformatted(const cJSON *item);
void   cJSON_Delete(cJSON *c);

int    cJSON_GetArraySize(const cJSON *array);
cJSON *cJSON_GetArrayItem(const cJSON *array, int index);
cJSON *cJSON_GetObjectItem(const cJSON * const object, const char * const string);
cJSON *cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * const string);
int    cJSON_HasObjectItem(const cJSON *object, const char *string);

cJSON *cJSON_CreateNull(void);
cJSON *cJSON_CreateTrue(void);
cJSON *cJSON_CreateFalse(void);
cJSON *cJSON_CreateBool(int b);
cJSON *cJSON_CreateNumber(double num);
cJSON *cJSON_CreateString(const char *string);
cJSON *cJSON_CreateRaw(const char *raw);
cJSON *cJSON_CreateArray(void);
cJSON *cJSON_CreateObject(void);

void   cJSON_AddItemToArray(cJSON *array, cJSON *item);
void   cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item);
void   cJSON_DeleteItemFromArray(cJSON *array, int which);
void   cJSON_DeleteItemFromObject(cJSON *object, const char *string);

cJSON *cJSON_AddNullToObject(cJSON * const object, const char * const name);
cJSON *cJSON_AddTrueToObject(cJSON * const object, const char * const name);
cJSON *cJSON_AddFalseToObject(cJSON * const object, const char * const name);
cJSON *cJSON_AddBoolToObject(cJSON * const object, const char * const name, const int boolean);
cJSON *cJSON_AddNumberToObject(cJSON * const object, const char * const name, const double number);
cJSON *cJSON_AddStringToObject(cJSON * const object, const char * const name, const char * const string);
cJSON *cJSON_AddRawToObject(cJSON * const object, const char * const name, const char * const raw);

char  *cJSON_GetStringValue(const cJSON * const item);
double cJSON_GetNumberValue(const cJSON * const item);

int cJSON_IsInvalid(const cJSON * const item);
int cJSON_IsFalse(const cJSON * const item);
int cJSON_IsTrue(const cJSON * const item);
int cJSON_IsBool(const cJSON * const item);
int cJSON_IsNull(const cJSON * const item);
int cJSON_IsNumber(const cJSON * const item);
int cJSON_IsString(const cJSON * const item);
int cJSON_IsArray(const cJSON * const item);
int cJSON_IsObject(const cJSON * const item);
int cJSON_IsRaw(const cJSON * const item);

#ifdef __cplusplus
}
#endif

#endif
