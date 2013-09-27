#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mysql.h>

#include "password.h"

extern int msgno;

my_bool
php_password_hash_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    char *salt = NULL;
    int cost = -1;

    if (args->arg_count < 1 || args->arg_count > 4) {
        strcpy(message,
               "Wrong arguments to php_password_hash; "
               "must be (STRING, STRING, STRING, INTEGER)");
        return 1;
    }

    if (args->arg_type[0] != STRING_RESULT) {
        args->arg_type[0] = STRING_RESULT;
    }

    if (args->arg_count > 1 && args->arg_type[1] != STRING_RESULT) {
        args->arg_type[1] = STRING_RESULT;
    }

    if (args->arg_count > 2) {
        if (args->arg_type[2] != STRING_RESULT) {
            args->arg_type[2] = STRING_RESULT;
        }
        salt = (char *)args->args[2];
        if (salt && strlen(salt) < BCRYPT_BLOWFISH_SALT_REQUIRED_LEN) {
            strcpy(message,
                   "Wrong arguments to php_password_hash; "
                   "provided salt is too short expecting 22");
            return 1;
        }
    }

    if (args->arg_count > 3) {
        if (args->arg_type[3] != INT_RESULT) {
            args->arg_type[3] = INT_RESULT;
        }
        cost = (int)(*((long long *)args->args[3]));
        if (cost < 4 || cost > 31) {
            strcpy(message,
                   "Wrong arguments to php_password_hash; "
                   "invalid bcrypt cost less than 4 or greater than 31");
            return 1;
        }
    }

    return 0;
}

void
php_password_hash_deinit(UDF_INIT *initid)
{}

char *
php_password_hash(UDF_INIT *initid, UDF_ARGS *args, char *result,
                  unsigned long *length, char *is_null, char *error)
{
    const char *password = (char *)args->args[0];
    char *algo = BCRYPT_BLOWFISH;
    char *salt = NULL;
    int cost = BCRYPT_BLOWFISH_COST;
    char *hash = NULL;
    size_t len;

    msgno = -1;

    if (args->arg_count > 1) {
        algo = (char *)args->args[1];
    }
    if (args->arg_count > 2) {
        salt = (char *)args->args[2];
    }
    if (args->arg_count > 3) {
        cost = (int)(*((long long *)args->args[3]));
    }

    hash = password_hash(password, algo, salt, cost);
    if (!hash) {
        *is_null = 1;
        *error = 1;
        *length = 0;
        return NULL;
    }

    len = strlen(hash);
    memcpy(result, hash, len);
    result[len] = '\0';
    *length = len;

    free(hash);

    return result;
}

my_bool
php_password_verify_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    if (args->arg_count != 2) {
        strcpy(message,"Wrong arguments tos php_password_verify;"
               " must be (STRING, STRING)");
        return 1;
    }

    if (args->arg_type[0] != STRING_RESULT) {
        args->arg_type[0] = STRING_RESULT;
    }

    if (args->arg_type[1] != STRING_RESULT) {
        args->arg_type[1] = STRING_RESULT;
    }

    return 0;
}

void
php_password_verify_deinit(UDF_INIT *initid)
{}

long long
php_password_verify(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
    const char *password = (char *)args->args[0];
    const char *hash = (char *)args->args[1];

    msgno = -1;

    if (password_verify(password, hash) == 0) {
        return 1;
    }

    return 0;
}
