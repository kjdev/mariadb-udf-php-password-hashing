# PHP Password Hashing for MariaDB/MySQL UDF

## Dependencies

[PHP Password Hashing](https://github.com/kjdev/php-password-hashing.git)

## Build

```
% mkdir build && cd build
% cmake -DCMAKE_BUILD_TYPE=Release ..
% make
% make install
```

Add MariaDB/MySQL UDF.

```
mariadb> CREATE FUNCTION php_password_hash RETURNS STRING SONAME 'php_password_hashing.so';
mariadb> CREATE FUNCTION php_password_verify RETURNS INTEGER SONAME 'php_password_hashing.so';
```

## Function

### php\_password\_hash — Creates a password hash

string **php\_password\_hash** ( string _PASSWORD_ , string _ALGORITHM_ , string
_SALT_ , integer _COST_ )

```
mariadb> SELECT php_password_hash('password');
+--------------------------------------------------------------+
| php_password_hash('password')                                |
+--------------------------------------------------------------+
| $2y$10$k./h1h/YV4dMmSxjQG.bzuZtv4./Ri8P0u/3.UnBM/m39HqSA/LJ6 |
+--------------------------------------------------------------+
```

Not Use Algorithm.

Use Salt (grater than 22).

```
mariadb> SELECT php_password_hash('password', NULL, 'abcdefghijklmnopqrstuv');
+---------------------------------------------------------------+
| php_password_hash('password', NULL, 'abcdefghijklmnopqrstuv') |
+---------------------------------------------------------------+
| $2y$10$abcdefghijklmnopqrstuu5Lo0g67CiD3M4RpN1BmBb4Crp5w7dbK  |
+---------------------------------------------------------------+
```

Use Cost (grater than 4 and less than 31).

```
mariadb> SELECT php_password_hash('password', NULL, NULL, 5);
+--------------------------------------------------------------+
| php_password_hash('password', NULL, NULL, 5)                 |
+--------------------------------------------------------------+
| $2y$05$xQYIrC9yqg/oW/UoOG/vGe.oH0CvRuQ1OB2X7qc6DKBodnDsALnn. |
+--------------------------------------------------------------+
```

### php\_password\_verify — Verifies that a password matches a hash

integer **php\_password\_verify** ( string _PASSWORD_ , string _HASH_ )

```
mariadb> SELECT php_password_verify('password', '$2y$10$k./h1h/YV4dMmSxjQG.bzuZtv4./Ri8P0u/3.UnBM/m39HqSA/LJ6') AS verify;
+--------+
| verify |
+--------+
|      1 |
+--------+
```

```
mariadb> SELECT php_password_verify('password', 'test') AS verify;
+--------+
| verify |
+--------+
|      0 |
+--------+
```
