/* Manual, bounded public-API WAL regression for issue #908.
 * See docs/sqlite-wal-reset-probe.md for provenance and invocation.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int (*open_db)(const char *, sqlite3 **);
static int (*execute)(sqlite3 *, const char *,
                      int (*)(void *, int, char **, char **), void *, char **);
static int (*prepare)(sqlite3 *, const char *, int, sqlite3_stmt **,
                      const char **);
static int (*step)(sqlite3_stmt *);
static sqlite3_int64 (*integer)(sqlite3_stmt *, int);
static const unsigned char *(*text)(sqlite3_stmt *, int);
static int (*finalize)(sqlite3_stmt *);
static int (*checkpoint)(sqlite3 *, const char *, int, int *, int *);
static int (*busy_timeout)(sqlite3 *, int);
static int (*close_db)(sqlite3 *);
static const char *(*version)(void);
static const char *(*source_id)(void);
static atomic_int stopped, worker_error;
static atomic_long committed;
static sqlite3 *writer;
static void require(int ok, const char *phase) {
  if (!ok) {
    fprintf(stderr, "HARNESS_ERROR %s\n", phase);
    exit(2);
  }
}
static void sql(sqlite3 *db, const char *query) {
  int rc = execute(db, query, 0, 0, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "HARNESS_ERROR sql rc=%d\n", rc);
    exit(2);
  }
}
static long count(sqlite3 *db, const char *query) {
  sqlite3_stmt *s = 0;
  if (prepare(db, query, -1, &s, 0) != SQLITE_OK)
    return -1;
  int rc = step(s);
  long value = rc == SQLITE_ROW ? (long)integer(s, 0) : -1;
  finalize(s);
  return value;
}
static void *write_rows(void *unused) {
  (void)unused;
  char query[100];
  while (!atomic_load(&stopped)) {
    snprintf(query, sizeof(query), "INSERT INTO canary VALUES(%ld)",
             atomic_load(&committed) + 1);
    int rc = execute(writer, query, 0, 0, 0);
    if (rc == SQLITE_OK)
      atomic_fetch_add(&committed, 1);
    else if (rc != SQLITE_BUSY && rc != SQLITE_LOCKED) {
      atomic_store(&worker_error, rc);
      break;
    }
  }
  return 0;
}
int main(int argc, char **argv) {
  require(argc == 3, "arguments");
  setvbuf(stdout, 0, _IONBF, 0);
  void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  require(library != 0, "dlopen");
#define LOAD(variable, name)                                                   \
  do {                                                                         \
    *(void **)(&variable) = dlsym(library, name);                              \
    require(variable != 0, name);                                              \
  } while (0)
  LOAD(open_db, "sqlite3_open");
  LOAD(execute, "sqlite3_exec");
  LOAD(prepare, "sqlite3_prepare_v2");
  LOAD(step, "sqlite3_step");
  LOAD(integer, "sqlite3_column_int64");
  LOAD(text, "sqlite3_column_text");
  LOAD(finalize, "sqlite3_finalize");
  LOAD(checkpoint, "sqlite3_wal_checkpoint_v2");
  LOAD(busy_timeout, "sqlite3_busy_timeout");
  LOAD(close_db, "sqlite3_close");
  LOAD(version, "sqlite3_libversion");
  LOAD(source_id, "sqlite3_sourceid");
  printf("sqlite_version=%s\nsource_id=%s\n", version(), source_id());
  sqlite3 *reader = 0, *helper = 0;
  require(open_db(argv[2], &reader) == SQLITE_OK, "open reader");
  require(busy_timeout(reader, 1000) == SQLITE_OK, "busy timeout");
  sql(reader, "PRAGMA journal_mode=WAL; PRAGMA mmap_size=1073741824; CREATE "
              "TABLE payload(id INTEGER PRIMARY KEY,data BLOB); CREATE TABLE "
              "canary(id INTEGER PRIMARY KEY); BEGIN; WITH RECURSIVE seq(n) AS "
              "(VALUES(1) UNION ALL SELECT n+1 FROM seq WHERE n<65536) INSERT "
              "INTO payload SELECT n,randomblob(3900) FROM seq; COMMIT;");
  require(count(reader, "PRAGMA mmap_size") >= 268435456, "mmap enabled");
  require(checkpoint(reader, "main", SQLITE_CHECKPOINT_TRUNCATE, 0, 0) ==
              SQLITE_OK,
          "initial checkpoint");
  require(open_db(argv[2], &helper) == SQLITE_OK, "open helper");
  require(open_db(argv[2], &writer) == SQLITE_OK, "open writer");
  require(busy_timeout(helper, 1000) == SQLITE_OK, "helper timeout");
  require(busy_timeout(writer, 1000) == SQLITE_OK, "writer timeout");
  int lost = 0, rounds = 0;
  for (int round = 0; round < 200; round++) {
    require(
        count(reader, "SELECT count(*) FROM payload WHERE data IS NOT NULL") ==
            65536,
        "warm mapped pages");
    sql(helper, "UPDATE payload SET data=randomblob(3900) WHERE id<=20");
    int log = -1, done = -1;
    require(checkpoint(helper, "main", SQLITE_CHECKPOINT_PASSIVE, &log,
                       &done) == SQLITE_OK &&
                log >= 0 && log == done,
            "complete helper checkpoint");
    atomic_store(&stopped, 0);
    pthread_t thread;
    require(pthread_create(&thread, 0, write_rows, 0) == 0, "writer thread");
    int rc = checkpoint(reader, "main", SQLITE_CHECKPOINT_PASSIVE, 0, 0);
    atomic_store(&stopped, 1);
    require(pthread_join(thread, 0) == 0, "join writer");
    require(rc == SQLITE_OK, "racing checkpoint");
    require(atomic_load(&worker_error) == 0, "writer SQL");
    rounds++;
    long visible = count(helper, "SELECT count(*) FROM canary");
    if (visible < 0 || visible < atomic_load(&committed)) {
      lost = 1;
      printf("race_detected round=%d committed=%ld visible=%ld\n", rounds,
             atomic_load(&committed), visible);
      break;
    }
  }
  require(checkpoint(helper, "main", SQLITE_CHECKPOINT_TRUNCATE, 0, 0) ==
              SQLITE_OK,
          "final checkpoint");
  long recovered = count(helper, "SELECT count(*) FROM canary");
  sqlite3_stmt *check = 0;
  int integrity =
      prepare(helper, "PRAGMA integrity_check", -1, &check, 0) == SQLITE_OK &&
      step(check) == SQLITE_ROW &&
      strcmp((const char *)text(check, 0), "ok") == 0;
  if (check)
    finalize(check);
  long writes = atomic_load(&committed);
  printf("rounds=%d committed=%ld recovered=%ld integrity_ok=%d\n", rounds,
         writes, recovered, integrity);
  require(writes > 0, "writer executed");
  close_db(writer);
  close_db(helper);
  close_db(reader);
  dlclose(library);
  return lost || recovered != writes || !integrity ? 1 : 0;
}