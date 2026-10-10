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
static const char *(*error_message)(sqlite3 *);
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
    fprintf(stderr,
            "HARNESS_ERROR phase=setup SQL rc=%d primary=%d message=%s\n",
            rc, rc & 0xff, error_message(db));
    exit(2);
  }
}
static int outcome, baseline_ready;
static void harness_error(const char *phase) {
  fprintf(stderr, "HARNESS_ERROR %s\n", phase);
  if (outcome == 0)
    outcome = 2;
}
static void database_error(const char *phase, int rc, const char *message) {
  int primary = rc & 0xff;
  int regression = baseline_ready &&
                   (primary == SQLITE_CORRUPT || primary == SQLITE_NOTADB);
  fprintf(stderr, "%s phase=%s rc=%d primary=%d message=%s\n",
          regression ? "DATABASE_REGRESSION" : "HARNESS_ERROR", phase, rc,
          primary, message ? message : "(unavailable)");
  if (outcome == 0)
    outcome = regression ? 1 : 2;
}
static void record_loss(void) {
  if (outcome == 0)
    outcome = 1;
}
typedef struct {
  long value;
  int ok;
} Count;
static Count count(sqlite3 *db, const char *query, const char *phase) {
  sqlite3_stmt *s = 0;
  Count result = {-1, 0};
  int rc = prepare(db, query, -1, &s, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "query_prepare rc=%d message=%s\n", rc, error_message(db));
    database_error(phase, rc, error_message(db));
  } else {
    rc = step(s);
    if (rc != SQLITE_ROW) {
      fprintf(stderr, "query_step rc=%d message=%s\n", rc, error_message(db));
      database_error(phase, rc, error_message(db));
    } else {
      result.value = (long)integer(s, 0);
      result.ok = 1;
    }
  }
  if (s) {
    rc = finalize(s);
    if (rc != SQLITE_OK) {
      database_error("finalize count", rc, error_message(db));
      result.ok = 0;
    }
  }
  return result;
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
    else if ((rc & 0xff) != SQLITE_BUSY && (rc & 0xff) != SQLITE_LOCKED) {
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
  LOAD(error_message, "sqlite3_errmsg");
  printf("sqlite_version=%s\nsource_id=%s\n", version(), source_id());
  sqlite3 *reader = 0, *helper = 0;
  require(open_db(argv[2], &reader) == SQLITE_OK, "open reader");
  require(busy_timeout(reader, 1000) == SQLITE_OK, "busy timeout");
  sql(reader, "PRAGMA journal_mode=WAL; PRAGMA mmap_size=1073741824; CREATE "
              "TABLE payload(id INTEGER PRIMARY KEY,data BLOB); CREATE TABLE "
              "canary(id INTEGER PRIMARY KEY); BEGIN; WITH RECURSIVE seq(n) AS "
              "(VALUES(1) UNION ALL SELECT n+1 FROM seq WHERE n<65536) INSERT "
              "INTO payload SELECT n,randomblob(3900) FROM seq; COMMIT;");
  Count mapping = count(reader, "PRAGMA mmap_size", "mmap enabled");
  if (!mapping.ok || mapping.value < 268435456) {
    harness_error("mmap enabled");
    goto cleanup;
  }
  require(checkpoint(reader, "main", SQLITE_CHECKPOINT_TRUNCATE, 0, 0) ==
              SQLITE_OK,
          "initial checkpoint");
  require(open_db(argv[2], &helper) == SQLITE_OK, "open helper");
  require(open_db(argv[2], &writer) == SQLITE_OK, "open writer");
  require(busy_timeout(helper, 1000) == SQLITE_OK, "helper timeout");
  require(busy_timeout(writer, 1000) == SQLITE_OK, "writer timeout");
  int rounds = 0;
  for (int round = 0; round < 200; round++) {
    Count warm = count(reader,
                       "SELECT count(*) FROM payload WHERE data IS NOT NULL",
                       "warm mapped pages");
    if (!warm.ok)
      break;
    if (warm.value != 65536) {
      if (baseline_ready) {
        record_loss();
        printf("payload_loss phase=warm mapped pages expected=65536 visible=%ld\n",
               warm.value);
      } else {
        harness_error("warm mapped pages");
      }
      break;
    }
    /* The original first warm query admits the baseline without adding SQL. */
    baseline_ready = 1;
    int rc = execute(helper,
                     "UPDATE payload SET data=randomblob(3900) WHERE id<=20",
                     0, 0, 0);
    if (rc != SQLITE_OK) {
      database_error("helper SQL", rc, error_message(helper));
      break;
    }
    int log = -1, done = -1;
    rc = checkpoint(helper, "main", SQLITE_CHECKPOINT_PASSIVE, &log, &done);
    if (rc != SQLITE_OK) {
      database_error("complete helper checkpoint", rc, error_message(helper));
      break;
    }
    if (log < 0 || log != done) {
      harness_error("complete helper checkpoint");
      break;
    }
    atomic_store(&stopped, 0);
    pthread_t thread;
    int thread_rc = pthread_create(&thread, 0, write_rows, 0);
    if (thread_rc != 0) {
      fprintf(stderr, "HARNESS_ERROR phase=writer thread pthread_rc=%d\n",
              thread_rc);
      harness_error("writer thread");
      goto cleanup;
    }
    rc = checkpoint(reader, "main", SQLITE_CHECKPOINT_PASSIVE, 0, 0);
    char checkpoint_message[512];
    if (rc != SQLITE_OK)
      snprintf(checkpoint_message, sizeof(checkpoint_message), "%s",
               error_message(reader));
    atomic_store(&stopped, 1);
    /* No connection cleanup or error inspection until the exact writer joins.
     * If join fails, the external supervisor owns process termination; never
     * close a connection potentially still used by that writer. */
    thread_rc = pthread_join(thread, 0);
    if (thread_rc != 0) {
      fprintf(stderr, "HARNESS_ERROR phase=join writer pthread_rc=%d\n",
              thread_rc);
      return 2;
    }
    if (rc != SQLITE_OK)
      database_error("racing checkpoint", rc, checkpoint_message);
    int writer_rc = atomic_load(&worker_error);
    if (writer_rc != 0)
      database_error("writer SQL", writer_rc, error_message(writer));
    if (outcome != 0)
      break;
    rounds++;
    Count visible = count(helper, "SELECT count(*) FROM canary", "canary read");
    if (!visible.ok) {
      if (outcome == 1)
        printf("race_detected round=%d committed=%ld visible=-1\n", rounds,
               atomic_load(&committed));
      break;
    }
    if (visible.value < atomic_load(&committed)) {
      record_loss();
      printf("race_detected round=%d committed=%ld visible=%ld\n", rounds,
             atomic_load(&committed), visible.value);
      break;
    }
  }
  int rc = checkpoint(helper, "main", SQLITE_CHECKPOINT_TRUNCATE, 0, 0);
  if (rc != SQLITE_OK)
    database_error("final checkpoint", rc, error_message(helper));
  Count recovered = count(helper, "SELECT count(*) FROM canary", "recovered read");
  sqlite3_stmt *check = 0;
  int integrity = 0;
  rc = prepare(helper, "PRAGMA integrity_check", -1, &check, 0);
  if (rc != SQLITE_OK) {
    database_error("integrity prepare", rc, error_message(helper));
  } else {
    rc = step(check);
    if (rc != SQLITE_ROW) {
      database_error("integrity step", rc, error_message(helper));
    } else {
      const unsigned char *value = text(check, 0);
      if (!value)
        harness_error("integrity text unavailable");
      else {
        integrity = strcmp((const char *)value, "ok") == 0;
        if (!integrity)
          record_loss();
      }
    }
  }
  if (check) {
    rc = finalize(check);
    if (rc != SQLITE_OK)
      database_error("finalize integrity", rc, error_message(helper));
  }
  long writes = atomic_load(&committed);
  if (recovered.ok && recovered.value != writes)
    record_loss();
  printf("rounds=%d committed=%ld recovered=%ld integrity_ok=%d\n", rounds,
         writes, recovered.value, integrity);
  if (writes <= 0)
    harness_error("writer executed");
cleanup:
  if (writer) {
    int close_rc = close_db(writer);
    if (close_rc != SQLITE_OK)
      database_error("close writer", close_rc, error_message(writer));
  }
  if (helper) {
    int close_rc = close_db(helper);
    if (close_rc != SQLITE_OK)
      database_error("close helper", close_rc, error_message(helper));
  }
  if (reader) {
    int close_rc = close_db(reader);
    if (close_rc != SQLITE_OK)
      database_error("close reader", close_rc, error_message(reader));
  }
  if (dlclose(library) != 0)
    harness_error("dlclose");
  return outcome;
}
