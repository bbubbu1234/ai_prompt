# Security Specification: 나의 AI 프롬프트 창고 (Public Read, Admin-Only Write)

## 1. Data Invariants
1. Every document in `/prompts/{promptId}` must have a valid document ID (`^[a-zA-Z0-9_\-]+$`, max 128 chars).
2. Anyone (even without logging in) may read (`get`, `list`) prompts in `/prompts/{promptId}`.
3. All write operations (`create`, `update`, `delete`) on `/prompts/{promptId}` require a verified Google-authenticated administrator (`request.auth.token.email == 'lhk050403@gmail.com' && request.auth.token.email_verified == true`).
4. Every prompt document must contain exactly the four allowed keys: `title`, `category`, `content`, and `createdAt`.
5. `title` must be a non-empty string between 1 and 100 characters.
6. `category` must be one of: `"사진 합성"`, `"스타일 변환"`, `"캐릭터·포스터"`.
7. `content` must be a non-empty string between 1 and 10,000 characters.
8. `createdAt` must equal `request.time` on creation and remain strictly immutable on update.
9. All other collections and paths are completely blocked for both read and write (`allow read, write: if false;`).

## 2. Adversarial Payloads ("Dirty Dozen")
1. Unauthenticated guest attempting `create` on `/prompts/test` -> DENIED (`isAdmin()`)
2. Non-admin authenticated user (`other@gmail.com`) attempting `create`/`update`/`delete` -> DENIED (`isAdmin()`)
3. Unverified email spoof (`email == 'lhk050403@gmail.com'`, `email_verified == false`) -> DENIED (`email_verified == true`)
4. Oversized document ID (>128 chars) -> DENIED (`isValidId`)
5. Invalid characters in document ID (`../etc`) -> DENIED (`isValidId`)
6. Missing required field (`content` omitted) -> DENIED (`hasAll`)
7. Shadow/ghost field injection (`isAdmin: true`) -> DENIED (`hasOnly`)
8. Empty or >100 char `title` -> DENIED (`title.size() <= 100`)
9. Invalid `category` (`"기타"`) -> DENIED (`isValidCategory`)
10. Oversized `content` (>10,000 chars) -> DENIED (`content.size() <= 10000`)
11. Mutating `createdAt` on update -> DENIED (`affectedKeys().hasOnly(['title', 'category', 'content']) && incoming().createdAt == existing().createdAt`)
12. Reading or writing any other collection (e.g. `/users/1` or `/test/connection`) -> DENIED (default-deny catch-all)
