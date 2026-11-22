# Security Specification — SulE-Com Firestore Rules

## 1. Data Invariants
1. **Owner-Only Profile & PII Isolation**: A user may only read or write `/users/{userId}` and `/users/{userId}/private/info` when `request.auth.uid == userId` and `request.auth.token.email_verified == true` (for writes). No `list` on `/users` or `/users/{userId}/private` is allowed.
2. **Seller Role Enforcement via Relational Lookup**: Only users whose `/users/{uid}` document exists and has `accountType == 'buyer-seller'` may create `/products/{productId}`. `sellerId` must equal `request.auth.uid`.
3. **Immutable Ownership & Timestamps**: `uid`, `sellerId`, `userId`, and `createdAt` cannot be modified after creation. `createdAt` and `updatedAt` must equal `request.time`.
4. **Terminal State Locking**: Orders with `status` in `['completed', 'cancelled']` are permanently locked from updates.
5. **Atomic Order Line Items**: `/orders/{orderId}/items/{itemId}` can only be created when the parent `/orders/{orderId}` exists or is created atomically in the same batch (`existsAfter`), and belongs to `request.auth.uid`.
6. **Strict Schema & ID Guards**: Every document ID path variable is validated with `isValidId()` (`^[a-zA-Z0-9_\-]+$`, `<= 128` chars), and every write validates exact required/allowed keys (`hasAll` + `hasOnly`) and field types/sizes.

## 2. The "Dirty Dozen" Attack Payloads
1. **Identity Spoofing on User Profile**: Unauthenticated or wrong-UID write to `/users/victim_uid` with `{ uid: 'victim_uid', ... }` -> `PERMISSION_DENIED`.
2. **PII Leak via Cross-User Read**: Signed-in user `attacker` reading `/users/victim_uid/private/info` -> `PERMISSION_DENIED`.
3. **Blanket User List Scrape**: Signed-in user listing `/users` -> `PERMISSION_DENIED`.
4. **Shadow Field Injection on Profile**: Creating `/users/uid` with extra ghost field `{ isAdmin: true }` -> `PERMISSION_DENIED`.
5. **Unverified Email Write**: Creating `/products/p1` with `email_verified: false` -> `PERMISSION_DENIED`.
6. **Buy-Only Seller Escalation**: User with `accountType: 'buyer'` attempting to create `/products/p1` -> `PERMISSION_DENIED`.
7. **Seller Spoofing on Product**: Creating `/products/p1` with `sellerId: 'other_user'` -> `PERMISSION_DENIED`.
8. **Product Hijack Update**: Non-owner attempting to update `/products/p1` -> `PERMISSION_DENIED`.
9. **Timestamp Forgery**: Creating `/products/p1` with `createdAt` not equal to `request.time` -> `PERMISSION_DENIED`.
10. **ID Poisoning**: Creating `/products/` with a 300-character or special-character document ID -> `PERMISSION_DENIED`.
11. **Terminal Order Mutation**: Updating `/orders/o1` after `status == 'completed'` -> `PERMISSION_DENIED`.
12. **Orphaned / Cross-User Order Item**: Creating `/orders/victim_order/items/item1` -> `PERMISSION_DENIED`.
