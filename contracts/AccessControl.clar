(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-ALREADY-ASSIGNED (err u101))
(define-constant ERR-ROLE-NOT-FOUND (err u102))
(define-constant ERR-INVALID-ROLE-NAME (err u103))
(define-constant ERR-NOT-ROLE-ADMIN (err u104))
(define-constant ERR-INVALID-TIMESTAMP (err u105))
(define-constant ERR-AUTHORITY-NOT-VERIFIED (err u106))
(define-constant ERR-INVALID-FEE (err u107))
(define-constant ERR-MAX-ROLES-EXCEEDED (err u108))
(define-constant ERR-INVALID-DESCRIPTION (err u109))
(define-constant ERR-INVALID-EXPIRY (err u110))
(define-constant ERR-ROLE-ALREADY-EXISTS (err u111))
(define-constant ERR-INVALID-UPDATE-PARAM (err u112))
(define-constant ERR-MEMBER-NOT-FOUND (err u113))
(define-constant ERR-ROLE-UPDATE-NOT-ALLOWED (err u114))
(define-constant ERR-INVALID-PRINCIPAL (err u115))
(define-constant ERR-EXPIRY-PASSED (err u116))
(define-constant ERR-INVALID-MAX-MEMBERS (err u117))
(define-constant ERR-MAX-MEMBERS-EXCEEDED (err u118))
(define-constant ERR-INVALID-STATUS (err u119))
(define-constant ERR-AUTHORITY-ALREADY-SET (err u120))

(define-data-var next-role-id uint u0)
(define-data-var max-roles uint u1000)
(define-data-var grant-fee uint u1000)
(define-data-var authority-contract (optional principal) none)
(define-data-var max-members-per-role uint u1000)

(define-map roles
  uint
  {
    name: (string-ascii 32),
    description: (string-utf8 256),
    admin: principal,
    timestamp: uint,
    expiry: (optional uint),
    status: bool
  }
)

(define-map role-members
  uint
  (list 1000 principal)
)

(define-map member-roles
  principal
  (list 10 uint)
)

(define-map role-updates
  uint
  {
    update-name: (string-ascii 32),
    update-description: (string-utf8 256),
    update-timestamp: uint,
    updater: principal
  }
)

(define-read-only (get-role (id uint))
  (map-get? roles id)
)

(define-read-only (get-role-members (id uint))
  (default-to (list) (map-get? role-members id))
)

(define-read-only (get-member-roles (member principal))
  (default-to (list) (map-get? member-roles member))
)

(define-read-only (has-role (member principal) (role-id uint))
  (match (index-of? (get-member-roles member) role-id)
    some-index true
    false
  )
)

(define-read-only (is-role-active (id uint))
  (match (get-role id)
    role (let ((exp (get expiry role)))
           (if (is-some exp)
               (>= (unwrap-panic exp) block-height)
               true
             )
         )
    false
  )
)

(define-read-only (get-role-updates (id uint))
  (map-get? role-updates id)
)

(define-read-only (is-role-registered (name (string-ascii 32)))
  (fold or
    (map
      (lambda (id uint)
        (is-eq (get name (unwrap-panic (get-role id))) name)
      )
      (range u0 (var-get next-role-id))
    )
    false
  )
)

(define-private (validate-name (name (string-ascii 32)))
  (if (and (> (len name) u0) (<= (len name) u32))
      (ok true)
      ERR-INVALID-ROLE-NAME
  )
)

(define-private (validate-description (desc (string-utf8 256)))
  (if (<= (len desc) u256)
      (ok true)
      ERR-INVALID-DESCRIPTION
  )
)

(define-private (validate-expiry (exp (optional uint)))
  (match exp
    e (if (> e block-height)
        (ok true)
        ERR-INVALID-EXPIRY
      )
    (ok true)
  )
)

(define-private (validate-principal (p principal))
  (if (not (is-eq p 'SP000000000000000000002Q6VF78))
      (ok true)
      ERR-INVALID-PRINCIPAL
  )
)

(define-private (validate-max-members (members uint))
  (if (and (> members u0) (<= members (var-get max-members-per-role)))
      (ok true)
      ERR-INVALID-MAX-MEMBERS
  )
)

(define-private (validate-timestamp (ts uint))
  (if (>= ts block-height)
      (ok true)
      ERR-INVALID-TIMESTAMP
  )
)

(define-private (validate-status (status bool))
  (ok true)
)

(define-private (validate-fee (fee uint))
  (if (>= fee u0)
      (ok true)
      ERR-INVALID-FEE
  )
)

(define-private (is-admin (account principal))
  (fold or
    (map
      (lambda (role-id uint)
        (and (is-eq (get admin (unwrap-panic (get-role role-id))) account)
             (is-role-active role-id)
        )
      )
      (get-member-roles account)
    )
    false
  )
)

(define-private (is-role-admin (account principal) (role-id uint))
  (match (get-role role-id)
    role (and (is-eq (get admin role) account) (is-role-active role-id))
    false
  )
)

(define-public (set-authority-contract (contract-principal principal))
  (begin
    (try! (validate-principal contract-principal))
    (asserts! (is-none (var-get authority-contract)) ERR-AUTHORITY-ALREADY-SET)
    (var-set authority-contract (some contract-principal))
    (ok true)
  )
)

(define-public (set-max-roles (new-max uint))
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (> new-max u0) ERR-INVALID-UPDATE-PARAM)
    (var-set max-roles new-max)
    (ok true)
  )
)

(define-public (set-grant-fee (new-fee uint))
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (try! (validate-fee new-fee))
    (var-set grant-fee new-fee)
    (ok true)
  )
)

(define-public (set-max-members-per-role (new-max uint))
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (try! (validate-max-members new-max))
    (var-set max-members-per-role new-max)
    (ok true)
  )
)

(define-public (create-role
  (role-name (string-ascii 32))
  (description (string-utf8 256))
  (expiry (optional uint))
)
  (let (
        (next-id (var-get next-role-id))
        (current-max (var-get max-roles))
      )
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (< next-id current-max) ERR-MAX-ROLES-EXCEEDED)
    (try! (validate-name role-name))
    (try! (validate-description description))
    (try! (validate-expiry expiry))
    (asserts! (not (is-role-registered role-name)) ERR-ROLE-ALREADY-EXISTS)
    (map-set roles next-id
      {
        name: role-name,
        description: description,
        admin: tx-sender,
        timestamp: block-height,
        expiry: expiry,
        status: true
      }
    )
    (var-set next-role-id (+ next-id u1))
    (print { event: "role-created", id: next-id })
    (ok next-id)
  )
)

(define-public (grant-role (role-id uint) (member principal))
  (match (get-role role-id)
    role
      (begin
        (asserts! (is-role-admin tx-sender role-id) ERR-NOT-ROLE-ADMIN)
        (asserts! (is-role-active role-id) ERR-EXPIRY-PASSED)
        (asserts! (not (has-role member role-id)) ERR-ALREADY-ASSIGNED)
        (let ((current-members (get-role-members role-id)))
          (asserts! (< (len current-members) (var-get max-members-per-role)) ERR-MAX-MEMBERS-EXCEEDED)
          (map-set role-members role-id (unwrap-panic (as-max-len? (append current-members member) u1000)))
        )
        (let ((current-roles (get-member-roles member)))
          (map-set member-roles member (unwrap-panic (as-max-len? (append current-roles role-id) u10)))
        )
        (if (> (var-get grant-fee) u0)
            (try! (stx-transfer? (var-get grant-fee) tx-sender (unwrap-panic (var-get authority-contract))))
            (ok true)
        )
        (print { event: "role-granted", role-id: role-id, member: member })
        (ok true)
      )
    ERR-ROLE-NOT-FOUND
  )
)

(define-public (revoke-role (role-id uint) (member principal))
  (match (get-role role-id)
    role
      (begin
        (asserts! (is-role-admin tx-sender role-id) ERR-NOT-ROLE-ADMIN)
        (asserts! (has-role member role-id) ERR-MEMBER-NOT-FOUND)
        (let ((current-members (get-role-members role-id)))
          (map-set role-members role-id (filter (lambda (p principal) (not (is-eq p member))) current-members))
        )
        (let ((current-roles (get-member-roles member)))
          (map-set member-roles member (filter (lambda (id uint) (not (is-eq id role-id))) current-roles))
        )
        (print { event: "role-revoked", role-id: role-id, member: member })
        (ok true)
      )
    ERR-ROLE-NOT-FOUND
  )
)

(define-public (update-role
  (role-id uint)
  (update-name (string-ascii 32))
  (update-description (string-utf8 256))
)
  (match (get-role role-id)
    role
      (begin
        (asserts! (is-role-admin tx-sender role-id) ERR-NOT-ROLE-ADMIN)
        (try! (validate-name update-name))
        (try! (validate-description update-description))
        (if (not (is-eq (get name role) update-name))
            (asserts! (not (is-role-registered update-name)) ERR-ROLE-ALREADY-EXISTS)
            (ok true)
        )
        (map-set roles role-id
          (merge role
            {
              name: update-name,
              description: update-description,
              timestamp: block-height
            }
          )
        )
        (map-set role-updates role-id
          {
            update-name: update-name,
            update-description: update-description,
            update-timestamp: block-height,
            updater: tx-sender
          }
        )
        (print { event: "role-updated", id: role-id })
        (ok true)
      )
    ERR-ROLE-NOT-FOUND
  )
)

(define-public (deactivate-role (role-id uint))
  (match (get-role role-id)
    role
      (begin
        (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
        (map-set roles role-id (merge role { status: false }))
        (ok true)
      )
    ERR-ROLE-NOT-FOUND
  )
)

(define-public (get-role-count)
  (ok (var-get next-role-id))
)