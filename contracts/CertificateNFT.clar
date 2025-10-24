(define-constant ERR-NOT-ISSUER u100)
(define-constant ERR-NOT-OWNER u101)
(define-constant ERR-INVALID-RECIPIENT u102)
(define-constant ERR-INVALID-HASH u103)
(define-constant ERR-NFT-NOT-FOUND u104)
(define-constant ERR-MINT-FROZEN u105)
(define-constant ERR-ALREADY-FROZEN u106)
(define-constant ERR-NOT-FROZEN u107)
(define-constant ERR-INVALID-METADATA u108)
(define-constant ERR-INVALID-STATUS u109)

(define-non-fungible-token certificate-nft uint)
(define-data-var next-id uint u1)
(define-data-var mint-frozen bool false)
(define-data-var admin principal tx-sender)
(define-data-var issuer-registry principal 'SP000000000000000000002Q6VF78)
(define-map nft-metadata uint {
  issuer: principal,
  recipient: principal,
  hash: (buff 32),
  issue-date: uint,
  expiry-date: (optional uint),
  status: (string-ascii 20)
})
(define-map nft-attributes uint (list 10 { key: (string-ascii 50), value: (string-utf8 100) }))
(define-map issuer-limits principal { mint-limit: uint, minted-count: uint })

(define-read-only (get-last-token-id)
  (ok (- (var-get next-id) u1)))

(define-read-only (get-token-uri (id uint))
  (ok none))

(define-read-only (get-owner (id uint))
  (ok (nft-get-owner? certificate-nft id)))

(define-read-only (get-metadata (id uint))
  (map-get? nft-metadata id))

(define-read-only (get-attributes (id uint))
  (map-get? nft-attributes id))

(define-read-only (get-issuer-limit (issuer principal))
  (map-get? issuer-limits issuer))

(define-read-only (is-mint-frozen)
  (ok (var-get mint-frozen)))

(define-private (is-admin (account principal))
  (is-eq account (var-get admin)))

(define-private (is-issuer (account principal))
  (contract-call? .IssuerRegistry check-role account "issuer"))

(define-private (validate-hash (hash (buff 32)))
  (if (> (len hash) u0) (ok true) (err ERR-INVALID-HASH)))

(define-private (validate-recipient (recipient principal))
  (if (not (is-eq recipient 'SP000000000000000000002Q6VF78))
    (ok true)
    (err ERR-INVALID-RECIPIENT)))

(define-private (validate-status (status (string-ascii 20)))
  (if (or (is-eq status "active") (is-eq status "revoked") (is-eq status "expired"))
    (ok true)
    (err ERR-INVALID-STATUS)))

(define-public (set-issuer-registry (registry principal))
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-ISSUER)
    (var-set issuer-registry registry)
    (ok true)))

(define-public (set-mint-limit (issuer principal) (limit uint))
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-ISSUER)
    (asserts! (is-some (contract-call? .IssuerRegistry get-issuer-info issuer)) ERR-NOT-ISSUER)
    (map-set issuer-limits issuer { mint-limit: limit, minted-count: (default-to u0 (get minted-count (map-get? issuer-limits issuer))) })
    (ok true)))

(define-public (freeze-mint)
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-ISSUER)
    (asserts! (not (var-get mint-frozen)) ERR-ALREADY-FROZEN)
    (var-set mint-frozen true)
    (ok true)))

(define-public (unfreeze-mint)
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-ISSUER)
    (asserts! (var-get mint-frozen) ERR-NOT-FROZEN)
    (var-set mint-frozen false)
    (ok true)))

(define-public (mint (recipient principal) (hash (buff 32)) (issue-date uint) (expiry (optional uint)) (attributes (list 10 { key: (string-ascii 50), value: (string-utf8 100) })))
  (let ((id (var-get next-id))
        (issuer-info (contract-call? .IssuerRegistry get-issuer-info tx-sender))
        (limits (default-to { mint-limit: u0, minted-count: u0 } (map-get? issuer-limits tx-sender))))
    (asserts! (not (var-get mint-frozen)) ERR-MINT-FROZEN)
    (asserts! (is-some issuer-info) ERR-NOT-ISSUER)
    (asserts! (unwrap! (is-issuer tx-sender) false) ERR-NOT-ISSUER)
    (try! (validate-recipient recipient))
    (try! (validate-hash hash))
    (asserts! (<= (get minted-count limits) (get mint-limit limits)) ERR-NOT-ISSUER)
    (try! (nft-mint? certificate-nft id recipient))
    (map-set nft-metadata id { issuer: tx-sender, recipient: recipient, hash: hash, issue-date: issue-date, expiry-date: expiry, status: "active" })
    (map-set nft-attributes id attributes)
    (map-set issuer-limits tx-sender { mint-limit: (get mint-limit limits), minted-count: (+ (get minted-count limits) u1) })
    (var-set next-id (+ id u1))
    (print { event: "nft-minted", id: id, recipient: recipient })
    (ok id)))

(define-public (transfer (id uint) (sender principal) (recipient principal))
  (begin
    (asserts! (is-eq tx-sender sender) ERR-NOT-OWNER)
    (asserts! (is-some (nft-get-owner? certificate-nft id)) ERR-NFT-NOT-FOUND)
    (asserts! (is-eq (unwrap-panic (nft-get-owner? certificate-nft id)) sender) ERR-NOT-OWNER)
    (try! (validate-recipient recipient))
    (try! (nft-transfer? certificate-nft id sender recipient))
    (map-set nft-metadata id (merge (unwrap-panic (map-get? nft-metadata id)) { recipient: recipient }))
    (print { event: "nft-transferred", id: id, from: sender, to: recipient })
    (ok true)))

(define-public (update-status (id uint) (status (string-ascii 20)))
  (let ((metadata (map-get? nft-metadata id)))
    (asserts! (is-some metadata) ERR-NFT-NOT-FOUND)
    (asserts! (is-eq (get issuer (unwrap-panic metadata)) tx-sender) ERR-NOT-ISSUER)
    (try! (validate-status status))
    (map-set nft-metadata id (merge (unwrap-panic metadata) { status: status }))
    (print { event: "status-updated", id: id, status: status })
    (ok true)))

(define-public (add-attribute (id uint) (key (string-ascii 50)) (value (string-utf8 100)))
  (let ((metadata (map-get? nft-metadata id))
        (attributes (default-to (list) (map-get? nft-attributes id))))
    (asserts! (is-some metadata) ERR-NFT-NOT-FOUND)
    (asserts! (is-eq (get issuer (unwrap-panic metadata)) tx-sender) ERR-NOT-ISSUER)
    (asserts! (> (len key) u0) ERR-INVALID-METADATA)
    (asserts! (<= (len attributes) u9) ERR-INVALID-METADATA)
    (map-set nft-attributes id (unwrap-panic (as-max-len? (append attributes { key: key, value: value }) u10)))
    (print { event: "attribute-added", id: id, key: key, value: value })
    (ok true)))

(define-public (burn (id uint))
  (let ((metadata (map-get? nft-metadata id)))
    (asserts! (is-some metadata) ERR-NFT-NOT-FOUND)
    (asserts! (or (is-admin tx-sender) (is-eq (get issuer (unwrap-panic metadata)) tx-sender)) ERR-NOT-ISSUER)
    (try! (nft-burn? certificate-nft id (unwrap-panic (nft-get-owner? certificate-nft id))))
    (map-delete nft-metadata id)
    (map-delete nft-attributes id)
    (print { event: "nft-burned", id: id })
    (ok true)))