(define-constant ERR-UNAUTHORIZED u100)
(define-constant ERR-INVALID-NFT-ID u101)
(define-constant ERR-INVALID-HASH u102)
(define-constant ERR-INVALID-OWNER u103)
(define-constant ERR-VERIFICATION-FAILED u104)
(define-constant ERR-NO-METADATA u105)
(define-constant ERR-NO-DETAILS u106)
(define-constant ERR-ALREADY-VERIFIED u107)
(define-constant ERR-INVALID-TIMESTAMP u108)
(define-constant ERR-EXPIRED-CERT u109)
(define-constant ERR-INVALID-ISSUER u110)
(define-constant ERR-BATCH-LIMIT-EXCEEDED u111)
(define-constant ERR-INVALID-PROVIDED-HASH u112)
(define-constant ERR-INVALID-CLAIMED-OWNER u113)
(define-constant ERR-VERIFIER-NOT-REGISTERED u114)
(define-constant ERR-INVALID-VERIFIER u115)
(define-constant ERR-VERIFICATION-LOG-NOT-FOUND u116)
(define-constant ERR-INVALID-LOG-ID u117)
(define-constant ERR-INVALID-BATCH-SIZE u118)
(define-constant ERR-INVALID-EXPIRY u119)
(define-constant ERR-INVALID-STATUS u120)

(define-data-var next-verification-id uint u0)
(define-data-var max-batch-size uint u10)
(define-data-var verification-fee uint u100)
(define-data-var admin principal tx-sender)

(define-map verification-logs
  uint
  {
    nft-id: uint,
    verifier: principal,
    timestamp: uint,
    valid: bool,
    provided-hash: (optional (buff 32)),
    claimed-owner: (optional principal)
  }
)

(define-map registered-verifiers principal bool)

(define-private (is-admin (account principal))
  (is-eq account (var-get admin)))

(define-private (is-registered-verifier (account principal))
  (default-to false (map-get? registered-verifiers account)))

(define-private (validate-nft-id (id uint))
  (if (> id u0)
    (ok id)
    (err ERR-INVALID-NFT-ID)))

(define-private (validate-hash (h (buff 32)))
  (if (is-eq (len h) u32)
    (ok h)
    (err ERR-INVALID-HASH)))

(define-private (validate-owner (o principal))
  (ok o))

(define-private (validate-timestamp (ts uint))
  (if (>= ts block-height)
    (ok ts)
    (err ERR-INVALID-TIMESTAMP)))

(define-private (validate-expiry (expiry (optional uint)))
  (match expiry
    some-exp (if (> some-exp block-height)
      (ok some-exp)
      (err ERR-EXPIRED-CERT))
    (ok none)))

(define-private (validate-issuer (issuer principal))
  (contract-call? .AccessControl check-role issuer "issuer"))

(define-private (validate-batch-size (size uint))
  (if (and (> size u0) (<= size (var-get max-batch-size)))
    (ok size)
    (err ERR-INVALID-BATCH-SIZE)))

(define-public (register-verifier)
  (begin
    (asserts! (not (is-registered-verifier tx-sender)) (err ERR-ALREADY-VERIFIED))
    (map-set registered-verifiers tx-sender true)
    (ok true)))

(define-public (unregister-verifier)
  (begin
    (asserts! (is-registered-verifier tx-sender) (err ERR-VERIFIER-NOT-REGISTERED))
    (map-delete registered-verifiers tx-sender)
    (ok true)))

(define-public (set-admin (new-admin principal))
  (begin
    (asserts! (is-admin tx-sender) (err ERR-UNAUTHORIZED))
    (var-set admin (unwrap-panic (ok new-admin)))
    (ok true)))

(define-public (set-max-batch-size (new-size uint))
  (begin
    (asserts! (is-admin tx-sender) (err ERR-UNAUTHORIZED))
    (asserts! (> new-size u0) (err ERR-INVALID-BATCH-SIZE))
    (var-set max-batch-size new-size)
    (ok true)))

(define-public (set-verification-fee (new-fee uint))
  (begin
    (asserts! (is-admin tx-sender) (err ERR-UNAUTHORIZED))
    (var-set verification-fee (unwrap-panic (ok new-fee)))
    (ok true)))

(define-private (internal-verify-certificate (nft-id uint) (provided-hash (buff 32)))
  (let ((checked-id (try! (validate-nft-id nft-id)))
        (checked-hash (try! (validate-hash provided-hash))))
    (match (contract-call? .CertificateNFT get-metadata checked-id)
      some-meta
        (let (
          (stored-hash (get hash some-meta))
          (issuer (get issuer some-meta))
          (recipient (get recipient some-meta))
          (details-opt (contract-call? .CertificateStorage get-certificate checked-id))
        )
          (try! (validate-issuer issuer))
          (asserts! (is-eq stored-hash checked-hash) (err ERR-VERIFICATION-FAILED))
          (match details-opt
            details
              (let (
                (expiry (get expiry-date details))
                (issue-date (get issue-date details))
              )
                (try! (validate-expiry expiry))
                (try! (validate-timestamp issue-date))
                (ok { valid: true, details: details })
              )
            (err ERR-NO-DETAILS)
          )
        )
      (err ERR-NO-METADATA)
    )
  )
)

(define-public (verify-certificate (nft-id uint) (provided-hash (buff 32)))
  (begin
    (asserts! (is-registered-verifier tx-sender) (err ERR-VERIFIER-NOT-REGISTERED))
    (try! (stx-transfer? (var-get verification-fee) tx-sender (var-get admin)))
    (match (internal-verify-certificate nft-id provided-hash)
      success
        (let ((log-id (var-get next-verification-id)))
          (map-set verification-logs log-id
            {
              nft-id: nft-id,
              verifier: tx-sender,
              timestamp: block-height,
              valid: true,
              provided-hash: (some provided-hash),
              claimed-owner: none
            }
          )
          (var-set next-verification-id (+ log-id u1))
          (print { event: "certificate-verified", log-id: log-id, nft-id: nft-id })
          (ok (merge success { log-id: log-id }))
        )
      error (err error)
    )
  )
)

(define-private (internal-verify-ownership (nft-id uint) (claimed-owner principal))
  (let ((checked-id (try! (validate-nft-id nft-id)))
        (checked-owner (try! (validate-owner claimed-owner))))
    (match (contract-call? .CertificateNFT get-owner checked-id)
      some-owner
        (begin
          (asserts! (is-eq some-owner checked-owner) (err ERR-INVALID-OWNER))
          (ok { valid: true, owner: checked-owner })
        )
      (err ERR-INVALID-OWNER)
    )
  )
)

(define-public (verify-ownership (nft-id uint) (claimed-owner principal))
  (begin
    (asserts! (is-registered-verifier tx-sender) (err ERR-VERIFIER-NOT-REGISTERED))
    (try! (stx-transfer? (var-get verification-fee) tx-sender (var-get admin)))
    (match (internal-verify-ownership nft-id claimed-owner)
      success
        (let ((log-id (var-get next-verification-id)))
          (map-set verification-logs log-id
            {
              nft-id: nft-id,
              verifier: tx-sender,
              timestamp: block-height,
              valid: true,
              provided-hash: none,
              claimed-owner: (some claimed-owner)
            }
          )
          (var-set next-verification-id (+ log-id u1))
          (print { event: "ownership-verified", log-id: log-id, nft-id: nft-id })
          (ok (merge success { log-id: log-id }))
        )
      error (err error)
    )
  )
)

(define-public (batch-verify-certificates (nft-ids (list 10 uint)) (hashes (list 10 (buff 32))))
  (let ((batch-size (len nft-ids)))
    (try! (validate-batch-size batch-size))
    (asserts! (is-eq batch-size (len hashes)) (err ERR-INVALID-BATCH-SIZE))
    (asserts! (is-registered-verifier tx-sender) (err ERR-VERIFIER-NOT-REGISTERED))
    (try! (stx-transfer? (* (var-get verification-fee) batch-size) tx-sender (var-get admin)))
    (let ((results (map internal-verify-certificate nft-ids hashes)))
      (var-set next-verification-id (+ (var-get next-verification-id) batch-size))
      (ok results)
    )
  )
)

(define-read-only (get-verification-log (log-id uint))
  (map-get? verification-logs log-id))

(define-read-only (is-verifier-registered (verifier principal))
  (ok (is-registered-verifier verifier)))

(define-read-only (get-max-batch-size)
  (ok (var-get max-batch-size)))

(define-read-only (get-verification-fee)
  (ok (var-get verification-fee)))

(define-read-only (get-next-verification-id)
  (ok (var-get next-verification-id)))

(define-read-only (check-certificate-validity (nft-id uint) (provided-hash (buff 32)))
  (match (contract-call? .CertificateNFT get-metadata nft-id)
    some-meta
      (ok (is-eq (get hash some-meta) provided-hash))
    none (err ERR-NO-METADATA)))

(define-read-only (check-ownership (nft-id uint) (claimed-owner principal))
  (match (contract-call? .CertificateNFT get-owner nft-id)
    some-owner (ok (is-eq some-owner claimed-owner))
    none (err ERR-INVALID-OWNER)))