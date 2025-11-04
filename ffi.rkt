#lang racket/base

(require ffi/unsafe
         ffi/unsafe/define
         openssl/libcrypto)

(define-ffi-definer define-crypto libcrypto
  #:default-make-fail
  (lambda (_name)
    (lambda _args
      void)))
(define-crypto OSSL_PROVIDER_load (_fun _pointer _string -> _pointer))
(void (OSSL_PROVIDER_load #f "legacy"))
(void (OSSL_PROVIDER_load #f "default"))
